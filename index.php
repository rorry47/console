<?php
// ════════════════════════════════════════════════════════════════
//  CONFIG
// ════════════════════════════════════════════════════════════════

// Local, session-bound arithmetic CAPTCHA; no external services or secrets.
ini_set('display_errors', '0');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ini_set('session.cookie_secure', '1');
ob_start();
session_start();
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');
function newCaptcha(): array {
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $word = '';
    for ($i = 0; $i < 6; $i++) $word .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    return ['word' => $word, 'expires' => time() + 300, 'attempts' => 0];
}
if (!isset($_SESSION['captcha']) || !is_array($_SESSION['captcha']) || !isset($_SESSION['captcha']['word']) || time() > ($_SESSION['captcha']['expires'] ?? 0)) {
    $_SESSION['captcha'] = newCaptcha();
}

// Serve a first-party CAPTCHA image. Requires the PHP GD extension.
if (isset($_GET['captcha_image'])) {
    header('Content-Type: image/png');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    if (!extension_loaded('gd') || empty($_SESSION['captcha']['word'])) {
        http_response_code(503);
        exit();
    }
    $w = 250; $h = 85;
    $im = imagecreatetruecolor($w, $h);
    $bg = imagecolorallocate($im, 13, 19, 28);
    $ink = imagecolorallocate($im, 109, 235, 225);
    $muted = imagecolorallocate($im, 39, 72, 83);
    imagefilledrectangle($im, 0, 0, $w, $h, $bg);
    for ($i = 0; $i < 12; $i++) {
        imageline($im, random_int(0,$w),random_int(0,$h),random_int(0,$w),random_int(0,$h),$muted);
    }
    // Draw characters separately with random positions and rotation.
    // Prefer a locally installed TrueType font; never load remote assets.
    $fonts = ['/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
              '/usr/share/fonts/truetype/liberation2/LiberationMono-Bold.ttf',
              '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'];
    $font = null;
    foreach ($fonts as $candidate) if (is_readable($candidate)) { $font = $candidate; break; }
    $word = $_SESSION['captcha']['word'];
    for ($i = 0; $i < strlen($word); $i++) {
        $x = 16 + $i * 37 + random_int(-3,3);
        $y = 56 + random_int(-9,9);
        if ($font && function_exists('imagettftext')) {
            imagettftext($im, random_int(24,30), random_int(-22,22), $x, $y, $ink, $font, $word[$i]);
        } else {
            imagestring($im, 5, $x, $y - 22, $word[$i], $ink);
        }
    }
    for ($i = 0; $i < 160; $i++) imagesetpixel($im,random_int(0,$w-1),random_int(0,$h-1),$muted);
    // Subtle wave distortion across columns.
    $out = imagecreatetruecolor($w, $h);
    imagefilledrectangle($out, 0, 0, $w, $h, $bg);
    $phase = random_int(0,628)/100;
    for ($x = 0; $x < $w; $x++) {
        $shift = (int)round(3 * sin($x / 17 + $phase));
        imagecopy($out, $im, $x, $shift, $x, 0, 1, $h);
    }
    imagepng($out);
    imagedestroy($out);
    imagedestroy($im);
    exit();
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting (max 60 requests per minute per session)
if (!isset($_SESSION['rate_limit'])) {
    $_SESSION['rate_limit'] = ['count' => 0, 'reset' => time() + 60];
}
if (time() >= $_SESSION['rate_limit']['reset']) {
    $_SESSION['rate_limit'] = ['count' => 0, 'reset' => time() + 60];
}

// ── AJAX command handler: respond with plain output only, no HTML ────────────
if (!empty($_SESSION['var']) && isset($_POST['command'])) {
    define('CONSOLE_INTERNAL_DISPATCH', true);
    header('Content-Type: text/html; charset=UTF-8');

    // CSRF check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        echo '<span style="color:#ff6b6b">CSRF validation failed.</span>';
        exit();
    }

    // Rate limiting
    $_SESSION['rate_limit']['count']++;
    if ($_SESSION['rate_limit']['count'] > 60) {
        echo '<span style="color:#ff6b6b">Rate limit exceeded. Please wait.</span>';
        exit();
    }

    require './console.php';
    exit();
}

// Verify CAPTCHA before rendering HTML so redirects and headers are reliable.
$captchaError = '';
if (empty($_SESSION['var']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ok'])) {
    $c = $_SESSION['captcha'];
    $token = $_POST['csrf_token'] ?? '';
    $answer = $_POST['captcha_answer'] ?? '';
    if (!is_string($token) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        $captchaError = 'Invalid request.';
    } else {
        $valid = is_string($answer) && strlen($answer) === 6 && $c['attempts'] < 5
            && time() <= $c['expires'] && hash_equals($c['word'], strtoupper($answer));
        $_SESSION['captcha']['attempts']++;
        if ($valid) {
            session_regenerate_id(true);
            $_SESSION['var'] = '1';
            unset($_SESSION['captcha']);
            header('Location: ./', true, 303);
            exit();
        }
        $captchaError = 'Incorrect characters. Try again.';
        // New challenge on every failure prevents unlimited guesses of one image.
        $_SESSION['captcha'] = newCaptcha();
    }
}

// Helper to get safe display name
function getDisplayName(): string {
    if (!empty($_SESSION['name'])) {
        return htmlspecialchars($_SESSION['name'], ENT_QUOTES, 'UTF-8');
    }
    return htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'unknown', ENT_QUOTES, 'UTF-8');
}

$displayName = getDisplayName();
?>
<!doctype html>
<html lang="en">
<head>
    <title>console@<?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?> — example</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="/command-line.png" type="image/x-icon">


    <style>
:root{color-scheme:dark;--bg:#090e17;--surface:#101927;--surface2:#0c1420;--border:#26364a;--fg:#d9e5f1;--muted:#8da1b7;--acc:#62e6da;--ok:#80e1a2;--err:#ff8799;--font:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}html{min-height:100%;scroll-behavior:smooth}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse 65% 45% at 85% 0%,#12304566,transparent),radial-gradient(ellipse 50% 40% at 0% 90%,#102a3360,transparent),var(--bg);color:var(--fg);font:14px/1.65 var(--font);padding:24px clamp(12px,3vw,48px) 32px}
body::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.22;background-image:linear-gradient(#ffffff06 1px,transparent 1px),linear-gradient(90deg,#ffffff06 1px,transparent 1px);background-size:36px 36px;z-index:-1}
button,input{font:inherit}button{cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid var(--acc);outline-offset:3px}
::selection{background:#28776f;color:white}
#workspace{width:min(100%,1320px);margin:0 auto}
#workspace-top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}.brand-icon{width:44px;height:44px;display:grid;place-items:center;border:1px solid #28776f;border-radius:12px;background:#123038;color:var(--acc);font-size:22px;box-shadow:0 0 25px #36c4b318}
.brand-title{font-size:17px;font-weight:750;letter-spacing:-.5px}.brand-subtitle{font:12px/1.3 var(--font);color:var(--muted)}
.top-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.status{font-size:12px;color:var(--ok);margin-right:12px}.status::before{content:"";display:inline-block;width:7px;height:7px;background:var(--ok);border-radius:50%;margin-right:7px;box-shadow:0 0 12px var(--ok)}
.ui-button{border:1px solid var(--border);background:#142132;color:var(--fg);padding:8px 13px;border-radius:8px;transition:background .2s,border-color .2s}.ui-button:hover{background:#1b3043;border-color:#3d6574}
#terminal-shell{border:1px solid #304356;border-radius:15px;background:var(--surface2);overflow:hidden;box-shadow:0 24px 80px #0008,0 0 0 1px #ffffff05;min-height:66vh;display:flex;flex-direction:column}
#header-bar{display:flex;align-items:center;gap:8px;padding:13px 17px;background:linear-gradient(180deg,#19283a,#142133);border-bottom:1px solid var(--border);font-size:12px;color:var(--muted)}
#header-bar .dot{width:10px;height:10px;border-radius:50%}#header-bar .dot.r{background:#ff6c70}#header-bar .dot.y{background:#ffcf68}#header-bar .dot.g{background:#61d79c}
#header-bar .title{flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#header-bar .session{font-size:11px;color:#7d96a9}
#output{flex:1;min-height:350px;padding:24px clamp(16px,3vw,34px);overflow-wrap:anywhere}
#output:empty::before{content:"Welcome to console.nkotov.net  •  Type help to get started";display:block;color:var(--muted);white-space:pre-wrap;padding:2px 0}
.cmd-block{margin:0 0 24px;padding-bottom:18px;border-bottom:1px solid #203044}.cmd-block:last-child{border-bottom:0}.cmd-line{color:var(--fg);overflow-wrap:anywhere}.cmd-line .prompt,.prompt-label{color:var(--ok)}.cmd-line .host,.prompt-label .host{color:var(--acc)}.cmd-line .entered-command{color:#f4f8ff}
.result{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px 0 0 16px;margin-top:8px;border-left:2px solid #2a4a56;font-size:13px;line-height:1.65;color:#b7c8d7}
.result a{color:var(--acc);text-decoration:underline;text-underline-offset:3px}.result b{color:#eef8ff}.error-text{color:var(--err)}.success-text{color:var(--ok)}
#loader{display:none;padding:8px 26px;color:var(--acc);font-size:12px}#loader.active{display:block}#loader span{display:inline-block;animation:blink 1s step-start infinite}@keyframes blink{50%{opacity:0}}
#input-wrapper{display:flex;align-items:center;gap:12px;padding:16px clamp(14px,3vw,30px);border-top:1px solid var(--border);background:#132030;position:sticky;bottom:0}
#input-wrapper .prompt-label{white-space:nowrap;font-size:13px;user-select:none}#command-input{flex:1;min-width:0;border:0;background:transparent;color:var(--fg);outline:none;caret-color:var(--acc);font-size:14px}#command-input::placeholder{color:#71899e}
#terminal-footer{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:10px 17px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);background:#0e1926}
.kbd{display:inline-block;border:1px solid #405166;border-radius:4px;padding:0 5px;color:#c6d5e3}
.btn{background:#172b39;color:var(--fg);border:1px solid #385263;border-radius:7px;padding:9px 16px;cursor:pointer}.btn:hover{background:#203a49}
#captcha-gate{box-shadow:0 22px 65px #0008}
body.theme-A{--fg:#9bf59b;--acc:#74f87a;--ok:#75e78c}
body.theme-B{--bg:#edf3f7;--surface2:#f6fafc;--border:#becedb;--fg:#1e3242;--muted:#5b7184;--acc:#087d83;--ok:#14784a;--err:#c02949;color-scheme:light}
body.theme-B #terminal-shell,body.theme-B #input-wrapper,body.theme-B #header-bar,body.theme-B #terminal-footer{background:#f6fafc}body.theme-B .result{color:#344e60}body.theme-B .cmd-line .entered-command{color:#203a4c}
body.theme-C{--acc:#e2e9ef;--ok:#bfcbd8}body.theme-D{--acc:#f3a6d2;--ok:#b6a2ed}body.theme-X{--acc:#b8b0ff;--ok:#91e0f1}body.theme-P{--acc:#9fb7ff;--ok:#b6d0ff}
@media(max-width:640px){body{padding:14px 9px 20px}#workspace-top{gap:12px}.brand-title{font-size:15px}.status{display:none}#terminal-shell{min-height:75vh}#output{padding:18px 14px;min-height:320px}.result{font-size:12px;padding-left:10px}#input-wrapper{gap:7px;padding:14px 11px}.prompt-label{font-size:11px!important}#command-input{font-size:13px}#header-bar .session{display:none}#terminal-footer{font-size:10px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;scroll-behavior:auto!important}}
</style>

    <?php
    $theme = $_SESSION['style'] ?? '';
    if ($theme) {
        echo '<script>document.documentElement.className="theme-' . htmlspecialchars($theme, ENT_QUOTES, 'UTF-8') . '";</script>';
    }
    ?>
</head>
<body class="<?= $theme ? 'theme-' . htmlspecialchars($theme, ENT_QUOTES, 'UTF-8') : '' ?>">

<?php
?>

<?php if (empty($_SESSION['var'])): ?>
    <div id="captcha-gate" style="max-width:350px;margin:12vh auto;padding:26px;border:1px solid #2e454c;border-radius:12px;background:#101820;text-align:center">
        <div style="font-size:19px;margin-bottom:12px;color:#6cf7fc">Human verification</div>
        <p style="font-size:13px;margin-bottom:18px;color:#a4b2b6">Type the characters shown in the image.</p>
        <form method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <img src="?captcha_image=1" alt="CAPTCHA challenge" width="250" height="85" style="display:block;margin:0 auto 14px;border:1px solid #35535d;border-radius:8px;max-width:100%">
            <input id="captcha-answer" name="captcha_answer" type="text" maxlength="6" minlength="6" pattern="[A-Za-z0-9]{6}" required autocomplete="off" spellcheck="false" autocapitalize="characters" placeholder="Enter the 6 characters" class="btn" style="width:100%;margin-bottom:12px;text-align:center;letter-spacing:3px;text-transform:uppercase" autofocus>
            <button type="submit" name="ok" value="1" class="btn" style="width:100%">Continue</button>
        </form>
        <?php if (!empty($captchaError)): ?>
            <p class="error-text" style="margin-top:12px"><?= htmlspecialchars($captchaError, ENT_QUOTES, 'UTF-8') ?></p>
        <?php endif; ?>
    </div>

<?php else: ?>

    <main id="workspace">
        <div id="workspace-top">
            <div class="brand"><div class="brand-icon" aria-hidden="true">&gt;_</div><div><div class="brand-title">Network Console <span style="color:var(--acc)">/</span></div><div class="brand-subtitle">Diagnostics &amp; developer utilities</div></div></div>
            <div class="top-actions"><span class="status">Session active</span><button class="ui-button" id="help-button" type="button">Help</button><button class="ui-button" id="copy-button" type="button">Copy output</button><button class="ui-button" id="clear-button" type="button">Clear</button></div>
        </div>
        <section id="terminal-shell" aria-label="Interactive network console">
            <div id="header-bar">
                <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
                <span class="title">console.nkotov.net — terminal</span>
                <span class="session">● <?= $displayName ?></span>
            </div>
            <div id="output" role="log" aria-live="polite" aria-relevant="additions"></div>
            <div id="loader" role="status"><span>▌</span> Executing command...</div>
            <div id="input-wrapper">
                <label for="command-input" class="prompt-label"><span class="host">~</span> $</label>
                <input type="text" id="command-input" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="Enter command, e.g. help" maxlength="2048" autofocus aria-label="Console command">
                <button class="ui-button" id="run-button" type="button">Run ↵</button>
            </div>
            <div id="terminal-footer"><span><span class="kbd">↑</span> <span class="kbd">↓</span> history &nbsp; <span class="kbd">Enter</span> run</span><span><span class="kbd">Ctrl</span> + <span class="kbd">L</span> clear &nbsp; • &nbsp; First-party, privacy-friendly</span></div>
        </section>
    </main>

    <script>
    const input   = document.getElementById('command-input');
    const output  = document.getElementById('output');
    const loader  = document.getElementById('loader');
    const history = [];
    let histIdx   = -1;

    // Key handling: history navigation + submit
    input.addEventListener('keydown', e => {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (histIdx < history.length - 1) {
                histIdx++;
                input.value = history[histIdx];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (histIdx > 0) {
                histIdx--;
                input.value = history[histIdx];
            } else {
                histIdx = -1;
                input.value = '';
            }
        } else if (e.key === 'Enter') {
            e.preventDefault();
            submit();
        } else if (e.key === 'l' && e.ctrlKey) {
            e.preventDefault();
            output.innerHTML = '';
        }
    });

    async function submit() {
        const cmd = input.value.trim();
        if (!cmd) return;

        history.unshift(cmd);
        histIdx = -1;
        input.value = '';

        // Render command echo
        const block = document.createElement('div');
        block.className = 'cmd-block';
        const line = document.createElement('div');
        line.className = 'cmd-line';
        const prompt = document.createElement('span');
        prompt.className = 'prompt';
        prompt.textContent = '~ $ ';
        const entered = document.createElement('span');
        entered.className = 'entered-command';
        entered.textContent = cmd;
        line.append(prompt, entered);
        block.appendChild(line);
        output.appendChild(block);

        // Client-side commands
        if (cmd.toLowerCase() === 'clear' || cmd.toLowerCase() === 'cls') {
            output.innerHTML = '';
            return;
        }

        loader.classList.add('active');
        input.disabled = true;

        try {
            const fd = new FormData();
            fd.append('command', cmd);
            fd.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>');

            const res  = await fetch('', { method: 'POST', body: fd });
            const text = await res.text();

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const out = document.createElement('div');
            out.className = 'result';
            out.innerHTML = text;
            block.appendChild(out);
        } catch (err) {
            const pre = document.createElement('pre');
            pre.className = 'result error-text';
            pre.textContent = 'Network error: ' + err.message;
            block.appendChild(pre);
        } finally {
            loader.classList.remove('active');
            input.disabled = false;
            input.focus();
            block.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }

    function escHtml(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    document.getElementById('run-button').addEventListener('click', submit);
    document.getElementById('help-button').addEventListener('click', () => { input.value = 'help'; submit(); });
    document.getElementById('clear-button').addEventListener('click', () => { output.replaceChildren(); input.focus(); });
    document.getElementById('copy-button').addEventListener('click', async () => {
        const button = document.getElementById('copy-button');
        try {
            await navigator.clipboard.writeText(output.innerText);
            button.textContent = 'Copied ✓';
            input.focus();
        } catch (err) {
            button.textContent = 'Copy unavailable';
        }
    });
    document.getElementById('terminal-shell').addEventListener('click', e => {
        if (e.target === output || e.target === document.getElementById('terminal-shell')) input.focus();
    });
    </script>

<?php endif; ?>

</body>
</html>
