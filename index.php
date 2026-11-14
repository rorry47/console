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
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg:   #1d1d1d;
            --fg:   #cccccc;
            --acc:  #6CF7FC;
            --muted:#888;
            --err:  #ff6b6b;
            --ok:   #6bcb77;
            --font: 'Arial', monospace;
        }

        body {
            padding: 10px;
            background: #141414;
            color: var(--fg);
            font-family: var(--font);
            font-size: 15px;
            line-height: 1.5;
            min-height: 100vh;
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #444; border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: #666; }

        /* Header bar */
        #header-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 10px;
            background: #141414;
            width: 100%;
            border: 1px solid #2e2e2e;
            border-radius: 6px;
            margin-bottom: -5px;
            position: relative;
            font-size: 13px;
            color: var(--muted);
        }
        #header-bar .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        #header-bar .dot.r { background: #ff5f57; }
        #header-bar .dot.y { background: #febc2e; }
        #header-bar .dot.g { background: #28c840; }
        #header-bar .title { flex: 1; text-align: center; color: var(--muted); }

        /* Output area */
        #output {
            margin: 0px 10px 0px 10px;
            background: #040404;
            border-left: 1px solid #2e2e2e;
            border-right: 1px solid #2e2e2e;
            padding: 50px 20px 20px 20px;
        }

        /* Each command block */
        .cmd-block { margin-bottom: 14px; }
        .cmd-line  { color: var(--acc); margin-bottom: 4px; word-break: break-all; }
        .cmd-line .prompt { color: var(--ok); }
        .cmd-line .host   { color: #aaa; }
        .inc_logo {
            background: #686868;
            border-radius: 4px;
            margin-right: 5px;
        }

        .result {
            white-space: pre-wrap;
            word-break: break-word;
            padding: 4px 20px 0;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.1;
            color: var(--fg);
        }
        .result a { color: var(--acc); text-decoration: none; }
        .result a:hover { text-decoration: underline; }
        .result b { color: var(--fg); }
        .error-text { color: var(--err); }
        .success-text { color: var(--ok); }

        /* Input form */
        #input-wrapper {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            background: #141414;
            border: 1px solid #2e2e2e;
            border-radius: 6px;
            position: sticky;
            bottom: 0px;
        }
        #input-wrapper .prompt-label {
            white-space: nowrap;
            color: var(--ok);
            font-size: 15px;
            user-select: none;
            display: flex;
            align-items: center;
        }
        #input-wrapper .prompt-label .host { color: var(--acc); }
        #command-input {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            color: var(--fg);
            font-family: var(--font);
            font-size: 15px;
            caret-color: var(--acc);
        }
        #command-input::selection { background: #2a4a5a; }

        /* Loader */
        #loader {
            display: none;
            color: var(--muted);
            font-size: 13px;
            padding: 4px 20px 0;
            font-size: 12px;
            line-height: 1.1;
        }
        #loader.active { display: block;
            color: var(--muted);
            background: #000000;
            border-left: 1px solid #2e2e2e;
            font-size: 13px;
            padding: 8px 10px;
            font-size: 12px;
            line-height: 1.1;}
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        #loader span { animation: blink 1s step-start infinite; }

        /* Recaptcha gate */
        #captcha-gate {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 16px;
            padding: 20px 0;
        }
        .btn {
            background: #2a2a2a;
            color: var(--fg);
            border: 1px solid #444;
            border-radius: 5px;
            padding: 6px 22px;
            font-family: var(--font);
            font-size: 14px;
            cursor: pointer;
            transition: background .15s, border-color .15s;
        }
        .btn:hover { background: #333; border-color: #666; }

        /* Color themes */
        body.theme-A { --bg:#000; --fg:#00C000; --acc:#00C000; --ok:#00a000; }
        body.theme-B { --bg:#fff; --fg:#1d1d1d; --acc:#1d1d1d; --ok:#333; --err:#c00; }
        body.theme-B ::-webkit-scrollbar-track { background: #eee; }
        body.theme-B ::-webkit-scrollbar-thumb { background: #bbb; }
        body.theme-C { --bg:#424242; --fg:#B8B8B8; --acc:#fff; --ok:#ccc; }
        body.theme-D { --bg:#281022; --fg:#fff; --acc:#898989; --ok:#ccc; }
        body.theme-X {
            --fg:#fff; --acc:#a0a0ff; --ok:#ccc;
            background: linear-gradient(to right, #1a2a6c, #b21f1f, #fdbb2d) !important;
        }
        body.theme-P { --bg:#1a2a6c; --fg:#fff; --acc:#898989; }

        /* Mobile */
        @media (max-width: 600px) {
            body { font-size: 13px; padding: 8px 8px 70px; }
            #command-input { font-size: 13px; }
        }
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

    <!-- Main console UI -->
    <div id="header-bar">
        <span class="dot r"></span>
        <span class="dot y"></span>
        <span class="dot g"></span>
        <span class="title"><b>console</b></span>
        <span><?= $displayName ?></span>
    </div>

    <div id="output"></div>
    <div id="loader"><span>▌</span> running...</div>

    <div id="input-wrapper">
        <span class="prompt-label">
            <img src="/command-line.png" width="15px" class="inc_logo"> <b></b_><?= $displayName ?>@<span class="host">console</span> #:</b>
        </span>
        <input
            type="text"
            id="command-input"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            placeholder="type a command or 'help'"
            autofocus
        >
    </div>

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
        block.innerHTML = `<div class="cmd-line"><span class="prompt"><img src="/command-line.png" width="15px" class="inc_logo"><b><?= $displayName ?>@<span class="host">console</span> #:</b></span> ${escHtml(cmd)}</div>`;
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
            window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
        }
    }

    function escHtml(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // Auto-focus on click anywhere
    document.addEventListener('click', () => input.focus());
    </script>

<?php endif; ?>

</body>
</html>
