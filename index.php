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

    // IP-based limits shared across sessions (including fresh browser sessions).
    // Use the actual TCP peer address; never trust client-supplied IP headers.
    $clientIp = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $cmdParts = preg_split('/\\s+/', trim((string)$_POST['command']), 2);
    $cmdName = strtolower($cmdParts[0] ?? '');
    $heavy = in_array($cmdName, ['nmap', 'tracert', 'whois', 'rdap', 'dnsbl', 'dnssec'], true);
    $limitFile = sys_get_temp_dir() . '/console-rate-' . hash('sha256', $clientIp) . '.json';
    $fp = @fopen($limitFile, 'c+');
    if ($fp === false || !flock($fp, LOCK_EX)) {
        if (is_resource($fp)) fclose($fp);
        http_response_code(503);
        echo 'Rate limiter temporarily unavailable.';
        exit();
    }
    $now = time();
    $state = json_decode(stream_get_contents($fp) ?: '', true);
    if (!is_array($state) || ($state['until'] ?? 0) <= $now) {
        $state = ['until' => $now + 60, 'all' => 0, 'heavy' => 0];
    }
    $state['all']++;
    if ($heavy) $state['heavy']++;
    $limited = $state['all'] > 60 || $state['heavy'] > 8;
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, json_encode($state));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($limited) {
        http_response_code(429);
        header('Retry-After: ' . max(1, $state['until'] - $now));
        echo 'Rate limit exceeded. Please wait.';
        exit();
    }

    // Rate limiting
    $_SESSION['rate_limit']['count']++;
    if ($_SESSION['rate_limit']['count'] > 60) {
        echo '<span style="color:#ff6b6b">Rate limit exceeded. Please wait.</span>';
        exit();
    }

    // Process-wide concurrency cap shared by all PHP-FPM workers and sessions.
    // Keep locks open for the entire command; OS releases them on worker exit.
    // Lock files are permanent: never unlink them (avoids split-lock races).
    $slotDir = sys_get_temp_dir();
    $acquireSlot = static function (string $kind, int $capacity) use ($slotDir) {
        for ($slot = 0; $slot < $capacity; $slot++) {
            $path = $slotDir . '/console-exec-' . $kind . '-' . $slot . '.lock';
            $handle = @fopen($path, 'c');
            if ($handle === false) return false;
            if (flock($handle, LOCK_EX | LOCK_NB)) return $handle;
            fclose($handle);
        }
        return false;
    };
    $globalSlot = $acquireSlot('global', 6);
    if ($globalSlot === false) {
        http_response_code(429);
        header('Retry-After: 3');
        echo 'Server busy. Please retry shortly.';
        exit();
    }
    $heavySlot = null;
    if ($heavy) {
        $heavySlot = $acquireSlot('heavy', 2);
        if ($heavySlot === false) {
            flock($globalSlot, LOCK_UN);
            fclose($globalSlot);
            http_response_code(429);
            header('Retry-After: 3');
            echo 'Heavy command capacity reached. Please retry shortly.';
            exit();
        }
    }
    // Explicit release also covers normal return; PHP releases locks on fatal exit.
    try {
        require './console.php';
    } finally {
        if (is_resource($heavySlot)) {
            flock($heavySlot, LOCK_UN);
            fclose($heavySlot);
        }
        flock($globalSlot, LOCK_UN);
        fclose($globalSlot);
    }
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
body{margin:0;min-height:100vh;background:radial-gradient(ellipse 65% 45% at 85% 0%,var(--page-glow),transparent),radial-gradient(ellipse 50% 40% at 0% 90%,var(--page-glow2),transparent),var(--bg);color:var(--fg);font:14px/1.65 var(--font);padding:24px clamp(12px,3vw,48px) 32px}
body::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.22;background-image:linear-gradient(#ffffff06 1px,transparent 1px),linear-gradient(90deg,#ffffff06 1px,transparent 1px);background-size:36px 36px;z-index:-1}
button,input{font:inherit}button{cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid var(--acc);outline-offset:3px}
::selection{background:#28776f;color:white}
#workspace{width:min(100%,1320px);margin:0 auto}
#workspace-top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}.brand-icon{width:44px;height:44px;display:grid;place-items:center;border:1px solid var(--brand-border);border-radius:12px;background:var(--brand-bg);color:var(--acc);font-size:22px;box-shadow:0 0 25px #36c4b318}
.brand-title{font-size:17px;font-weight:750;letter-spacing:-.5px}.brand-subtitle{font:12px/1.3 var(--font);color:var(--muted)}
.top-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.status{font-size:12px;color:var(--ok);margin-right:12px}.status::before{content:"";display:inline-block;width:7px;height:7px;background:var(--ok);border-radius:50%;margin-right:7px;box-shadow:0 0 12px var(--ok)}
.ui-button{border:1px solid var(--border);background:var(--button-bg);color:var(--button-text);padding:8px 13px;border-radius:8px;transition:background .2s,border-color .2s}.ui-button:hover{background:var(--button-hover);border-color:var(--acc)}
#terminal-shell{border:1px solid var(--terminal-outline);border-radius:15px;background:var(--terminal-bg);overflow:hidden;box-shadow:0 24px 80px #0008,0 0 0 1px #ffffff05;min-height:66vh;display:flex;flex-direction:column}
#header-bar{display:flex;align-items:center;gap:8px;padding:13px 17px;background:var(--header-bg);border-bottom:1px solid var(--border);font-size:12px;color:var(--muted)}
#header-bar .dot{width:10px;height:10px;border-radius:50%}#header-bar .dot.r{background:#ff6c70}#header-bar .dot.y{background:#ffcf68}#header-bar .dot.g{background:#61d79c}
#header-bar .title{flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#header-bar .session{font-size:11px;color:#7d96a9}
#output{flex:1;min-height:350px;padding:24px clamp(16px,3vw,34px);overflow-wrap:anywhere}
#output:empty::before{content:"Welcome to console.nkotov.net  •  Type help to get started";display:block;color:var(--muted);white-space:pre-wrap;padding:2px 0}
.cmd-block{margin:0 0 24px;padding-bottom:18px;border-bottom:1px solid var(--line)}.cmd-block:last-child{border-bottom:0}.cmd-line{color:var(--fg);overflow-wrap:anywhere}.cmd-line .prompt,.prompt-label{color:var(--ok)}.cmd-line .host,.prompt-label .host{color:var(--acc)}.cmd-line .entered-command{color:var(--command-fg)}
.result{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px 0 0 16px;margin-top:8px;border-left:2px solid #2a4a56;font-size:13px;line-height:1.65;color:var(--result-fg)}
.result a{color:var(--acc);text-decoration:underline;text-underline-offset:3px}.result b{color:#eef8ff}.error-text{color:var(--err)}.success-text{color:var(--ok)}
#loader{display:none;padding:8px 26px;color:var(--acc);font-size:12px}#loader.active{display:block}#loader span{display:inline-block;animation:blink 1s step-start infinite}@keyframes blink{50%{opacity:0}}
#input-wrapper{display:flex;align-items:center;gap:12px;padding:16px clamp(14px,3vw,30px);border-top:1px solid var(--border);background:var(--input-bg);position:sticky;bottom:0}
#input-wrapper .prompt-label{white-space:nowrap;font-size:13px;user-select:none}#command-input{flex:1;min-width:0;border:0;background:transparent;color:var(--fg);outline:none;caret-color:var(--acc);font-size:14px}#command-input::placeholder{color:#71899e}
#terminal-footer{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:10px 17px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);background:var(--footer-bg)}
.kbd{display:inline-block;border:1px solid #405166;border-radius:4px;padding:0 5px;color:#c6d5e3}
.btn{background:#172b39;color:var(--fg);border:1px solid #385263;border-radius:7px;padding:9px 16px;cursor:pointer}.btn:hover{background:#203a49}
#captcha-gate{box-shadow:0 22px 65px #0008}
/* Theme palettes use variables consumed by every surface, not just text. */
body{--page-glow:#12304566;--page-glow2:#102a3360;--terminal-bg:#0c1420;--header-bg:#172638;--input-bg:#132030;--footer-bg:#0e1926;--button-bg:#142132;--button-hover:#1b3043;--button-text:#d9e5f1;--terminal-outline:#304356;--output-bg:transparent;--result-fg:#b7c8d7;--command-fg:#f4f8ff;--line:#203044;--brand-bg:#123038;--brand-border:#28776f}
body.theme-A{--bg:#061009;--surface2:#09160d;--fg:#a5f5b0;--muted:#72ac7d;--acc:#74f87a;--ok:#75e78c;--border:#285638;--page-glow:#164b2366;--page-glow2:#092d1160;--terminal-bg:#09160d;--header-bg:#102518;--input-bg:#102518;--footer-bg:#0b1c11;--button-bg:#14321e;--button-hover:#1c4329;--button-text:#c2f6c9;--terminal-outline:#346a42;--result-fg:#a8d9b0;--command-fg:#e4ffe8;--line:#23472b;--brand-bg:#12341d;--brand-border:#2c7842}
body.theme-B{--bg:#edf3f7;--surface2:#fff;--fg:#1e3242;--muted:#5b7184;--acc:#087d83;--ok:#14784a;--err:#c02949;--border:#becedb;--page-glow:#a5cad433;--page-glow2:#c8dce933;--terminal-bg:#fff;--header-bg:#e8f0f5;--input-bg:#f0f6f9;--footer-bg:#e8f0f5;--button-bg:#e6eef4;--button-hover:#d6e6ee;--button-text:#1e3242;--terminal-outline:#b4c5d3;--output-bg:#fff;--result-fg:#344e60;--command-fg:#203a4c;--line:#dce6ed;--brand-bg:#dceef0;--brand-border:#9bc9cb;color-scheme:light}
body.theme-C{--bg:#141a20;--fg:#d2dae2;--muted:#98a5b2;--acc:#e2e9ef;--ok:#bfcbd8;--border:#3c4b58;--page-glow:#35404b55;--page-glow2:#202c3855;--terminal-bg:#19222b;--header-bg:#27333e;--input-bg:#27333e;--footer-bg:#202a34;--button-bg:#2a3744;--button-hover:#3a4b59;--button-text:#e4ebf1;--terminal-outline:#536473;--result-fg:#c0cbd5;--command-fg:#fff;--line:#3b4b58;--brand-bg:#2a3944;--brand-border:#657685}
body.theme-D{--bg:#180e1b;--fg:#f4d9ee;--muted:#b18ba9;--acc:#f3a6d2;--ok:#b6a2ed;--border:#50324e;--page-glow:#6b235266;--page-glow2:#36235b66;--terminal-bg:#1d1121;--header-bg:#301c35;--input-bg:#2b1a30;--footer-bg:#241529;--button-bg:#39223c;--button-hover:#4b2b50;--button-text:#f5e1f1;--terminal-outline:#654263;--result-fg:#e0bcd7;--command-fg:#fff;--line:#492b48;--brand-bg:#38223b;--brand-border:#94577c}
body.theme-X{--bg:#101023;--fg:#e4e0ff;--muted:#a19bc4;--acc:#b8b0ff;--ok:#91e0f1;--border:#37365e;--page-glow:#493a9466;--page-glow2:#243b8c66;--terminal-bg:#13132a;--header-bg:#242344;--input-bg:#222140;--footer-bg:#1b1b35;--button-bg:#2c2b50;--button-hover:#3c3966;--button-text:#ece9ff;--terminal-outline:#555287;--result-fg:#c4c0e8;--command-fg:#fff;--line:#36345b;--brand-bg:#29274b;--brand-border:#7870c1}
body.theme-P{--bg:#09162a;--fg:#d9e8ff;--muted:#8aa8ca;--acc:#9fb7ff;--ok:#b6d0ff;--border:#274366;--page-glow:#164b8c66;--page-glow2:#102a6466;--terminal-bg:#0c1c35;--header-bg:#142b49;--input-bg:#132b49;--footer-bg:#0e2340;--button-bg:#193757;--button-hover:#24496f;--button-text:#e1ecff;--terminal-outline:#355a83;--result-fg:#b9d0ee;--command-fg:#fff;--line:#244366;--brand-bg:#183c59;--brand-border:#447ca0}
@media(max-width:640px){body{padding:14px 9px 20px}#workspace-top{gap:12px}.brand-title{font-size:15px}.status{display:none}#terminal-shell{min-height:75vh}#output{padding:18px 14px;min-height:320px}.result{font-size:12px;padding-left:10px}#input-wrapper{gap:7px;padding:14px 11px}.prompt-label{font-size:11px!important}#command-input{font-size:13px}#header-bar .session{display:none}#terminal-footer{font-size:10px}}
/* Fixed viewport console: scroll command history inside the terminal only. */
html,body{height:100%;overflow:hidden}
body{height:100dvh;min-height:0;display:flex;flex-direction:column;padding-bottom:24px}
#workspace{height:100%;min-height:0;display:flex;flex-direction:column}
#workspace-top{flex:0 0 auto}
#terminal-shell{flex:1 1 auto;min-height:0;height:auto}
#output{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:#39566b transparent}
#input-wrapper,#terminal-footer,#header-bar{flex-shrink:0}
#input-wrapper{position:relative;bottom:auto}
@media(max-width:640px){body{height:100dvh;padding-bottom:12px}#terminal-shell{min-height:0}#output{min-height:0}}
.theme-label{color:var(--muted);font-size:12px}#theme-picker{max-width:132px;color:var(--button-text);background:var(--button-bg);border:1px solid var(--border)}#theme-picker option{color:#d9e5f1;background:#142132}
/* Header controls */
#workspace-top{gap:18px;padding:2px 0 6px}
.brand{min-width:0}.brand-title{font-size:18px;letter-spacing:-.6px}.brand-subtitle{letter-spacing:.1px}
.top-actions{gap:16px;justify-content:flex-end}
.action-group{display:flex;gap:8px;align-items:center;padding-left:14px;border-left:1px solid var(--border)}
.ui-button{display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:42px;padding:9px 14px;white-space:nowrap;font-size:13px;font-weight:600}
.action-icon{display:block;flex:0 0 auto}
.ui-button .action-icon{color:var(--acc)}
.ui-button:active{transform:translateY(1px)}
.theme-control{display:flex;align-items:center;gap:10px}
.theme-control-icon{color:var(--acc);display:flex;align-items:center}
.theme-label{color:var(--muted);font-size:12px;font-weight:600}
.theme-select-wrap{position:relative;display:flex;align-items:center;min-width:142px}
#theme-picker{appearance:none;-webkit-appearance:none;display:block;width:100%;max-width:none;min-height:42px;padding:9px 37px 9px 14px;border:1px solid var(--border);border-radius:9px;background:var(--button-bg);color:var(--button-text);font:600 13px/1.4 var(--font);cursor:pointer;outline:none}
#theme-picker:hover{border-color:var(--acc);background:var(--button-hover)}
#theme-picker:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.theme-select-wrap>.action-icon{position:absolute;right:12px;top:50%;transform:translateY(-50%);pointer-events:none;color:var(--muted);width:16px;height:16px}
#theme-picker option{background:#142132;color:#d9e5f1}
.status{margin-right:0;white-space:nowrap}
@media(max-width:900px){#workspace-top{align-items:flex-start}.top-actions{gap:10px}.action-group{padding-left:0;border-left:0}.brand-subtitle{font-size:11px}}
@media(max-width:640px){#workspace-top{gap:14px}.top-actions{width:100%;justify-content:space-between;gap:8px}.theme-control{gap:7px}.theme-label{display:none}.theme-select-wrap{min-width:120px}.action-group{gap:6px}.ui-button{min-height:39px;padding:8px 10px;gap:6px}.action-group .button-label{display:none}.status{display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;scroll-behavior:auto!important}}
</style>

<body>

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
            <div class="top-actions">
                <div class="theme-control"><span class="theme-control-icon"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18h1.5a2.5 2.5 0 0 0 2.1-4 1.5 1.5 0 0 1 1.3-2.3H19a2 2 0 0 0 2-2 9 9 0 0 0-9-9Z"/><circle cx="7.5" cy="11" r=".7" fill="currentColor" stroke="none"/><circle cx="10" cy="7.5" r=".7" fill="currentColor" stroke="none"/><circle cx="15" cy="8" r=".7" fill="currentColor" stroke="none"/></svg></span><label for="theme-picker" class="theme-label">Theme</label><div class="theme-select-wrap"><select id="theme-picker" aria-label="Console color theme"><option value="">Midnight</option><option value="A">Matrix</option><option value="B">Light</option><option value="C">Slate</option><option value="D">Rose</option><option value="X">Violet</option><option value="P">Ocean</option></select><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></div></div>
                <span class="status">Session active</span>
                <div class="action-group"><button class="ui-button" id="help-button" type="button" title="Show commands"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.7 2.7 0 1 1 4.7 1.8c-1.2 1.2-2.2 1.4-2.2 3.2"/><path d="M12 17.5h.01"/></svg><span>Help</span></button><button class="ui-button" id="copy-button" type="button" title="Copy terminal output"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg><span class="button-label">Copy output</span></button><button class="ui-button" id="screenshot-button" type="button" title="Save terminal screenshot as PNG"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="6" width="18" height="14" rx="2"/><circle cx="12" cy="13" r="3"/><path d="M8 6l1.5-2h5L16 6"/></svg><span class="button-label">Screenshot</span></button><button class="ui-button" id="clear-button" type="button" title="Clear terminal"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg><span>Clear</span></button></div></div>
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
    const themePicker = document.getElementById('theme-picker');
    const validThemes = ['', 'A', 'B', 'C', 'D', 'X', 'P'];
    let savedTheme = '';
    try { savedTheme = localStorage.getItem('console-theme') || ''; } catch (_) {}
    if (!validThemes.includes(savedTheme)) savedTheme = '';
    for (const t of validThemes) if (t) document.body.classList.remove('theme-' + t);
    if (savedTheme) document.body.classList.add('theme-' + savedTheme);
    themePicker.value = savedTheme;
    themePicker.addEventListener('change', () => {
        for (const t of validThemes) if (t) document.body.classList.remove('theme-' + t);
        if (themePicker.value && validThemes.includes(themePicker.value)) document.body.classList.add('theme-' + themePicker.value);
        try { localStorage.setItem('console-theme', themePicker.value); } catch (_) {}
    });
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
        output.scrollTop = output.scrollHeight;

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
            output.scrollTo({ top: output.scrollHeight, behavior: 'smooth' });
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
    // Capture the actual rendered terminal via the browser's screen-sharing API.
    // No image is uploaded; the captured frame is cropped and saved locally.
    document.getElementById('screenshot-button').addEventListener('click', async () => {
        const button = document.getElementById('screenshot-button');
        const originalLabel = button.querySelector('.button-label').textContent;
        let stream;
        try {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
                throw new Error('Screen capture is not supported by this browser');
            }
            stream = await navigator.mediaDevices.getDisplayMedia({
                video: { displaySurface: 'browser' },
                audio: false,
                preferCurrentTab: true,
                selfBrowserSurface: 'include'
            });
            const track = stream.getVideoTracks()[0];
            const settings = track.getSettings();
            if (settings.displaySurface && settings.displaySurface !== 'browser') {
                throw new Error('Please select this browser tab, not a window or screen');
            }
            const video = document.createElement('video');
            video.srcObject = stream;
            video.muted = true;
            video.playsInline = true;
            await video.play();
            if (!video.videoWidth || !video.videoHeight) {
                throw new Error('Unable to capture the browser tab');
            }
            const terminal = document.getElementById('terminal-shell');
            const rect = terminal.getBoundingClientRect();
            // Tab capture maps to the visible viewport; crop only the terminal.
            const sx = video.videoWidth / window.innerWidth;
            const sy = video.videoHeight / window.innerHeight;
            const left = Math.max(0, Math.round(rect.left * sx));
            const top = Math.max(0, Math.round(rect.top * sy));
            const width = Math.min(video.videoWidth - left, Math.round(rect.width * sx));
            const height = Math.min(video.videoHeight - top, Math.round(rect.height * sy));
            if (width <= 0 || height <= 0) throw new Error('Terminal is outside the captured area');
            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            canvas.getContext('2d').drawImage(video, left, top, width, height, 0, 0, width, height);
            const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
            if (!blob) throw new Error('Could not encode PNG');
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'console-' + new Date().toISOString().replace(/[:.]/g, '-') + '.png';
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            button.querySelector('.button-label').textContent = 'Saved';
        } catch (err) {
            if (err.name !== 'NotAllowedError') {
                alert('Screenshot: ' + err.message);
            }
        } finally {
            if (stream) stream.getTracks().forEach(track => track.stop());
            button.querySelector('.button-label').textContent = originalLabel;
        }
    });
    document.getElementById('terminal-shell').addEventListener('click', e => {
        if (e.target === output || e.target === document.getElementById('terminal-shell')) input.focus();
    });
    </script>

<?php endif; ?>

</body>
</html>
