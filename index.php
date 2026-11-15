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
    if (!is_string($_POST['command']) || strlen($_POST['command']) > 2048) {
        http_response_code(400);
        echo 'Invalid command.';
        exit();
    }
    $cmdParts = preg_split('/\s+/', trim($_POST['command']), 2);
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
    // Occasionally purge stale IP counters without scanning unbounded directories.
    if (random_int(1, 200) === 1) {
        $dir = @opendir(sys_get_temp_dir());
        if ($dir !== false) {
            $scanned = 0;
            $removed = 0;
            while ($scanned < 2000 && $removed < 100 && ($name = readdir($dir)) !== false) {
                $scanned++;
                if (!preg_match('/^console-rate-[a-f0-9]{64}\\.json$/D', $name)) continue;
                $path = sys_get_temp_dir() . '/' . $name;
                $mtime = @filemtime($path);
                if ($mtime !== false && $mtime < time() - 172800 && @unlink($path)) $removed++;
            }
            closedir($dir);
        }
    }
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
/* Additional palettes: pure black OLED, soft pastel, warm paper, muted sage. */
body.theme-K{--bg:#000;--surface2:#050505;--fg:#e8e8e8;--muted:#9b9b9b;--acc:#c9d5df;--ok:#88d6b0;--err:#f08e96;--border:#303030;--page-glow:transparent;--page-glow2:transparent;--terminal-bg:#050505;--header-bg:#0d0d0d;--input-bg:#0c0c0c;--footer-bg:#090909;--button-bg:#151515;--button-hover:#242424;--button-text:#eee;--terminal-outline:#363636;--output-bg:transparent;--result-fg:#c7c7c7;--command-fg:#fff;--line:#252525;--brand-bg:#101010;--brand-border:#555;color-scheme:dark}
body.theme-L{--bg:#f7f2fa;--surface2:#fffaff;--fg:#51445f;--muted:#7e708b;--acc:#926da8;--ok:#4c897a;--err:#bb5976;--border:#dfd0e8;--page-glow:#e9d6f344;--page-glow2:#d8e5fa44;--terminal-bg:#fffaff;--header-bg:#f1e8f6;--input-bg:#faf5fd;--footer-bg:#f6eff9;--button-bg:#f0e6f5;--button-hover:#e6d8ed;--button-text:#574762;--terminal-outline:#d8c6e2;--output-bg:transparent;--result-fg:#675671;--command-fg:#40334d;--line:#eadff0;--brand-bg:#f0e5f5;--brand-border:#cdb2dd;color-scheme:light}
body.theme-W{--bg:#f7f4ed;--surface2:#fffdf8;--fg:#423d36;--muted:#82796d;--acc:#a2764b;--ok:#5c8562;--err:#b95f57;--border:#ddd4c5;--page-glow:#e9d8bc33;--page-glow2:#f0e6d433;--terminal-bg:#fffdf8;--header-bg:#f0e9dd;--input-bg:#faf5eb;--footer-bg:#f4eee3;--button-bg:#eee5d7;--button-hover:#e5d8c5;--button-text:#4c4135;--terminal-outline:#d6c9b5;--output-bg:transparent;--result-fg:#5e564c;--command-fg:#332c25;--line:#e8dfd2;--brand-bg:#f0e5d3;--brand-border:#cfb998;color-scheme:light}
body.theme-S{--bg:#101b18;--surface2:#15231e;--fg:#d7e5db;--muted:#91ad9c;--acc:#a8c8ad;--ok:#91c6a1;--err:#e39b9b;--border:#334d40;--page-glow:#254d3933;--page-glow2:#1b3e3033;--terminal-bg:#14211b;--header-bg:#1e3027;--input-bg:#1b2d24;--footer-bg:#19281f;--button-bg:#253a2e;--button-hover:#314b3b;--button-text:#e0eee3;--terminal-outline:#405a49;--output-bg:transparent;--result-fg:#c1d3c6;--command-fg:#f4fff5;--line:#304739;--brand-bg:#263e30;--brand-border:#587a60;color-scheme:dark}
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
#theme-picker option{background:var(--button-bg);color:var(--button-text)}
.status{margin-right:0;white-space:nowrap}
@media(max-width:900px){#workspace-top{align-items:flex-start}.top-actions{gap:10px}.action-group{padding-left:0;border-left:0}.brand-subtitle{font-size:11px}}
@media(max-width:640px){#workspace-top{gap:14px}.top-actions{width:100%;justify-content:space-between;gap:8px}.theme-control{gap:7px}.theme-label{display:none}.theme-select-wrap{min-width:120px}.action-group{gap:6px}.ui-button{min-height:39px;padding:8px 10px;gap:6px}.action-group .button-label{display:none}.status{display:none}}
/* Readable result cards and scoped actions. */
.cmd-block{padding:0 0 19px;margin-bottom:20px}
.cmd-heading{display:flex;align-items:center;gap:10px;min-width:0}
.cmd-heading .cmd-line{flex:1;min-width:0}
.cmd-actions{display:flex;gap:6px;flex:0 0 auto}
.cmd-copy{font:600 11px/1.4 var(--font);color:var(--muted);background:var(--button-bg);border:1px solid var(--border);border-radius:6px;padding:5px 9px;transition:color .2s,border-color .2s,background .2s}
.cmd-copy:hover{color:var(--acc);border-color:var(--acc);background:var(--button-hover)}
.result{padding:14px 15px;margin-top:12px;border:1px solid var(--line);border-left:3px solid var(--border);border-radius:9px;background:var(--page-glow2)}
.cmd-block:hover .result{border-left-color:var(--acc)}
.result.is-error{border-left-color:var(--err)!important}
.result.is-success{border-left-color:var(--ok)!important}
.result .token-ip,.result .token-domain{color:var(--acc);font-weight:600}
.result .token-http-ok{color:var(--ok);font-weight:700}
.result .token-http-warn{color:#f0bf70;font-weight:700}
.result .token-http-error{color:var(--err);font-weight:700}
@media(max-width:640px){.cmd-heading{align-items:flex-start}.cmd-copy{padding:5px 7px}.result{padding:11px 10px}}
/* Compact single-row toolbar: keep actions accessible without pushing terminal down. */
#workspace-top{gap:12px;margin-bottom:12px}
.top-actions{gap:10px;flex-wrap:nowrap;min-width:0}
.action-group{gap:5px;padding-left:10px;flex-wrap:nowrap}
.action-group .ui-button{width:38px;min-width:38px;height:38px;min-height:38px;padding:0;gap:0;border-radius:9px}
.action-group .ui-button > span{display:none}
.action-group .ui-button .action-icon{width:18px;height:18px}
.export-controls{gap:4px}
#export-format{height:38px;max-width:64px}
.theme-control{gap:7px}
.theme-select-wrap{min-width:0}
#theme-picker{max-width:145px}
@media(max-width:1100px){
  #workspace-top{align-items:flex-start}
  .top-actions{width:100%;justify-content:space-between;flex-wrap:wrap;row-gap:8px}
  .action-group{padding-left:0;border-left:0}
}
@media(max-width:640px){
  #workspace-top{gap:8px;margin-bottom:10px}
  .top-actions{gap:6px}
  .action-group{gap:4px}
  .action-group .ui-button{width:34px;min-width:34px;height:36px;min-height:36px}
  #export-format{height:36px;max-width:58px;font-size:10px}
  #theme-picker{max-width:120px}
}
/* Export controls share the existing action-bar visual language. */
.export-controls{display:flex;align-items:center;gap:5px}
#export-format{height:36px;max-width:74px;border:1px solid var(--border);border-radius:7px;background:var(--button-bg);color:var(--fg);font:inherit;font-size:11px;padding:0 5px}
#export-format:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:640px){#export-format{height:39px;max-width:65px}}
/* Terminal tabs and searchable command palette */
#terminal-tabs{display:flex;align-items:center;gap:5px;padding:7px 10px;border-bottom:1px solid var(--border);background:var(--footer-bg);overflow-x:auto;flex-shrink:0}
.terminal-tab{display:flex;align-items:center;gap:8px;white-space:nowrap;border:1px solid transparent;border-radius:7px;padding:7px 10px;background:transparent;color:var(--muted);font:inherit;font-size:12px;cursor:pointer}
.terminal-tab[aria-selected="true"]{color:var(--acc);background:var(--button-hover);border-color:var(--border)}
.tab-close{color:var(--muted);padding:0 3px;font-size:15px;cursor:pointer}
.tab-close:hover{color:var(--err)}
#new-tab{border:1px solid var(--border);border-radius:7px;background:var(--button-bg);color:var(--fg);padding:6px 11px;cursor:pointer}
#command-palette{position:fixed;inset:0;z-index:1000;background:#000a;display:grid;place-items:start center;padding:12vh 15px 20px}
#command-palette[hidden]{display:none}
.palette-dialog{width:min(570px,100%);max-height:75vh;display:flex;flex-direction:column;overflow:hidden;border:1px solid var(--terminal-outline);border-radius:14px;background:var(--terminal-bg);box-shadow:0 24px 80px #000b}
#palette-search{width:100%;box-sizing:border-box;background:transparent;border:0;border-bottom:1px solid var(--border);padding:17px;color:var(--fg);font:inherit;outline:none}
#palette-results{overflow:auto;padding:7px}
.palette-option{display:flex;justify-content:space-between;gap:15px;width:100%;padding:11px;border:0;border-radius:8px;background:transparent;color:var(--fg);text-align:left;cursor:pointer;font:inherit}
.palette-option[aria-selected="true"],.palette-option:hover{background:var(--button-hover)}
.palette-option strong{color:var(--acc)}
.palette-option small{color:var(--muted)}
.palette-footer{border-top:1px solid var(--border);padding:9px 14px;color:var(--muted);font-size:11px}
@media(max-width:640px){#terminal-tabs{padding:5px}.terminal-tab{padding:6px 8px}.palette-option{flex-direction:column;gap:2px}}
/* Command completion: compact keyboard-accessible suggestions. */
#input-wrapper{z-index:3}
#completion-panel{position:absolute;bottom:calc(100% + 8px);left:clamp(14px,3vw,30px);right:clamp(14px,3vw,30px);max-height:min(310px,45vh);overflow:auto;border:1px solid var(--terminal-outline);border-radius:12px;background:var(--terminal-bg);box-shadow:0 16px 44px #0008;padding:6px;scrollbar-width:thin}
#completion-panel[hidden]{display:none}
.completion-item{display:flex;width:100%;gap:12px;align-items:center;justify-content:space-between;padding:9px 12px;text-align:left;color:var(--fg);background:transparent;border:0;border-radius:7px}
.completion-item:hover,.completion-item[aria-selected="true"]{background:var(--button-hover)}
.completion-item[aria-selected="true"]{box-shadow:inset 2px 0 0 var(--acc)}
.completion-command{color:var(--acc);font-weight:700;white-space:nowrap}
.completion-description{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.completion-hint{padding:6px 12px 3px;color:var(--muted);font-size:11px;border-top:1px solid var(--border)}
@media(max-width:640px){.completion-item{align-items:flex-start;flex-direction:column;gap:1px}.completion-description{max-width:100%}#completion-panel{max-height:35vh}}
/* Network activity visualization: decorative, not a connectivity indicator. */
.brand-icon svg{width:29px;height:29px;overflow:visible;filter:drop-shadow(0 0 8px var(--page-glow))}
.brand-icon .logo-cursor{animation:logo-cursor 1.4s steps(1,end) infinite}
@keyframes logo-cursor{50%{opacity:.15}}
.terminal-identity{display:inline-flex;align-items:center;gap:8px;min-width:0;flex:1;justify-content:center}
.terminal-identity svg{flex:0 0 auto;color:var(--acc);opacity:.85}
#header-bar .title{flex:0 1 auto}
.network-activity{display:inline-flex;align-items:center;gap:3px;height:18px;padding:0 3px;color:var(--acc)}
.network-activity i{display:block;width:3px;height:5px;border-radius:3px;background:currentColor;opacity:.35;transform-origin:bottom;animation:activity-bars 1.35s ease-in-out infinite}
.network-activity i:nth-child(2){animation-delay:.16s}
.network-activity i:nth-child(3){animation-delay:.32s}
.network-activity i:nth-child(4){animation-delay:.48s}
@keyframes activity-bars{0%,100%{height:5px;opacity:.3}45%{height:14px;opacity:.85}}
#terminal-shell.is-executing .network-activity i{animation-duration:.55s}
#terminal-shell.is-executing #header-bar::after{opacity:.85}
.terminal-rail{display:flex;align-items:center;gap:9px;min-width:0}
.terminal-rail .session{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:170px}
#loader.active{display:flex;align-items:center;gap:10px}
#loader.active::before{content:"";width:10px;height:10px;border:2px solid var(--border);border-top-color:var(--acc);border-radius:50%;animation:loader-spin .7s linear infinite}
@keyframes loader-spin{to{transform:rotate(360deg)}}
#loader.active span{display:none}
@media(max-width:640px){.terminal-identity{gap:5px}.terminal-identity svg{width:13px;height:13px}.network-activity{gap:2px}.network-activity i{width:2px}.terminal-rail{display:none}#header-bar .title{font-size:11px}}
@media(prefers-reduced-motion:reduce){.brand-icon .logo-cursor,.network-activity i,#loader.active::before{animation:none!important}}
/* UI refresh: decorative layers, improved hierarchy and accessible focus. */
body{position:relative;isolation:isolate}
body::after{content:"";position:fixed;inset:-35%;z-index:-1;pointer-events:none;background:conic-gradient(from 160deg at 50% 50%,transparent 0deg,var(--page-glow) 68deg,transparent 135deg,var(--page-glow2) 235deg,transparent 310deg);filter:blur(95px);opacity:.33;animation:ambient-drift 28s ease-in-out infinite alternate}
@keyframes ambient-drift{from{transform:translate3d(-3%,1%,0) rotate(-8deg)}to{transform:translate3d(4%,-3%,0) rotate(9deg)}}

/* Quiet ambient background: slow drifting dot field, no JS or canvas. */
body::before{
  inset:-48px;
  opacity:.38;
  background-image:radial-gradient(circle,var(--border) .75px,transparent 1px);
  background-size:32px 32px;
  background-position:0 0;
  animation:background-dots 75s linear infinite;
  will-change:transform;
}
@keyframes background-dots{
  from{transform:translate3d(0,0,0)}
  to{transform:translate3d(32px,32px,0)}
}
/* Ambient dotted waves: decorative SVG behind the workspace, GPU-friendly motion. */
body::before{display:none}
.dot-waves{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;overflow:hidden;color:var(--acc);opacity:.52}
.dot-waves .wave{fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-dasharray:.1 11;vector-effect:non-scaling-stroke}
.dot-waves .wave-layer{transform-box:fill-box;transform-origin:center;animation:dot-wave-swell 17s ease-in-out infinite}
.dot-waves .wave-layer:nth-child(2){animation-duration:23s;animation-delay:-8s;opacity:.68}
.dot-waves .wave-layer:nth-child(3){animation-duration:29s;animation-delay:-13s;opacity:.42}
/* Oscillate wave amplitude and phase rather than merely sliding the pattern. */
@keyframes dot-wave-swell{
  0%,100%{transform:translate3d(-18px,8px,0) scaleY(.76) skewX(-3deg)}
  25%{transform:translate3d(5px,-10px,0) scaleY(1.15) skewX(2deg)}
  50%{transform:translate3d(23px,6px,0) scaleY(.88) skewX(4deg)}
  75%{transform:translate3d(-3px,15px,0) scaleY(1.23) skewX(-2deg)}
}
#workspace{position:relative;z-index:1}
body.theme-K .dot-waves{opacity:.38}
@media(prefers-reduced-motion:reduce){.dot-waves .wave-layer{animation:none!important}}
/* Keep OLED genuinely black, with only a faint graphite dot pattern. */
body.theme-K::after{display:none}
body.theme-K::before{opacity:.28}
@media(prefers-reduced-motion:reduce){body::before{animation:none!important;will-change:auto}}

#workspace-top{position:relative}
.brand-icon{position:relative;overflow:hidden;font-weight:800;letter-spacing:-2px;box-shadow:inset 0 1px 0 #ffffff19,0 8px 26px #0003,0 0 25px var(--page-glow);transition:transform .25s ease,box-shadow .25s ease}
.brand-icon::after{content:"";position:absolute;inset:-50%;background:linear-gradient(120deg,transparent 35%,#ffffff22 50%,transparent 65%);transform:translateX(-90%) rotate(15deg);transition:transform .65s ease}
.brand:hover .brand-icon{transform:translateY(-2px)}
.brand:hover .brand-icon::after{transform:translateX(90%) rotate(15deg)}
.brand-title{font-weight:800}
.brand-subtitle{opacity:.95}
#terminal-shell{position:relative;box-shadow:0 28px 90px #0008,0 0 0 1px #ffffff07,inset 0 1px 0 #ffffff0c;transition:border-color .3s ease,box-shadow .3s ease}
/* Keep terminal frame visually stable while typing or focusing controls. */
#header-bar{position:relative;min-height:49px;background:linear-gradient(180deg,#ffffff09,transparent),var(--header-bg)}
#header-bar::after{content:"";position:absolute;bottom:-1px;left:0;width:100%;height:1px;background:linear-gradient(90deg,transparent,var(--acc),transparent);opacity:.35}
#header-bar .dot{box-shadow:inset 0 1px 2px #ffffff66,0 0 0 1px #0003}
#header-bar .title{font-weight:650;letter-spacing:.12px;color:var(--fg)}
#output{background:radial-gradient(ellipse 75% 60% at 50% 0%,var(--page-glow),transparent 75%),var(--output-bg)}
.cmd-block{position:relative;animation:command-enter .23s ease-out both}
@keyframes command-enter{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}
.cmd-line{font-weight:600;letter-spacing:.05px}
.cmd-line .entered-command{font-weight:500}
.result{border-left-color:var(--border);border-radius:0 8px 8px 0;transition:border-color .2s ease}
.cmd-block:hover .result{border-left-color:var(--acc)}
#input-wrapper{background:linear-gradient(180deg,#ffffff05,transparent),var(--input-bg);box-shadow:0 -8px 30px #00000014}
#input-wrapper:focus-within .prompt-label{filter:drop-shadow(0 0 6px var(--page-glow))}
#command-input{line-height:1.8}
#command-input:focus-visible{outline:none}
#run-button{border-color:var(--brand-border);background:var(--brand-bg);color:var(--acc);font-weight:750}
#run-button:hover{background:var(--button-hover);box-shadow:0 0 0 1px var(--brand-border)}
.ui-button{transition:background .2s,border-color .2s,transform .2s,box-shadow .2s}
.ui-button:hover{transform:translateY(-1px);box-shadow:0 4px 14px #0002}
.ui-button:active{transform:translateY(0)}
#terminal-footer{background:linear-gradient(180deg,#ffffff04,transparent),var(--footer-bg)}
.kbd{background:#7f9ab014;border-color:var(--border);box-shadow:inset 0 -1px 0 #0002}
@media(max-width:640px){#header-bar{min-height:44px}#workspace-top{padding-top:0}.brand-icon{width:40px;height:40px}.ui-button:hover{transform:none}}
@media(prefers-reduced-motion:reduce){body::after,.cmd-block{animation:none!important}.brand-icon,.ui-button,#terminal-shell{transition:none!important}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;scroll-behavior:auto!important}}

/* User preferences dialog and responsive console layout. */
body.console-wide{padding-left:10px;padding-right:10px}
body.console-wide #workspace{width:100%;max-width:none}
body.console-full{padding:0}
body.console-full #workspace{width:100%;max-width:none}
body.console-full #workspace-top{padding:9px 14px;margin:0}
body.console-full #terminal-shell{border-radius:0;border-left:0;border-right:0;border-bottom:0}
body.console-font-custom{font-family:var(--user-font)}
body.console-font-custom #command-input,body.console-font-custom .brand-subtitle{font-family:var(--user-font)}
body.console-font-size{font-size:var(--user-font-size)}
body.console-font-size #command-input{font-size:inherit}
body.console-font-size .result{font-size:inherit}
body.console-font-size .cmd-line{font-size:inherit}
body.console-font-size #output{font-size:inherit}
body.bg-off .dot-waves,body.bg-off::after{display:none}
body.bg-grid .dot-waves{display:none}
body.bg-grid::before{display:block;z-index:0;inset:0;opacity:.42;animation:none;background-image:radial-gradient(circle,var(--acc) 1px,transparent 1.5px);background-size:32px 32px}
body.bg-static .wave-layer{animation:none!important}
#settings-dialog[hidden]{display:none}
#settings-dialog{position:fixed;inset:0;z-index:1200;display:grid;place-items:center;padding:16px;background:#0009;backdrop-filter:blur(5px)}
.settings-panel{width:min(100%,470px);max-height:min(90dvh,750px);overflow-y:auto;border:1px solid var(--terminal-outline);border-radius:16px;background:var(--terminal-bg);color:var(--fg);box-shadow:0 24px 90px #0009;padding:23px}
.settings-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:17px}
.settings-head h2{margin:0;font-size:18px}
.settings-close{background:var(--button-bg);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:4px 10px;font-size:22px;line-height:1.2}
.settings-field{display:grid;gap:7px;margin:0 0 17px}
.settings-field label{font-weight:650;font-size:13px}
.settings-field select,.settings-field input[type=color]{width:100%;min-height:41px;border:1px solid var(--border);border-radius:8px;background:var(--input-bg);color:var(--fg);padding:8px;font:inherit}
.settings-field input[type=color]{padding:4px;cursor:pointer}
.settings-field input[type=range]{width:100%;accent-color:var(--acc)}
.settings-field .settings-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.settings-field output{color:var(--acc);font-variant-numeric:tabular-nums}
.settings-footer{display:flex;justify-content:space-between;gap:12px;padding-top:13px;border-top:1px solid var(--border)}
.settings-footer button{padding:9px 15px;border:1px solid var(--border);border-radius:8px;background:var(--button-bg);color:var(--fg)}
.settings-footer button:last-child{background:var(--brand-bg);color:var(--acc)}
@media(max-width:640px){body.console-full #workspace-top{padding:8px} .settings-panel{padding:17px}}

</style>

<body>
    <svg class="dot-waves" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">
        <g class="wave-layer">
            <path class="wave" d="M-200 490 C100 240 290 750 590 490 S1080 240 1380 490 S1790 740 1950 490"/>
            <path class="wave" d="M-200 515 C100 265 290 775 590 515 S1080 265 1380 515 S1790 765 1950 515"/>
            <path class="wave" d="M-200 540 C100 290 290 800 590 540 S1080 290 1380 540 S1790 790 1950 540"/>
            <path class="wave" d="M-200 565 C100 315 290 825 590 565 S1080 315 1380 565 S1790 815 1950 565"/>
        </g>
        <g class="wave-layer">
            <path class="wave" d="M-200 210 C120 430 330 -40 640 210 S1110 440 1440 210 S1810 -10 1960 210"/>
            <path class="wave" d="M-200 235 C120 455 330 -15 640 235 S1110 465 1440 235 S1810 15 1960 235"/>
            <path class="wave" d="M-200 260 C120 480 330 10 640 260 S1110 490 1440 260 S1810 40 1960 260"/>
        </g>
        <g class="wave-layer">
            <path class="wave" d="M-200 770 C120 520 340 970 640 770 S1110 540 1440 770 S1800 990 1960 770"/>
            <path class="wave" d="M-200 795 C120 545 340 995 640 795 S1110 565 1440 795 S1800 1015 1960 795"/>
            <path class="wave" d="M-200 820 C120 570 340 1020 640 820 S1110 590 1440 820 S1800 1040 1960 820"/>
        </g>
    </svg>

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
            <div class="brand"><div class="brand-icon" aria-hidden="true"><svg viewBox="0 0 36 36" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 11 8 7-8 7"/><path d="M19 26h9"/><path class="logo-cursor" d="M29 9v6" stroke-width="2"/></svg></div><div><div class="brand-title">Network Console <span style="color:var(--acc)">/</span></div><div class="brand-subtitle">Diagnostics &amp; developer utilities</div></div></div>
            <div class="top-actions">
                <div class="theme-control"><span class="theme-control-icon"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18h1.5a2.5 2.5 0 0 0 2.1-4 1.5 1.5 0 0 1 1.3-2.3H19a2 2 0 0 0 2-2 9 9 0 0 0-9-9Z"/><circle cx="7.5" cy="11" r=".7" fill="currentColor" stroke="none"/><circle cx="10" cy="7.5" r=".7" fill="currentColor" stroke="none"/><circle cx="15" cy="8" r=".7" fill="currentColor" stroke="none"/></svg></span><label for="theme-picker" class="theme-label">Theme</label><div class="theme-select-wrap"><select id="theme-picker" aria-label="Console color theme"><option value="">Midnight</option><option value="A">Matrix</option><option value="B">Light</option><option value="C">Slate</option><option value="D">Rose</option><option value="X">Violet</option><option value="P">Ocean</option><option value="K">OLED Black</option><option value="L">Lavender Mist</option><option value="W">Warm Paper</option><option value="S">Sage Forest</option></select><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></div></div>
                <button class="ui-button" id="settings-button" type="button" title="Customize console" aria-label="Open console settings" aria-haspopup="dialog"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2 2-.06-.06A1.7 1.7 0 0 0 15.9 18.5a1.7 1.7 0 0 0-1.1 1.55V21h-2.8v-.95a1.7 1.7 0 0 0-1.1-1.55 1.7 1.7 0 0 0-1.84.38l-.06.06-2-2 .06-.06A1.7 1.7 0 0 0 7.4 15a1.7 1.7 0 0 0-1.55-1.1H5v-2.8h.85A1.7 1.7 0 0 0 7.4 10a1.7 1.7 0 0 0-.34-1.88L7 8.06l2-2 .06.06A1.7 1.7 0 0 0 10.9 6.5 1.7 1.7 0 0 0 12 4.95V4h2.8v.95a1.7 1.7 0 0 0 1.1 1.55 1.7 1.7 0 0 0 1.84-.38l.06-.06 2 2-.06.06A1.7 1.7 0 0 0 19.4 10a1.7 1.7 0 0 0 1.55 1.1H22v2.8h-1.05A1.7 1.7 0 0 0 19.4 15Z" transform="translate(-1 -1)"/></svg><span class="button-label">Settings</span></button><div class="action-group"><button class="ui-button" id="help-button" type="button" title="Show commands"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.7 2.7 0 1 1 4.7 1.8c-1.2 1.2-2.2 1.4-2.2 3.2"/><path d="M12 17.5h.01"/></svg><span>Help</span></button><button class="ui-button" id="copy-button" type="button" title="Copy terminal output"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg><span class="button-label">Copy output</span></button><div class="export-controls"><label class="sr-only" for="export-format">Report format</label><select id="export-format" aria-label="Report format"><option value="txt">TXT</option><option value="json">JSON</option><option value="pdf">PDF</option></select><button class="ui-button" id="export-button" type="button" title="Export completed results from the current tab"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12m-4-4 4 4 4-4"/><path d="M5 16v4h14v-4"/></svg><span class="button-label">Export</span></button></div><button class="ui-button" id="screenshot-button" type="button" title="Save terminal screenshot as PNG"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="6" width="18" height="14" rx="2"/><circle cx="12" cy="13" r="3"/><path d="M8 6l1.5-2h5L16 6"/></svg><span class="button-label">Screenshot</span></button><button class="ui-button" id="clear-button" type="button" title="Clear terminal"><svg class="action-icon" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg><span>Clear</span></button></div></div>
        </div>
        <section id="terminal-shell" aria-label="Interactive network console">
            <div id="header-bar">
                <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
                <span class="terminal-identity"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 10 3 2-3 2m6 0h4"/></svg><span class="title"><span id="terminal-identity-name"><?= htmlspecialchars((string)($_SESSION['name'] ?? 'console.nkotov.net'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span> — terminal</span></span>
                <span class="terminal-rail"><span class="session">● <?= $displayName ?></span></span>
            </div>
            <div id="terminal-tabs" role="tablist" aria-label="Terminal tabs"></div>
            <div id="output" role="log" aria-live="polite" aria-relevant="additions"></div>
            <div id="loader" role="status"><span>▌</span> Executing command...</div>
            <div id="input-wrapper">
                <label for="command-input" class="prompt-label"><span class="host">~</span> $</label>
                <input type="text" id="command-input" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="Enter command, e.g. help" maxlength="2048" autofocus aria-label="Console command" aria-controls="completion-panel" aria-expanded="false" aria-autocomplete="list">
                <div id="completion-panel" role="listbox" aria-label="Command suggestions" hidden></div>
                <button class="ui-button" id="run-button" type="button">Run ↵</button>
            </div>
            <div id="terminal-footer"><span><span class="kbd">↑</span> <span class="kbd">↓</span> history &nbsp; <span class="kbd">Enter</span> run &nbsp; <span class="kbd">Tab</span> complete &nbsp; <span class="kbd">Ctrl</span>+<span class="kbd">K</span> commands</span><span><span class="kbd">Ctrl</span> + <span class="kbd">L</span> clear &nbsp; • &nbsp; First-party, privacy-friendly</span></div>
        </section>
    </main>

    <div id="settings-dialog" hidden>
        <section class="settings-panel" role="dialog" aria-modal="true" aria-labelledby="settings-title">
            <div class="settings-head"><h2 id="settings-title">Console settings</h2><button id="settings-close" class="settings-close" type="button" aria-label="Close settings">×</button></div>
            <div class="settings-field"><label for="settings-font">Font family</label><select id="settings-font"><option value="default">System monospace</option><option value="menlo">Menlo / Monaco</option><option value="consolas">Consolas</option><option value="courier">Courier New</option><option value="system">System UI</option><option value="serif">Serif</option></select></div>
            <div class="settings-field"><div class="settings-row"><label for="settings-size">Font size</label><output id="settings-size-value" for="settings-size">14 px</output></div><input id="settings-size" type="range" min="11" max="22" step="1" value="14"></div>
            <div class="settings-field"><label for="settings-background">Background</label><select id="settings-background"><option value="waves">Animated dotted waves</option><option value="static">Static dotted waves</option><option value="grid">Dot grid</option><option value="off">No animation / plain background</option></select></div>
            <div class="settings-field"><label for="settings-color">Custom accent color</label><input id="settings-color" type="color" value="#62e6da"><label class="settings-row" style="font-weight:400"><span>Use custom color</span><input id="settings-custom-color" type="checkbox"></label></div>
            <div class="settings-field"><label for="settings-width">Console width</label><select id="settings-width"><option value="normal">Standard (1320 px)</option><option value="wide">Wide (full available width)</option><option value="full">Full page (edge to edge)</option></select></div>
            <div class="settings-footer"><button id="settings-reset" type="button">Reset defaults</button><button id="settings-done" type="button">Done</button></div>
        </section>
    </div>
    <div id="command-palette" hidden>
        <div class="palette-dialog" role="dialog" aria-modal="true" aria-label="Command palette">
            <input id="palette-search" type="search" placeholder="Search commands by name or purpose..." autocomplete="off" aria-label="Search commands">
            <div id="palette-results" role="listbox" aria-label="Matching commands"></div>
            <div class="palette-footer">↑ ↓ navigate · Enter insert · Esc close</div>
        </div>
    </div>
    <script>
    const themePicker = document.getElementById('theme-picker');
    const validThemes = ['', 'A', 'B', 'C', 'D', 'X', 'P', 'K', 'L', 'W', 'S'];
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

    // Appearance preferences are local to this browser; never sent to the server.
    const settingsKey = 'console-appearance-v1';
    const settingsDialog = document.getElementById('settings-dialog');
    const settingsButton = document.getElementById('settings-button');
    const settingsFields = {
        font: document.getElementById('settings-font'),
        size: document.getElementById('settings-size'),
        background: document.getElementById('settings-background'),
        color: document.getElementById('settings-color'),
        customColor: document.getElementById('settings-custom-color'),
        width: document.getElementById('settings-width')
    };
    const appearanceDefaults = {font:'default',size:14,background:'waves',color:'#62e6da',customColor:false,width:'normal'};
    const fontChoices = {
        default:'',menlo:'Menlo, Monaco, monospace',consolas:'Consolas, monospace',
        courier:'"Courier New", monospace',system:'system-ui, sans-serif',serif:'Georgia, serif'
    };
    let appearance = {...appearanceDefaults};
    try {
        const stored = JSON.parse(localStorage.getItem(settingsKey) || '{}');
        if (stored && typeof stored === 'object' && !Array.isArray(stored)) appearance = {...appearance, ...stored};
    } catch (_) {}
    function validateAppearance(value) {
        return {
            font:Object.hasOwn(fontChoices,value.font) ? value.font : 'default',
            size:Number.isInteger(Number(value.size)) ? Math.max(11,Math.min(22,Number(value.size))) : 14,
            background:['waves','static','grid','off'].includes(value.background) ? value.background : 'waves',
            color:typeof value.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(value.color) ? value.color : '#62e6da',
            customColor:value.customColor === true,
            width:['normal','wide','full'].includes(value.width) ? value.width : 'normal'
        };
    }
    function applyAppearance() {
        appearance = validateAppearance(appearance);
        document.body.classList.toggle('console-font-custom',appearance.font !== 'default');
        document.body.classList.toggle('console-font-size',appearance.size !== 14);
        document.body.style.setProperty('--user-font',fontChoices[appearance.font] || 'inherit');
        document.body.style.setProperty('--user-font-size',appearance.size + 'px');
        for (const cls of ['bg-off','bg-grid','bg-static','console-wide','console-full']) document.body.classList.remove(cls);
        if (appearance.background !== 'waves') document.body.classList.add('bg-' + appearance.background);
        if (appearance.width !== 'normal') document.body.classList.add('console-' + appearance.width);
        if (appearance.customColor) document.body.style.setProperty('--acc',appearance.color);
        else document.body.style.removeProperty('--acc');
        settingsFields.font.value = appearance.font;
        settingsFields.size.value = String(appearance.size);
        document.getElementById('settings-size-value').textContent = appearance.size + ' px';
        settingsFields.background.value = appearance.background;
        settingsFields.color.value = appearance.color;
        settingsFields.customColor.checked = appearance.customColor;
        settingsFields.width.value = appearance.width;
    }
    function saveAppearance() {
        applyAppearance();
        try { localStorage.setItem(settingsKey,JSON.stringify(appearance)); } catch (_) {}
    }
    function closeSettings() {
        settingsDialog.hidden = true;
        settingsButton.focus();
    }
    settingsButton.addEventListener('click',() => {
        settingsDialog.hidden = false;
        settingsFields.font.focus();
    });
    document.getElementById('settings-close').addEventListener('click',closeSettings);
    document.getElementById('settings-done').addEventListener('click',closeSettings);
    settingsDialog.addEventListener('click',e => { if (e.target === settingsDialog) closeSettings(); });
    settingsDialog.addEventListener('keydown',e => {
        if (e.key === 'Escape') { e.preventDefault(); closeSettings(); return; }
        if (e.key !== 'Tab') return;
        const focusables = [...settingsDialog.querySelectorAll('button,select,input:not([disabled])')];
        const first = focusables[0], last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {e.preventDefault();last.focus();}
        else if (!e.shiftKey && document.activeElement === last) {e.preventDefault();first.focus();}
    });
    for (const [key,field] of Object.entries(settingsFields)) {
        field.addEventListener('input',() => {
            appearance[key] = key === 'customColor' ? field.checked : key === 'size' ? Number(field.value) : field.value;
            saveAppearance();
        });
    }
    document.getElementById('settings-reset').addEventListener('click',() => {
        appearance = {...appearanceDefaults};
        saveAppearance();
    });
    applyAppearance();

    const input   = document.getElementById('command-input');
    const output  = document.getElementById('output');
    const loader  = document.getElementById('loader');
    const history = [];
    let histIdx   = -1;

    // Per-tab history survives reload, but is not uploaded or stored permanently.
    // Each tab has its own history, input draft and bounded transcript.
    const tabsKey = 'console-tabs-v1';
    const legacyKey = 'console-transcript-v1';
    const transcriptLimit = 30;
    const transcriptMaxChars = 120000;
    const maxTabs = 6;
    let tabs = [];
    let activeTab = 0;
    let transcript = [];
    const tabBar = document.getElementById('terminal-tabs');
    function persistTabs() {
        try {
            tabs[activeTab].transcript = transcript;
            tabs[activeTab].draft = input.value;
            tabs[activeTab].history = history.slice(0,60);
            sessionStorage.setItem(tabsKey,JSON.stringify({active:activeTab,tabs:tabs.map(t=>({
                transcript:t.transcript,history:t.history,draft:t.draft
            }))}));
        } catch (_) {}
    }
    function clearTranscript() {
        transcript = [];
        output.replaceChildren();
        persistTabs();
    }
    function rememberResult(command,result,status) {
        transcript.push({command:command.slice(0,2048),result:result.slice(0,transcriptMaxChars),status:status|0});
        while (transcript.length > transcriptLimit || JSON.stringify(transcript).length > transcriptMaxChars) transcript.shift();
        persistTabs();
    }
    function makeRestoredBlock(entry) {
        const block = document.createElement('div');
        block.className = 'cmd-block';
        const heading = document.createElement('div');
        heading.className = 'cmd-heading';
        const line = document.createElement('div');
        line.className = 'cmd-line';
        const prompt = document.createElement('span');
        prompt.className = 'prompt';
        prompt.textContent = '~ $ ';
        const entered = document.createElement('span');
        entered.className = 'entered-command';
        entered.textContent = entry.command;
        line.append(prompt,entered);
        const actions = document.createElement('div');
        actions.className = 'cmd-actions';
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'cmd-copy';
        copy.textContent = 'Copy';
        copy.title = 'Copy this command and its result';
        copy.setAttribute('aria-label','Copy command and result');
        copy.addEventListener('click',async () => {
            try {
                await navigator.clipboard.writeText('~ $ ' + entry.command + '\n' + entry.result);
                copy.textContent = 'Copied ✓';
            } catch (_) { copy.textContent = 'Unavailable'; }
        });
        actions.append(copy);
        heading.append(line,actions);
        block.append(heading);
        const result = document.createElement('div');
        result.className = 'result';
        result.textContent = entry.result;
        enhanceResult(result,entry.status);
        block.append(result);
        return block;
    }
    function renderTab() {
        hideCompletions();
        const tab = tabs[activeTab];
        transcript = tab.transcript;
        history.splice(0,history.length,...tab.history);
        histIdx = -1;
        input.value = tab.draft;
        output.replaceChildren();
        for (const entry of transcript) output.append(makeRestoredBlock(entry));
        output.scrollTop = output.scrollHeight;
        tabBar.replaceChildren();
        tabs.forEach((t,i) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'terminal-tab';
            button.setAttribute('role','tab');
            button.setAttribute('aria-selected',String(i===activeTab));
            button.textContent = 'Terminal ' + (i+1);
            button.addEventListener('click',() => switchTab(i));
            if (tabs.length > 1) {
                const close = document.createElement('span');
                close.className = 'tab-close';
                close.textContent = '×';
                close.title = 'Close tab';
                close.addEventListener('click',e => { e.stopPropagation();closeTab(i); });
                button.append(close);
            }
            tabBar.append(button);
        });
        const add = document.createElement('button');
        add.id = 'new-tab';
        add.type = 'button';
        add.textContent = '+';
        add.title = 'New terminal tab (max 6)';
        add.disabled = tabs.length >= maxTabs;
        add.addEventListener('click',newTab);
        tabBar.append(add);
    }
    function switchTab(i) {
        if (input.disabled || i===activeTab || !tabs[i]) return;
        persistTabs();
        activeTab = i;
        renderTab();
        persistTabs();
        input.focus();
    }
    function newTab() {
        if (input.disabled || tabs.length >= maxTabs) return;
        persistTabs();
        tabs.push({transcript:[],history:[],draft:''});
        activeTab = tabs.length-1;
        renderTab();
        persistTabs();
        input.focus();
    }
    function closeTab(i) {
        if (input.disabled || tabs.length < 2) return;
        persistTabs();
        tabs.splice(i,1);
        if (i < activeTab) activeTab--;
        else if (i === activeTab) activeTab = Math.min(i,tabs.length-1);
        renderTab();
        persistTabs();
        input.focus();
    }
    try {
        const stored = JSON.parse(sessionStorage.getItem(tabsKey) || 'null');
        const legacy = JSON.parse(sessionStorage.getItem(legacyKey) || '[]');
        const entries = stored && Array.isArray(stored.tabs) ? stored.tabs : [{transcript:legacy,history:[],draft:''}];
        tabs = entries.slice(0,maxTabs).map(t => ({
            transcript:(Array.isArray(t.transcript)?t.transcript:[]).filter(e=>e&&typeof e.command==='string'&&typeof e.result==='string'&&Number.isInteger(e.status))
                .slice(-transcriptLimit).map(e=>({command:e.command.slice(0,2048),result:e.result.slice(0,transcriptMaxChars),status:e.status})),
            history:(Array.isArray(t.history)?t.history:[]).filter(v=>typeof v==='string').slice(0,60),
            draft:typeof t.draft==='string'?t.draft.slice(0,2048):''
        }));
        activeTab = stored && Number.isInteger(stored.active) ? Math.max(0,Math.min(stored.active,tabs.length-1)) : 0;
    } catch (_) { tabs=[]; }
    if (!tabs.length) tabs=[{transcript:[],history:[],draft:''}];
    try { sessionStorage.removeItem(legacyKey); } catch (_) {}

    // Local command catalog mirrors the server-side help list; no network requests.
    const commandCatalog = [
        ['whois','Domain or IP WHOIS lookup'],['rdap','Modern domain registration lookup'],
        ['geoip','Country, city, ISP and ASN'],['headers','HTTP response headers'],
        ['dnsbl','IP spam blacklist check'],['dnssec','DNSSEC validation'],
        ['redirect','Follow HTTP redirects'],['tech','Detect site technologies'],
        ['ping','ICMP connectivity test'],['httping','HTTP latency test'],
        ['dig','DNS record lookup'],['nslookup','DNS resolver lookup'],
        ['curl','Fetch HTTP headers'],['nmap','Scan common ports'],
        ['ssl','TLS certificate details'],['tracert','Trace network route'],
        ['ptr','Reverse DNS lookup'],['port','Check a TCP port'],
        ['passgen','Generate secure password'],['hash','Hash a string'],
        ['base64','Encode or decode Base64'],['urlencode','URL-encode text'],
        ['urldecode','URL-decode text'],['list','Fetch proxy lists'],
        ['myip','Display your IP'],['date','Server date and time'],
        ['uptime','Server uptime'],['whoami','Console identity'],
        ['su','Change display name'],['clear','Clear terminal output'],
        ['cls','Clear terminal output'],['info','About this console'],
        ['exit','Leave the console'],['help','Show available commands']
    ];
    const commandArgs = {
        dig:['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA','PTR','SRV'],
        base64:['encode','decode'],
        hash:['md5','sha1','sha256','sha512'],
        list:['proxy','http','socks4','socks5']
    };
    const palette = document.getElementById('command-palette');
    const paletteSearch = document.getElementById('palette-search');
    const paletteResults = document.getElementById('palette-results');
    let paletteMatches = [];
    let paletteIndex = 0;
    function closePalette() {
        palette.hidden = true;
        input.focus();
    }
    function selectPalette(index) {
        const item = paletteMatches[index];
        if (!item) return;
        input.value = item[0] + ' ';
        persistTabs();
        closePalette();
    }
    function renderPalette() {
        const query = paletteSearch.value.trim().toLowerCase();
        paletteMatches = commandCatalog.filter(([name,description]) =>
            name.includes(query) || description.toLowerCase().includes(query));
        paletteIndex = Math.min(paletteIndex,Math.max(0,paletteMatches.length-1));
        paletteResults.replaceChildren();
        paletteMatches.forEach(([name,description],i) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'palette-option';
            button.setAttribute('role','option');
            button.setAttribute('aria-selected',String(i===paletteIndex));
            const title = document.createElement('strong');
            title.textContent = name;
            const desc = document.createElement('small');
            desc.textContent = description;
            button.append(title,desc);
            button.addEventListener('click',() => selectPalette(i));
            paletteResults.append(button);
        });
    }
    function openPalette() {
        if (input.disabled) return;
        hideCompletions();
        palette.hidden = false;
        paletteSearch.value = '';
        paletteIndex = 0;
        renderPalette();
        paletteSearch.focus();
    }
    paletteSearch.addEventListener('input',() => {paletteIndex=0;renderPalette();});
    paletteSearch.addEventListener('keydown',e => {
        if (e.key === 'Escape') {e.preventDefault();closePalette();}
        else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            if (!paletteMatches.length) return;
            paletteIndex = (paletteIndex+(e.key==='ArrowDown'?1:-1)+paletteMatches.length)%paletteMatches.length;
            renderPalette();
            paletteResults.children[paletteIndex]?.scrollIntoView({block:'nearest'});
        } else if (e.key === 'Enter') {e.preventDefault();selectPalette(paletteIndex);}
    });
    palette.addEventListener('click',e => {if(e.target===palette)closePalette();});
    document.addEventListener('keydown',e => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase()==='k') {
            e.preventDefault();
            if (palette.hidden) openPalette(); else closePalette();
        } else if (e.key==='Escape' && !palette.hidden) closePalette();
    });
    input.addEventListener('input',persistTabs);

    const completionPanel = document.getElementById('completion-panel');
    let completionItems = [];
    let completionIndex = 0;
    renderTab();
    persistTabs();
    function hideCompletions() {
        completionPanel.hidden = true;
        completionPanel.replaceChildren();
        completionItems = [];
        input.setAttribute('aria-expanded','false');
        input.removeAttribute('aria-activedescendant');
    }
    function getCompletions(value) {
        const raw = value.trimStart();
        if (!raw || raw.length > 128 || /[\r\n]/.test(raw)) return [];
        const parts = raw.split(/\s+/);
        if (parts.length === 1) {
            const prefix = parts[0].toLowerCase();
            return commandCatalog.filter(([name]) => name.startsWith(prefix)).map(([name,desc]) => ({value:name,desc}));
        }
        const name = parts[0].toLowerCase();
        const options = commandArgs[name];
        if (!options || parts.length !== 2) return [];
        const prefix = parts[1].toLowerCase();
        return options.filter(v => v.toLowerCase().startsWith(prefix)).map(v => ({value:name+' '+v,desc:name+' option'}));
    }
    function markCompletion(index) {
        completionIndex = (index + completionItems.length) % completionItems.length;
        const buttons = completionPanel.querySelectorAll('.completion-item');
        buttons.forEach((button,i) => button.setAttribute('aria-selected',String(i === completionIndex)));
        const selected = buttons[completionIndex];
        if (selected) {
            input.setAttribute('aria-activedescendant',selected.id);
            selected.scrollIntoView({block:'nearest'});
        }
    }
    function showCompletions() {
        // Only suggest when editing at the end, so we never overwrite mid-string edits.
        if (input.disabled || input.selectionStart !== input.value.length || input.selectionEnd !== input.value.length) {
            hideCompletions(); return;
        }
        completionItems = getCompletions(input.value).slice(0,8);
        completionPanel.replaceChildren();
        if (!completionItems.length) { hideCompletions(); return; }
        completionItems.forEach((item,i) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'completion-item';
            button.id = 'completion-option-' + i;
            button.setAttribute('role','option');
            const command = document.createElement('span');
            command.className = 'completion-command';
            command.textContent = item.value;
            const description = document.createElement('span');
            description.className = 'completion-description';
            description.textContent = item.desc;
            button.append(command,description);
            button.addEventListener('mousedown',e => e.preventDefault());
            button.addEventListener('click',() => applyCompletion(i));
            completionPanel.append(button);
        });
        const hint = document.createElement('div');
        hint.className = 'completion-hint';
        hint.textContent = 'Tab / Enter select · ↑ ↓ navigate · Esc dismiss';
        completionPanel.append(hint);
        completionPanel.hidden = false;
        input.setAttribute('aria-expanded','true');
        markCompletion(0);
    }
    function applyCompletion(index) {
        const item = completionItems[index];
        if (!item) return;
        input.value = item.value + ' ';
        hideCompletions();
        input.focus();
    }
    input.addEventListener('input',showCompletions);
    input.addEventListener('blur',hideCompletions);

    // Key handling: history navigation + submit
    input.addEventListener('keydown', e => {
        if (e.key === 'Escape' && !completionPanel.hidden) {
            e.preventDefault();
            hideCompletions();
            return;
        }
        if (e.key === 'Tab' && !completionPanel.hidden) {
            e.preventDefault();
            applyCompletion(completionIndex);
            return;
        }
        if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && !completionPanel.hidden) {
            e.preventDefault();
            markCompletion(completionIndex + (e.key === 'ArrowDown' ? 1 : -1));
            return;
        }
        if (e.key === 'Enter' && !completionPanel.hidden) {
            e.preventDefault();
            applyCompletion(completionIndex);
            return;
        }
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
            clearTranscript();
        }
    });

    async function submit() {
        const cmd = input.value.trim();
        if (!cmd) return;
        hideCompletions();

        history.unshift(cmd);
        histIdx = -1;
        persistTabs();
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
        const heading = document.createElement('div');
        heading.className = 'cmd-heading';
        heading.appendChild(line);
        const actions = document.createElement('div');
        actions.className = 'cmd-actions';
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'cmd-copy';
        copy.textContent = 'Copy';
        copy.title = 'Copy this command and its result';
        copy.setAttribute('aria-label', 'Copy command and result');
        copy.addEventListener('click', async () => {
            const result = block.querySelector('.result');
            const content = '~ $ ' + cmd + (result ? '\n' + result.innerText : '');
            try {
                await navigator.clipboard.writeText(content);
                copy.textContent = 'Copied ✓';
            } catch (_) {
                copy.textContent = 'Unavailable';
            }
            // Restore on the next user interaction; no timer or layout changes.
        });
        actions.appendChild(copy);
        heading.appendChild(actions);
        block.appendChild(heading);
        output.appendChild(block);
        output.scrollTop = output.scrollHeight;

        // Client-side commands
        if (cmd.toLowerCase() === 'clear' || cmd.toLowerCase() === 'cls') {
            clearTranscript();
            return;
        }

        loader.classList.add('active');
        document.getElementById('terminal-shell').classList.add('is-executing');
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
            enhanceResult(out, res.status);
            block.appendChild(out);
            // Update the header only after the server confirms a successful su.
            const suMatch = /^su\s+([a-zA-Z0-9_-]{1,32})$/i.exec(cmd);
            if (res.ok && suMatch && out.textContent.trim() === 'Switched console identity to ' + suMatch[1]) {
                document.getElementById('terminal-identity-name').textContent = suMatch[1];
            }
            rememberResult(cmd, out.innerText, res.status);
        } catch (err) {
            const pre = document.createElement('pre');
            pre.className = 'result error-text';
            pre.textContent = 'Network error: ' + err.message;
            block.appendChild(pre);
            rememberResult(cmd, pre.innerText, 0);
        } finally {
            loader.classList.remove('active');
            document.getElementById('terminal-shell').classList.remove('is-executing');
            input.disabled = false;
            input.focus();
            output.scrollTo({ top: output.scrollHeight, behavior: 'smooth' });
            persistTabs();
        }
    }

    // Decorate text nodes only. Preserve server-rendered links and markup.
    function enhanceResult(root, status) {
        if (status >= 400) root.classList.add('is-error');
        // Limit DOM processing for unusually large outputs.
        if ((root.textContent || '').length > 30000) return;
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                if (!node.parentElement || node.parentElement.closest('a,script,style,.token-ip,.token-domain')) return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        const nodes = [];
        while (walker.nextNode() && nodes.length < 400) nodes.push(walker.currentNode);
        const pattern = /\bHTTP\/\d(?:\.\d)?\s+([1-5]\d{2})\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
        for (const node of nodes) {
            const text = node.nodeValue;
            pattern.lastIndex = 0;
            if (!pattern.test(text)) continue;
            pattern.lastIndex = 0;
            const fragment = document.createDocumentFragment();
            let last = 0;
            for (const match of text.matchAll(pattern)) {
                const value = match[0];
                const index = match.index;
                if (index > last) fragment.append(document.createTextNode(text.slice(last,index)));
                const token = document.createElement('span');
                const code = match[1] ? Number(match[1]) : 0;
                if (code) token.className = code < 300 ? 'token-http-ok' : code < 400 ? 'token-http-warn' : 'token-http-error';
                else token.className = /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(value) ? 'token-ip' : 'token-domain';
                token.textContent = value;
                fragment.append(token);
                last = index + value.length;
            }
            fragment.append(document.createTextNode(text.slice(last)));
            node.replaceWith(fragment);
        }
    }

    function escHtml(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    document.getElementById('run-button').addEventListener('click', submit);
    document.getElementById('help-button').title = 'Show commands (Ctrl+K to search)';
    document.getElementById('help-button').addEventListener('click', openPalette);
    document.getElementById('clear-button').addEventListener('click', () => { clearTranscript(); input.focus(); });
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
    // Export only completed results from the active tab. Never re-run commands.
    function reportData() {
        return {
            title: 'Network Console — Diagnostic Report',
            source: window.location.origin,
            generated_at: new Date().toISOString(),
            terminal: activeTab + 1,
            commands: transcript.map(({command,result,status}) => ({
                command, result, http_status: status || null
            }))
        };
    }
    function saveReportFile(content,type,extension) {
        const blob = new Blob([content],{type});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'console-report-' + new Date().toISOString().replace(/[:.]/g,'-') + '.' + extension;
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url),10000);
    }
    function reportAsText(data) {
        const sections = [
            data.title,
            'Source: ' + data.source,
            'Generated (UTC): ' + data.generated_at,
            'Terminal: ' + data.terminal,
            'Commands: ' + data.commands.length,
            '='.repeat(68)
        ];
        data.commands.forEach((entry,i) => {
            sections.push('', '[' + (i+1) + '] $ ' + entry.command,
                'HTTP status: ' + (entry.http_status ?? 'Unavailable'),
                '-'.repeat(68), entry.result);
        });
        return sections.join('\n') + '\n';
    }
    function reportAsPdf(data) {
        // Native browser print-to-PDF: content is inserted via textContent, not HTML.
        const win = window.open('','_blank');
        if (!win) {
            alert('Allow pop-ups to export a PDF report.');
            return;
        }
        win.opener = null;
        const doc = win.document;
        doc.title = 'Network Console — Diagnostic Report';
        const style = doc.createElement('style');
        style.textContent = '@page{size:A4;margin:17mm}body{font:13px/1.5 system-ui,sans-serif;color:#17202a;margin:30px}h1{font-size:22px;margin:0 0 8px}header{border-bottom:2px solid #148b92;padding-bottom:16px;margin-bottom:22px}.meta{font-size:11px;color:#50606c}section{break-inside:avoid-page;border:1px solid #d8e0e5;border-radius:8px;padding:14px;margin:0 0 16px}h2{font-size:14px;overflow-wrap:anywhere;margin:0 0 8px}pre{font:11px/1.5 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0 0}small{color:#53616d}@media print{body{margin:0}section{break-inside:auto}}';
        doc.head.append(style);
        const header = doc.createElement('header');
        const title = doc.createElement('h1');
        title.textContent = data.title;
        const meta = doc.createElement('div');
        meta.className = 'meta';
        meta.textContent = data.source + ' · ' + data.generated_at + ' · Terminal ' + data.terminal + ' · ' + data.commands.length + ' commands';
        header.append(title,meta);
        doc.body.append(header);
        data.commands.forEach((entry,i) => {
            const section = doc.createElement('section');
            const heading = doc.createElement('h2');
            heading.textContent = (i+1) + '. $ ' + entry.command;
            const status = doc.createElement('small');
            status.textContent = 'HTTP status: ' + (entry.http_status ?? 'Unavailable');
            const result = doc.createElement('pre');
            result.textContent = entry.result;
            section.append(heading,status,result);
            doc.body.append(section);
        });
        win.focus();
        win.print();
    }
    document.getElementById('export-button').addEventListener('click',() => {
        if (!transcript.length) {
            alert('No completed commands to export in this tab.');
            return;
        }
        const data = reportData();
        const format = document.getElementById('export-format').value;
        if (format === 'txt') saveReportFile(reportAsText(data),'text/plain;charset=utf-8','txt');
        else if (format === 'json') saveReportFile(JSON.stringify(data,null,2)+'\n','application/json;charset=utf-8','json');
        else if (format === 'pdf') reportAsPdf(data);
    });

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
