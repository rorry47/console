<?php
// ════════════════════════════════════════════════════════════════
//  CONFIG
// ════════════════════════════════════════════════════════════════

define('RECAPTCHA_ENABLED', true);          // true or false

define('RECAPTCHA_SITE_KEY',   'XXXXXXXXXXXXXXXXXXXXXXXXX');  // (site key)
define('RECAPTCHA_SECRET_KEY', 'XXXXXXXXXXXXXXXXXXXXXXXX'); // (secret key)

// ════════════════════════════════════════════════════════════════
session_start();

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting (max 60 requests per minute per session)
if (!isset($_SESSION['rate_limit'])) {
    $_SESSION['rate_limit'] = ['count' => 0, 'reset' => time() + 60];
}
if (time() > $_SESSION['rate_limit']['reset']) {
    $_SESSION['rate_limit'] = ['count' => 0, 'reset' => time() + 60];
}

// ── AJAX command handler: respond with plain output only, no HTML ────────────
if (!empty($_SESSION['var']) && isset($_POST['command'])) {
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
// Если капча выключена — пускаем сразу без проверки
if (!RECAPTCHA_ENABLED && empty($_SESSION['var'])) {
    $_SESSION['var'] = '1';
    header('Location: ' . (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}
?>

<?php if (empty($_SESSION['var'])): ?>
    <!-- reCAPTCHA gate -->
    <div id="captcha-gate">
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div class="g-recaptcha" data-theme="dark" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY, ENT_QUOTES, 'UTF-8') ?>"></div>
            <br>
            <button type="submit" name="ok" class="btn">OK</button>
        </form>
        <?php
        if (isset($_POST['ok'])) {
            // Validate CSRF
            if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
                echo '<p class="error-text">CSRF validation failed.</p>';
                exit();
            }
            if (empty($_POST['g-recaptcha-response'])) {
                echo '<p class="error-text">reCAPTCHA verification failed, please try again.</p>';
            } else {
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL            => 'https://www.google.com/recaptcha/api/siteverify',
                    CURLOPT_POST           => true,
                    CURLOPT_POSTFIELDS     => http_build_query(['secret' => RECAPTCHA_SECRET_KEY, 'response' => $_POST['g-recaptcha-response'], 'remoteip' => $_SERVER['REMOTE_ADDR']]),
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT        => 10,
                    CURLOPT_SSL_VERIFYPEER => true,
                ]);
                $response = curl_exec($ch);
                curl_close($ch);
                $result = json_decode($response, true);
                if (!empty($result['success'])) {
                    $_SESSION['var'] = '1';
                    header('Location: ' . (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
                    exit();
                }
                echo '<p class="error-text">reCAPTCHA verification failed, please try again.</p>';
            }
        }
        ?>
    </div>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

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
