<?php

// ─── PHP 8.0 polyfills for PHP 7.4 ──────────────────────────────────────────
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}

/**
 * console.php — command handler
 * Security: all inputs sanitized, shell injection prevented via escapeshellarg()
 */

if (!isset($_POST['command'])) {
    exit();
}

// ─── Constants ──────────────────────────────────────────────────────────────
const VERSION       = '2.0';
const MAX_INPUT_LEN = 128;
const CONSOLE_URL   = 'https://example.com/';
const SITE_URL      = 'https://example.com/';

// ─── Parse input ─────────────────────────────────────────────────────────────
$raw     = trim($_POST['command']);
$tokens  = preg_split('/\s+/', $raw, 5);
$command = strtolower($tokens[0] ?? '');
$arg1    = $tokens[1] ?? '';
$arg2    = $tokens[2] ?? '';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Sanitize a hostname/IP: strip dangerous chars, limit length.
 */
function sanitizeHost(string $input): string {
    $clean = preg_replace('/[^a-zA-Z0-9.\-_:]/', '', $input);
    return substr($clean, 0, MAX_INPUT_LEN);
}

/**
 * Validate the input is a valid IP or resolvable hostname.
 * Returns true if safe to use with network tools.
 */
function validateHost(string $host): bool {
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return true;
    }
    $resolved = gethostbyname($host);
    return filter_var($resolved, FILTER_VALIDATE_IP) !== false;
}

/**
 * Blocked IPs/ranges that must not be targeted.
 */
function isBlocked(string $host): bool {
    $blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '::1'];
    if (in_array(strtolower($host), $blocked, true)) return true;
    // Block RFC-1918 private ranges
    $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return true;
    }
    return false;
}

/**
 * Run a shell command safely and print its output line by line.
 */
function runAndPrint(array $parts): void {
    $cmd = implode(' ', array_map('escapeshellarg', $parts));
    exec($cmd . ' 2>&1', $output);
    foreach ($output as $line) {
        echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
    }
}

/**
 * Print an error message.
 */
function err(string $msg): void {
    echo '<span class="error-text">' . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') . '</span>';
}

/**
 * Print a success/info message.
 */
function ok(string $msg): void {
    echo '<span class="success-text">' . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') . '</span>';
}

// ─── Empty command ────────────────────────────────────────────────────────────
if ($command === '') {
    err('No command entered. Type "help" for available commands.');
    exit();
}

// ─── su ──────────────────────────────────────────────────────────────────────
if ($command === 'su') {
    if (empty($arg1)) {
        err('su: name not provided');
        exit();
    }
    $name = preg_replace('/[^a-zA-Z0-9_\-]/', '', mb_substr($arg1, 0, 32));
    $_SESSION['name'] = $name;
    header('Location: ' . CONSOLE_URL);
    exit();
}

// ─── whoami ───────────────────────────────────────────────────────────────────
if ($command === 'whoami') {
    $name = !empty($_SESSION['name']) ? $_SESSION['name'] : ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── color ────────────────────────────────────────────────────────────────────
if ($command === 'color') {
    $allowed = ['a', 'b', 'c', 'd', 'x', 'p'];
    $theme = strtolower($arg1);
    if ($theme === '' || $theme === 'reset') {
        $_SESSION['style'] = '';
    } elseif (in_array($theme, $allowed, true)) {
        $_SESSION['style'] = strtoupper($theme);
    } else {
        err('color: unknown theme. Available: a b c d x p (or empty to reset)');
        exit();
    }
    header('Location: ' . CONSOLE_URL);
    exit();
}

// ─── exit ─────────────────────────────────────────────────────────────────────
if ($command === 'exit') {
    header('Location: ' . SITE_URL);
    exit();
}

// ─── clear / cls ─────────────────────────────────────────────────────────────
if ($command === 'clear' || $command === 'cls') {
    // Handled client-side; this is a fallback
    exit();
}

// ─── date ─────────────────────────────────────────────────────────────────────
if ($command === 'date') {
    echo htmlspecialchars(date('Y-m-d H:i:s T'), ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── uptime ───────────────────────────────────────────────────────────────────
if ($command === 'uptime') {
    exec('uptime -p 2>/dev/null', $out);
    echo !empty($out) ? htmlspecialchars($out[0], ENT_QUOTES, 'UTF-8') : 'uptime: not available';
    exit();
}

// ─── myip ─────────────────────────────────────────────────────────────────────
if ($command === 'myip') {
    echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'unknown', ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── passgen ─────────────────────────────────────────────────────────────────
if ($command === 'passgen') {
    $len = max(8, min(128, (int)($arg1 ?: 22)));
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-=+[]{}';
    $max   = strlen($chars) - 1;
    $pass  = '';
    for ($i = 0; $i < $len; $i++) {
        $pass .= $chars[random_int(0, $max)];
    }
    echo htmlspecialchars($pass, ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── base64 ───────────────────────────────────────────────────────────────────
if ($command === 'base64') {
    if (empty($arg1)) {
        err('base64: usage: base64 encode|decode <text>');
        exit();
    }
    // Rebuild text from remaining tokens
    $text = implode(' ', array_slice($tokens, 2));
    if (empty($text)) {
        err('base64: no text provided');
        exit();
    }
    if ($arg1 === 'encode') {
        echo htmlspecialchars(base64_encode($text), ENT_QUOTES, 'UTF-8');
    } elseif ($arg1 === 'decode') {
        $decoded = base64_decode($text, true);
        if ($decoded === false) {
            err('base64: invalid base64 string');
        } else {
            echo htmlspecialchars($decoded, ENT_QUOTES, 'UTF-8');
        }
    } else {
        err('base64: usage: base64 encode|decode <text>');
    }
    exit();
}

// ─── hash ─────────────────────────────────────────────────────────────────────
if ($command === 'hash') {
    $allowed_algos = ['md5', 'sha1', 'sha256', 'sha512'];
    if (empty($arg1) || empty($arg2)) {
        err('hash: usage: hash <algo> <text>  (algos: md5 sha1 sha256 sha512)');
        exit();
    }
    if (!in_array($arg1, $allowed_algos, true)) {
        err('hash: unsupported algorithm. Choose: ' . implode(', ', $allowed_algos));
        exit();
    }
    $text = implode(' ', array_slice($tokens, 2));
    echo '<b>' . htmlspecialchars($arg1, ENT_QUOTES, 'UTF-8') . ':</b> ' . htmlspecialchars(hash($arg1, $text), ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── urlencode / urldecode ────────────────────────────────────────────────────
if ($command === 'urlencode') {
    $text = implode(' ', array_slice($tokens, 1));
    if (empty($text)) { err('urlencode: no text provided'); exit(); }
    echo htmlspecialchars(urlencode($text), ENT_QUOTES, 'UTF-8');
    exit();
}
if ($command === 'urldecode') {
    $text = implode(' ', array_slice($tokens, 1));
    if (empty($text)) { err('urldecode: no text provided'); exit(); }
    echo htmlspecialchars(urldecode($text), ENT_QUOTES, 'UTF-8');
    exit();
}

// ─── Network commands (require valid, non-blocked host) ───────────────────────
$net_cmds = ['ping', 'tracert', 'nslookup', 'ptr', 'whois', 'dig', 'nmap', 'curl', 'httping', 'ssl', 'port', 'rdap', 'geoip', 'headers', 'dnsbl', 'dnssec', 'redirect', 'tech'];
if (in_array($command, $net_cmds, true)) {
    if (empty($arg1)) {
        err("$command: no host provided");
        exit();
    }

    $host = sanitizeHost($arg1);

    if (isBlocked($host)) {
        err("$command: host not allowed");
        exit();
    }

    if (!validateHost($host)) {
        err("$command: cannot resolve '$host'");
        exit();
    }

    // ── ping ──────────────────────────────────────────────────────────────────
    if ($command === 'ping') {
        exec('ping -c 4 -W 3 ' . escapeshellarg($host) . ' 2>&1', $out);
        foreach ($out as $line) {
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── tracert ───────────────────────────────────────────────────────────────
    if ($command === 'tracert') {
        exec('traceroute -m 20 -w 3 ' . escapeshellarg($host) . ' 2>&1', $out);
        foreach ($out as $line) {
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── nslookup ──────────────────────────────────────────────────────────────
    if ($command === 'nslookup') {
        exec('nslookup -type=any ' . escapeshellarg($host) . ' 2>&1 | tail -n +4', $out);
        foreach ($out as $line) {
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── ptr ───────────────────────────────────────────────────────────────────
    if ($command === 'ptr') {
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            err('ptr: requires a valid IP address');
            exit();
        }
        exec('dig -x ' . escapeshellarg($host) . ' +short 2>&1', $out);
        if (empty($out)) {
            echo 'No PTR record found.';
        } else {
            foreach ($out as $line) {
                echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
            }
        }
        exit();
    }

    // ── whois ─────────────────────────────────────────────────────────────────
    if ($command === 'whois') {
        exec('whois -H ' . escapeshellarg($host) . ' 2>&1', $out);

        // Check if whois returned anything useful
        // Ignore error messages like "getaddrinfo(...): Name or service not known"
        $error_patterns = ['name or service not known', 'connection refused',
                           'no route to host', 'connection timed out',
                           'getaddrinfo', 'connect:', 'fgets: '];
        $has_data = false;
        foreach ($out as $line) {
            $lower = strtolower(trim($line));
            if (!str_contains($line, ':')) continue;
            $is_error = false;
            foreach ($error_patterns as $ep) {
                if (str_contains($lower, $ep)) { $is_error = true; break; }
            }
            if (!$is_error) { $has_data = true; break; }
        }

        if ($has_data) {
            foreach ($out as $line) {
                $trimmed = trim($line);
                if ($trimmed === '') continue;
                echo htmlspecialchars($trimmed, ENT_QUOTES, 'UTF-8') . '<br>';
            }
            exit();
        }

        // No whois data — fallback to RDAP (used by .dev .app .page .zip etc.)
        // Try Google RDAP directly first, then rdap.org as fallback
        $tld = ltrim(strrchr($host, '.'), '.');
        $rdap_servers = [
            'https://rdap.nic.google/domain/' . urlencode($host),  // Google TLDs: dev app page zip etc.
            'https://rdap.verisign.com/com/v1/domain/' . urlencode($host),  // .com .net
            'https://rdap.publicinterestregistry.org/rdap/domain/' . urlencode($host), // .org
            'https://rdap.org/domain/' . urlencode($host),          // universal fallback
        ];
        $json = null;
        $ctx  = stream_context_create(['http' => ['timeout' => 8, 'ignore_errors' => true]]);
        foreach ($rdap_servers as $rdap_url) {
            $json = @file_get_contents($rdap_url, false, $ctx);
            if ($json && str_contains($json, 'ldhName')) break;
            $json = null;
        }
        if ($json) {
            $data = json_decode($json, true);
            if (!empty($data)) {
                echo '<i style="color:var(--muted,#888)">whois unavailable, using RDAP</i><br><br>';

                if (!empty($data['ldhName']))
                    echo '<b>Domain Name:</b> ' . htmlspecialchars(strtoupper($data['ldhName']), ENT_QUOTES, 'UTF-8') . '<br>';

                if (!empty($data['status']))
                    foreach ((array)$data['status'] as $s)
                        echo '<b>Domain Status:</b> ' . htmlspecialchars($s, ENT_QUOTES, 'UTF-8') . '<br>';

                if (!empty($data['events']))
                    foreach ($data['events'] as $ev) {
                        $action = $ev['eventAction'] ?? '';
                        if ($action === 'registration')     $label = 'Creation Date';
                        elseif ($action === 'expiration')   $label = 'Registry Expiry Date';
                        elseif ($action === 'last changed') $label = 'Updated Date';
                        else                                $label = null;
                        if ($label)
                            echo '<b>' . $label . ':</b> ' . htmlspecialchars($ev['eventDate'] ?? '', ENT_QUOTES, 'UTF-8') . '<br>';
                    }

                if (!empty($data['nameservers']))
                    foreach ($data['nameservers'] as $ns)
                        echo '<b>Name Server:</b> ' . htmlspecialchars(strtoupper($ns['ldhName'] ?? ''), ENT_QUOTES, 'UTF-8') . '<br>';

                if (!empty($data['entities']))
                    foreach ($data['entities'] as $entity)
                        if (in_array('registrar', $entity['roles'] ?? []))
                            foreach ($entity['vcardArray'][1] ?? [] as $field)
                                if (($field[0] ?? '') === 'fn')
                                    echo '<b>Registrar:</b> ' . htmlspecialchars($field[3] ?? '', ENT_QUOTES, 'UTF-8') . '<br>';

                exit();
            }
        }

        err('whois: no data returned for ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8'));
        exit();
    }

    // ── dig ───────────────────────────────────────────────────────────────────
if ($command === 'dig') {
    $type = strtoupper(preg_replace('/[^a-zA-Z]/', '', $arg2) ?: 'A');
    $allowed_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'ANY'];
    if (!in_array($type, $allowed_types, true)) {
        $type = 'A';
    }

    exec('dig ' . escapeshellarg($host) . ' ' . escapeshellarg($type) . ' +noall +answer 2>&1', $out);

    if (empty($out)) {
        echo 'No results.<br>';
    } else {
        foreach ($out as $line) {
            if (trim($line) === '') continue;
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
    }
    exit();
}

    // ── nmap ──────────────────────────────────────────────────────────────────
    if ($command === 'nmap') {
        exec('nmap -F --open ' . escapeshellarg($host) . ' 2>&1', $out);
        foreach ($out as $line) {
            if (stripos($line, 'Nmap scan report') !== false) continue;
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── curl ──────────────────────────────────────────────────────────────────
    if ($command === 'curl') {
        // Allow http(s):// prefix; prepend https if missing
        if (!preg_match('#^https?://#i', $host)) {
            $url = 'https://' . $host;
        } else {
            $url = $host;
        }
        $url = filter_var($url, FILTER_SANITIZE_URL);
        exec('curl -Is --max-time 10 --max-redirs 5 ' . escapeshellarg($url) . ' 2>&1 | head -40', $out);
        foreach ($out as $line) {
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── httping ───────────────────────────────────────────────────────────────
    if ($command === 'httping') {
        exec('httping -c 4 -g ' . escapeshellarg('https://' . $host) . ' 2>&1', $out);
        foreach ($out as $line) {
            echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── ssl ───────────────────────────────────────────────────────────────────
    if ($command === 'ssl') {
        $cmd = 'echo | openssl s_client -servername ' . escapeshellarg($host)
             . ' -connect ' . escapeshellarg($host . ':443')
             . ' 2>/dev/null | openssl x509 -noout -issuer -subject -dates -fingerprint 2>&1';
        exec($cmd, $out);
        if (empty($out)) {
            err('ssl: could not retrieve certificate (port 443 may be closed or invalid domain)');
        } else {
            foreach ($out as $line) {
                echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . '<br>';
            }
        }
        exit();
    }

    // ── port ──────────────────────────────────────────────────────────────────
    if ($command === 'port') {
        $port = (int)preg_replace('/[^0-9]/', '', $arg2);
        if ($port < 1 || $port > 65535) {
            err('port: invalid port number (1–65535)');
            exit();
        }
        $errno  = 0;
        $errstr = '';
        $conn   = @fsockopen($host, $port, $errno, $errstr, 5);
        if ($conn) {
            fclose($conn);
            ok("port $port on $host is OPEN");
        } else {
            err("port $port on $host is CLOSED ($errstr)");
        }
        exit();
    }
}



// ── rdap ──────────────────────────────────────────────────────────────────
 // ── rdap ──────────────────────────────────────────────────────────────────
    if ($command === 'rdap') {
        $rdap_map = [
            'com'          => 'https://rdap.verisign.com/com/v1/domain/',
            'net'          => 'https://rdap.verisign.com/net/v1/domain/',
            'org'          => 'https://rdap.publicinterestregistry.org/rdap/domain/',
            'dev'          => 'https://rdap.nic.google/domain/',
            'app'          => 'https://rdap.nic.google/domain/',
            'page'         => 'https://rdap.nic.google/domain/',
            'ru'           => 'https://rdap.nic.ru/domain/',
            'su'           => 'https://rdap.nic.ru/domain/',
            'ua'           => 'https://rdap.hostmaster.ua/domain/',
            'io'           => 'https://rdap.nic.io/domain/',
            'co'           => 'https://rdap.nic.co/domain/',
            'uk'           => 'https://rdap.nominet.uk/domain/',
            'de'           => 'https://rdap.denic.de/domain/',
        ];

        $tld = strtolower(ltrim(strrchr($host, '.'), '.'));
        $base_url = $rdap_map[$tld] ?? 'https://rdap.org/domain/';
        $urls = array_unique([$base_url . urlencode($host), 'https://rdap.org/domain/' . urlencode($host)]);

        $json = null;
        foreach ($urls as $rdap_url) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $rdap_url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_HTTPHEADER     => [
                    'Accept: application/rdap+json, application/json',
                    'User-Agent: console/2.0',
                ],
            ]);
            $result = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($result && $http_code === 200 && str_contains($result, 'ldhName')) {
                $json = $result;
                break;
            }
        }

        if (!$json || !($data = json_decode($json, true))) {
            err('rdap: no data returned for ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8'));
            exit();
        }

        $labels = [
            'registration'                  => 'Creation Date',
            'expiration'                    => 'Registry Expiry Date',
            'last changed'                  => 'Updated Date',
            'last update of RDAP database'  => 'Last Update',
        ];

        if (!empty($data['ldhName']))
            echo '<b>Domain Name:</b> ' . htmlspecialchars(strtoupper($data['ldhName']), ENT_QUOTES, 'UTF-8') . '<br>';

        if (!empty($data['status']))
            foreach ((array)$data['status'] as $s)
                echo '<b>Status:</b> ' . htmlspecialchars($s, ENT_QUOTES, 'UTF-8') . '<br>';

        if (!empty($data['events']))
            foreach ($data['events'] as $ev) {
                $label = $labels[$ev['eventAction'] ?? ''] ?? null;
                if ($label)
                    echo '<b>' . $label . ':</b> ' . htmlspecialchars($ev['eventDate'] ?? '', ENT_QUOTES, 'UTF-8') . '<br>';
            }

        if (!empty($data['nameservers']))
            foreach ($data['nameservers'] as $ns)
                echo '<b>Name Server:</b> ' . htmlspecialchars(strtoupper($ns['ldhName'] ?? ''), ENT_QUOTES, 'UTF-8') . '<br>';

        if (!empty($data['entities']))
            foreach ($data['entities'] as $entity) {
                $roles = $entity['roles'] ?? [];
                $fn = '';
                foreach ($entity['vcardArray'][1] ?? [] as $field)
                    if (($field[0] ?? '') === 'fn') $fn = $field[3] ?? '';
                if (in_array('registrar', $roles) && $fn)
                    echo '<b>Registrar:</b> ' . htmlspecialchars($fn, ENT_QUOTES, 'UTF-8') . '<br>';
                if (in_array('registrant', $roles) && $fn)
                    echo '<b>Registrant:</b> ' . htmlspecialchars($fn, ENT_QUOTES, 'UTF-8') . '<br>';
            }

        if (!empty($data['links']))
            foreach ($data['links'] as $link)
                if (($link['rel'] ?? '') === 'self')
                    echo '<b>RDAP Source:</b> ' . htmlspecialchars($link['href'] ?? '', ENT_QUOTES, 'UTF-8') . '<br>';

        exit();
    }

    // ── geoip ─────────────────────────────────────────────────────────────────
    if ($command === 'geoip') {
        // Resolve to IP if hostname given
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            err('geoip: cannot resolve host to IP');
            exit();
        }

        $ctx  = stream_context_create(['http' => ['timeout' => 8, 'ignore_errors' => true]]);
        $json = @file_get_contents('http://ip-api.com/json/' . urlencode($ip) . '?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query', false, $ctx);

        if (!$json || !($data = json_decode($json, true)) || ($data['status'] ?? '') !== 'success') {
            err('geoip: failed to get data for ' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8'));
            exit();
        }

        if ($host !== $ip)
            echo '<b>Hostname:</b> ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8') . '<br>';

        $fields = [
            'query'       => 'IP',
            'country'     => 'Country',
            'countryCode' => 'Country Code',
            'regionName'  => 'Region',
            'city'        => 'City',
            'zip'         => 'ZIP',
            'lat'         => 'Latitude',
            'lon'         => 'Longitude',
            'timezone'    => 'Timezone',
            'isp'         => 'ISP',
            'org'         => 'Organization',
            'as'          => 'AS',
        ];

        foreach ($fields as $key => $label) {
            if (!empty($data[$key]))
                echo '<b>' . $label . ':</b> ' . htmlspecialchars((string)$data[$key], ENT_QUOTES, 'UTF-8') . '<br>';
        }
        exit();
    }

    // ── headers ───────────────────────────────────────────────────────────────
    if ($command === 'headers') {
        if (!preg_match('#^https?://#i', $host)) {
            $url = 'https://' . $host;
        } else {
            $url = $host;
        }
        $url = filter_var($url, FILTER_SANITIZE_URL);

        $ctx = stream_context_create([
            'http' => [
                'timeout'         => 10,
                'follow_location' => false,
                'ignore_errors'   => true,
                'method'          => 'HEAD',
                'user_agent'      => 'Mozilla/5.0 (compatible; console/2.0)',
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false,
            ],
        ]);

        $headers = @get_headers($url, true, $ctx);

        if (!$headers) {
            // Fallback: try HTTP
            $url_http = str_replace('https://', 'http://', $url);
            $headers  = @get_headers($url_http, true, $ctx);
        }

        if (!$headers) {
            err('headers: could not connect to ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8'));
            exit();
        }

        foreach ($headers as $key => $value) {
            if (is_int($key)) {
                // Status line (e.g. HTTP/1.1 200 OK)
                echo '<b>' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</b><br>';
            } else {
                $val = is_array($value) ? implode(', ', $value) : $value;
                echo '<b>' . htmlspecialchars($key, ENT_QUOTES, 'UTF-8') . ':</b> '
                   . htmlspecialchars($val, ENT_QUOTES, 'UTF-8') . '<br>';
            }
        }
        exit();
    }
// ── dnsbl ─────────────────────────────────────────────────────────────────
if ($command === 'dnsbl') {
    if (!filter_var($host, FILTER_VALIDATE_IP)) {
        err('dnsbl: requires a valid IPv4 address');
        exit();
    }

    $lists = [
        'zen.spamhaus.org'        => 'Spamhaus ZEN',
        'bl.spamcop.net'          => 'SpamCop',
        'dnsbl.sorbs.net'         => 'SORBS',
        'b.barracudacentral.org'  => 'Barracuda',
        'dnsbl-1.uceprotect.net'  => 'UCEPROTECT L1',
        'psbl.surriel.com'        => 'PSBL',
        'ix.dnsbl.manitu.net'     => 'Manitu',
        'dnsbl.dronebl.org'       => 'DroneBL',
        'all.s5h.net'             => 's5h',
        'spam.dnsbl.anonmails.de' => 'ANONMAILS',
        'spam.abuse.ch'                 => 'Abuse.ch',
        'dnsbl.zapbl.net'               => 'ZapBL',
        'psbl.surriel.com'              => 'PSBL',
        'spam.rats.dnsbl.net.au'        => 'RATS-Spam',
        'dyna.rats.dnsbl.net.au'        => 'RATS-Dyna',
        'noptr.rats.dnsbl.net.au'       => 'RATS-NoPtr',
    ];

    $reversed = implode('.', array_reverse(explode('.', $host)));

    $listed = 0;
    $clean  = 0;
    $errors = 0;

    echo '<b>DNSBL check for ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8') . '</b><br><br>';

    foreach ($lists as $bl => $name) {
        $lookup = $reversed . '.' . $bl;

        // dns_get_record с DNS_A: [] = не в списке, [...] = в списке, false = ошибка
        $result = @dns_get_record($lookup, DNS_A);

        if ($result === false) {
            echo '<span style="color:var(--muted,#888)">  [ERROR ] ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</span><br>';
            $errors++;
            continue;
        }

        // Фильтруем только валидные 127.x.x.x ответы — именно такие возвращают DNSBL
        // Любой другой IP (104.x, 172.x и т.д.) — это мусор от CDN/резолвера
        $hits = array_filter($result, function($r) {
            if (!isset($r['ip']) || strpos($r['ip'], '127.') !== 0) return false;
            // Исключаем служебные ответы Spamhaus
            if (in_array($r['ip'], ['127.255.255.254', '127.255.255.255'])) return false;
            return true;
        });

        if (!empty($hits)) {
            $code = reset($hits)['ip'];
            echo '<span style="color:#e05252">  [LISTED] ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8')
               . ' (' . htmlspecialchars($code, ENT_QUOTES, 'UTF-8') . ')</span><br>';
            $listed++;
        } else {
            echo '<span style="color:#52e052">  [CLEAN ] ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</span><br>';
            $clean++;
        }
    }

    echo '<br><b>Result:</b> '
       . ($listed > 0
           ? '<span style="color:#e05252">Listed on ' . $listed . ' / ' . count($lists) . ' blacklists</span>'
           : '<span style="color:#52e052">Clean on all checked blacklists</span>')
       . ($errors ? ' <span style="color:var(--muted,#888)">(' . $errors . ' errors)</span>' : '')
       . '<br>';
    exit();
}

    // ── dnssec ────────────────────────────────────────────────────────────────
    if ($command === 'dnssec') {
        echo '<b>DNSSEC check for ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8') . '</b><br><br>';

        // Check DNSKEY record
        exec('dig DNSKEY ' . escapeshellarg($host) . ' +short 2>&1', $dnskey);
        // Check DS record
        exec('dig DS ' . escapeshellarg($host) . ' +short 2>&1', $ds);
        // Check RRSIG on A record
        exec('dig A ' . escapeshellarg($host) . ' +dnssec +short 2>&1', $rrsig_out);

        $has_dnskey = !empty(array_filter($dnskey));
        $has_ds     = !empty(array_filter($ds));
        $has_rrsig  = false;
        foreach ($rrsig_out as $line) {
            if (stripos($line, 'RRSIG') !== false) { $has_rrsig = true; break; }
        }

        // DNSKEY
        if ($has_dnskey) {
            echo '<span style="color:#52e052">  [✓] DNSKEY found</span><br>';
            foreach (array_filter($dnskey) as $line) {
                $parts = explode(' ', trim($line), 4);
                $flags = $parts[0] ?? '';
                $algo  = $parts[2] ?? '';
                $algo_names = [
                    '5'=>'RSASHA1','7'=>'RSASHA1-NSEC3','8'=>'RSASHA256',
                    '10'=>'RSASHA512','13'=>'ECDSAP256SHA256','14'=>'ECDSAP384SHA384','15'=>'ED25519',
                ];
                $algo_name = $algo_names[$algo] ?? "algo $algo";
                $type_label = ($flags == '257') ? 'KSK (Key Signing Key)' : 'ZSK (Zone Signing Key)';
                echo '       flags=' . htmlspecialchars($flags, ENT_QUOTES, 'UTF-8')
                   . ' algo=' . htmlspecialchars($algo_name, ENT_QUOTES, 'UTF-8')
                   . ' (' . $type_label . ')<br>';
            }
        } else {
            echo '<span style="color:#e05252">  [✗] No DNSKEY record</span><br>';
        }

        // DS
        if ($has_ds) {
            echo '<span style="color:#52e052">  [✓] DS record found (delegation signed)</span><br>';
            foreach (array_filter($ds) as $line) {
                echo '       ' . htmlspecialchars(trim($line), ENT_QUOTES, 'UTF-8') . '<br>';
            }
        } else {
            echo '<span style="color:#e05252">  [✗] No DS record (chain of trust broken or unsigned)</span><br>';
        }

        // RRSIG
        if ($has_rrsig) {
            echo '<span style="color:#52e052">  [✓] RRSIG present (records are signed)</span><br>';
        } else {
            echo '<span style="color:#e05252">  [✗] No RRSIG on A record</span><br>';
        }

        // Verdict
        echo '<br>';
        if ($has_dnskey && $has_ds && $has_rrsig) {
            echo '<span style="color:#52e052"><b>✓ DNSSEC is enabled and chain of trust is intact</b></span><br>';
        } elseif ($has_dnskey || $has_rrsig) {
            echo '<span style="color:#e8a020"><b>⚠ DNSSEC partially configured (chain may be incomplete)</b></span><br>';
        } else {
            echo '<span style="color:#e05252"><b>✗ DNSSEC is not enabled</b></span><br>';
        }
        exit();
    }

    // ── redirect ──────────────────────────────────────────────────────────────
    if ($command === 'redirect') {
        if (!preg_match('#^https?://#i', $host)) {
            $start_url = 'https://' . $host;
        } else {
            $start_url = $host;
        }
        $start_url = filter_var($start_url, FILTER_SANITIZE_URL);

        $current_url = $start_url;
        $step        = 0;
        $max_steps   = 10;
        $seen        = [];

        echo '<b>Redirect chain for ' . htmlspecialchars($start_url, ENT_QUOTES, 'UTF-8') . '</b><br><br>';

        while ($step < $max_steps) {
            if (in_array($current_url, $seen, true)) {
                echo '<span style="color:#e05252">  [∞] Redirect loop detected!</span><br>';
                break;
            }
            $seen[] = $current_url;

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $current_url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; console/2.0)',
            ]);
            $response  = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $total_time = round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
            curl_close($ch);

            if (!$response) {
                echo '<span style="color:#e05252">  [ERR] Could not connect to '
                   . htmlspecialchars($current_url, ENT_QUOTES, 'UTF-8') . '</span><br>';
                break;
            }

            // Color by status code
            if ($http_code >= 200 && $http_code < 300) {
                $color = '#52e052';
            } elseif ($http_code >= 300 && $http_code < 400) {
                $color = '#e8a020';
            } else {
                $color = '#e05252';
            }

            echo '<span style="color:' . $color . '">'
               . '  [' . $http_code . '] </span>'
               . htmlspecialchars($current_url, ENT_QUOTES, 'UTF-8')
               . ' <span style="color:var(--muted,#888)">(' . $total_time . 'ms)</span><br>';

            // Not a redirect — we're done
            if ($http_code < 300 || $http_code >= 400) break;

            // Extract Location header
            $location = '';
            foreach (explode("\n", $response) as $hline) {
                if (stripos($hline, 'Location:') === 0) {
                    $location = trim(substr($hline, 9));
                    break;
                }
            }

            if (empty($location)) {
                echo '<span style="color:#e05252">  [ERR] Redirect with no Location header</span><br>';
                break;
            }

            // Handle relative redirects
            if (!preg_match('#^https?://#i', $location)) {
                $parsed = parse_url($current_url);
                $location = ($parsed['scheme'] ?? 'https') . '://' . ($parsed['host'] ?? '')
                          . '/' . ltrim($location, '/');
            }

            echo '       <span style="color:var(--muted,#888)">↳ ' . htmlspecialchars($location, ENT_QUOTES, 'UTF-8') . '</span><br>';
            $current_url = $location;
            $step++;
        }

        if ($step >= $max_steps) {
            echo '<span style="color:#e05252">  [ERR] Too many redirects (>' . $max_steps . ')</span><br>';
        }

        echo '<br><b>Total hops:</b> ' . $step . '<br>';
        exit();
    }

    // ── tech ──────────────────────────────────────────────────────────────────
    if ($command === 'tech') {
        if (!preg_match('#^https?://#i', $host)) {
            $url = 'https://' . $host;
        } else {
            $url = $host;
        }
        $url = filter_var($url, FILTER_SANITIZE_URL);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; console/2.0)',
        ]);
        $response  = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        if (!$response) {
            err('tech: could not connect to ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8'));
            exit();
        }

        $raw_headers = substr($response, 0, $header_size);
        $body        = substr($response, $header_size);

        // Parse headers into associative array
        $headers = [];
        foreach (explode("\n", $raw_headers) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = explode(':', $line, 2);
                $headers[strtolower(trim($k))] = trim($v);
            }
        }

        $tech = [];

        // ── Server / stack from headers ──
        if (!empty($headers['server']))
            $tech['Server'] = $headers['server'];

        if (!empty($headers['x-powered-by']))
            $tech['Powered By'] = $headers['x-powered-by'];

        if (!empty($headers['x-generator']))
            $tech['Generator'] = $headers['x-generator'];

        if (!empty($headers['x-drupal-cache']) || !empty($headers['x-drupal-dynamic-cache']))
            $tech['CMS'] = 'Drupal';

        if (!empty($headers['x-shopify-stage']) || str_contains($headers['server'] ?? '', 'Shopify'))
            $tech['Platform'] = 'Shopify';

        if (!empty($headers['x-wix-request-id']))
            $tech['Platform'] = 'Wix';

        if (!empty($headers['x-vercel-id']))
            $tech['Hosting'] = 'Vercel';

        if (!empty($headers['x-netlify']))
            $tech['Hosting'] = 'Netlify';

        if (str_contains($headers['server'] ?? '', 'cloudflare') || !empty($headers['cf-ray']))
            $tech['CDN'] = 'Cloudflare';

        if (!empty($headers['x-amz-request-id']) || str_contains($headers['server'] ?? '', 'AmazonS3'))
            $tech['Hosting'] = 'Amazon S3';

        if (!empty($headers['x-cache']) && str_contains($headers['x-cache'], 'cloudfront'))
            $tech['CDN'] = 'CloudFront';

        // ── Body fingerprints ──
        $body_lower = strtolower(substr($body, 0, 50000));

        if (str_contains($body_lower, 'wp-content') || str_contains($body_lower, 'wp-includes'))
            $tech['CMS'] = 'WordPress';

        if (str_contains($body_lower, 'joomla'))
            $tech['CMS'] = 'Joomla';

        if (str_contains($body_lower, 'content="typo3'))
            $tech['CMS'] = 'TYPO3';

        if (preg_match('/content=["\']bitrix/i', $body))
            $tech['CMS'] = '1C-Bitrix';

        if (str_contains($body_lower, '/bitrix/'))
            $tech['CMS'] = isset($tech['CMS']) ? $tech['CMS'] : '1C-Bitrix';

        if (str_contains($body_lower, 'data-reactroot') || str_contains($body_lower, 'react-dom'))
            $tech['JS Framework'] = 'React';

        if (str_contains($body_lower, '__nuxt') || str_contains($body_lower, 'data-n-head'))
            $tech['JS Framework'] = 'Nuxt.js (Vue)';

        if (str_contains($body_lower, '__next') || str_contains($body_lower, '_next/static'))
            $tech['JS Framework'] = 'Next.js (React)';

        if (str_contains($body_lower, 'ng-version') || str_contains($body_lower, 'ng-app'))
            $tech['JS Framework'] = 'Angular';

        if (preg_match('/jquery[\/\-]([\d.]+)/i', $body, $m))
            $tech['JS Library'] = 'jQuery ' . $m[1];

        if (str_contains($body_lower, 'bootstrap.min.css') || str_contains($body_lower, 'bootstrap.css'))
            $tech['CSS Framework'] = 'Bootstrap';

        if (str_contains($body_lower, 'tailwind'))
            $tech['CSS Framework'] = 'Tailwind CSS';

        // ── Meta generator ──
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']/i', $body, $m))
            $tech['Meta Generator'] = $m[1];
        elseif (preg_match('/<meta[^>]+content=["\'](.*?)["\']\s+name=["\']generator["\']/i', $body, $m))
            $tech['Meta Generator'] = $m[1];

        // ── Cookie fingerprints ──
        $cookies = $headers['set-cookie'] ?? '';
        if (str_contains($cookies, 'PHPSESSID'))    $tech['Language'] = 'PHP';
        if (str_contains($cookies, 'JSESSIONID'))   $tech['Language'] = 'Java';
        if (str_contains($cookies, 'ASP.NET_SessionId') || str_contains($headers['x-aspnet-version'] ?? '', '.'))
            $tech['Language'] = 'ASP.NET';
        if (!empty($headers['x-aspnet-version']))
            $tech['ASP.NET Version'] = $headers['x-aspnet-version'];

        // ── Output ──
        echo '<b>Tech stack for ' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8') . '</b> '
           . '<span style="color:var(--muted,#888)">[HTTP ' . $http_code . ']</span><br><br>';

        if (empty($tech)) {
            echo '<span style="color:var(--muted,#888)">No technologies detected</span><br>';
        } else {
            $max_len = max(array_map('strlen', array_keys($tech)));
            foreach ($tech as $label => $value) {
                $pad = str_repeat(' ', $max_len - strlen($label) + 2);
                echo '<b>' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . ':</b>'
                   . $pad . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '<br>';
            }
        }
        exit();
    }
// ─── list ─────────────────────────────────────────────────────────────────────
if ($command === 'list') {
    $sources = [
        'proxy'  => 'https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt',
        'http'   => 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
        'socks5' => 'https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks5.txt',
        'socks4' => 'https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks4.txt',
    ];
    $type = strtolower($arg1);
    if (empty($type) || !array_key_exists($type, $sources)) {
        err('list: usage: list proxy|http|socks4|socks5');
        exit();
    }
    $ctx  = stream_context_create(['http' => ['timeout' => 10]]);
    $data = @file_get_contents($sources[$type], false, $ctx);
    if ($data === false) {
        err('list: failed to fetch list');
    } else {
        echo '<pre>' . htmlspecialchars($data, ENT_QUOTES, 'UTF-8') . '</pre>';
    }
    exit();
}

// ─── info ─────────────────────────────────────────────────────────────────────
if ($command === 'info') {
    echo 'Version: ' . VERSION . '<br>';
    echo 'Hello, this is the console from <a href="' . SITE_URL . '" target="_blank">nkotov.net</a>!<br>';
    echo 'Questions / suggestions → Telegram: <a href="https://t.me/rorry_47" target="_blank">@rorry_47</a><br>';
    echo '<a href="https://github.com/rorry47/console" target="_blank">GitHub</a><br>';
    exit();
}

// ─── help ─────────────────────────────────────────────────────────────────────
if ($command === 'help') {
    $cmds = [
        'Network tools' => [
            'whois [host]'                    => 'WHOIS lookup for domain or IP',
            'rdap [host]'                     => 'RDAP lookup for domain (modern whois)',
            'geoip [host|ip]'                 => 'GeoIP info: country, city, ISP, ASN',
            'headers [host]'                  => 'Show HTTP response headers',
            'dnsbl [ip]'                      => 'Check IP against spam blacklists',
            'dnssec [domain]'                 => 'Check DNSSEC signature and chain of trust',
            'redirect [url]'                  => 'Show full redirect chain with status codes',
            'tech [domain]'                   => 'Detect CMS, framework, server, CDN',
            'ping [host]'                     => 'Ping a host (4 packets)',
            'httping [host]'                  => 'HTTP ping a host',
            'dig [host] [type]'               => 'DNS lookup (type: A MX NS TXT etc.)',
            'nslookup [host]'                 => 'DNS lookup via nslookup',
            'curl [host]'                     => 'Fetch HTTP response headers',
            'nmap [host]'                     => 'Fast port scan (top ports)',
            'ssl [host]'                      => 'TLS certificate info',
            'tracert [host]'                  => 'Traceroute to host',
            'ptr [ip]'                        => 'Reverse DNS (PTR record)',
            'port [host] [port]'              => 'Check if a port is open',
        ],
        'Encoding / Crypto' => [
            'passgen [length]'                => 'Generate a random password',
            'hash <algo> <text>'              => 'Hash text (md5 sha1 sha256 sha512)',
            'base64 encode|decode <text>'     => 'Encode or decode base64',
            'urlencode <text>'                => 'URL-encode a string',
            'urldecode <text>'                => 'URL-decode a string',
        ],
        'Proxy lists' => [
            'list proxy|http|socks4|socks5'   => 'Fetch a fresh proxy list',
        ],
        'System' => [
            'myip'                            => 'Show your IP address',
            'date'                            => 'Show current server date/time',
            'uptime'                          => 'Show server uptime',
            'whoami'                          => 'Show current console identity',
        ],
        'Console' => [
            'su [name]'                       => 'Change display name (instead of IP)',
            'color [a|b|c|d|x|p]'            => 'Switch color theme (empty to reset)',
            'clear / cls'                     => 'Clear the screen',
            'info'                            => 'About & contact',
            'exit'                            => 'Redirect to example.com',
        ],
    ];

    echo '<br><b>&gt; HELP</b><br>';
    echo str_repeat('─', 70) . '<br><br>';
    foreach ($cmds as $section => $items) {
        echo '<b>' . htmlspecialchars($section, ENT_QUOTES, 'UTF-8') . '</b><br>';
        foreach ($items as $usage => $desc) {
            $pad = str_repeat(' ', max(1, 42 - strlen($usage)));
            echo '  <b>' . htmlspecialchars($usage, ENT_QUOTES, 'UTF-8') . '</b>'
               . $pad
               . htmlspecialchars($desc, ENT_QUOTES, 'UTF-8') . '<br>';
        }
        echo '<br>';
    }
    echo str_repeat('─', 70) . '<br>';
    exit();
}

// ─── Unknown command ──────────────────────────────────────────────────────────
err("$command: command not found");
echo '<br>Type <b>help</b> for available commands.';
exit();
