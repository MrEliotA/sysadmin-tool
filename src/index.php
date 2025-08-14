<?php
header('Content-Type: application/json; charset=utf-8');

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// /health
if ($path === '/health') {
    echo json_encode(['ok' => true, 'ts' => time()]);
    exit;
}

// /
$domain = $_GET['domain'] ?? null;
if (!$domain) {
    http_response_code(400);
    echo json_encode(['error' => 'Domain parameter is required, e.g. /?domain=example.com'], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
    exit;
}

// DNS servers (قابل تغییر در آینده با ENV)
$dnsServers = [
    'Cloudflare' => '1.1.1.1',
    'Google'     => '8.8.8.8',
    'Quad9'      => '9.9.9.9',
];

$domainArg = escapeshellarg($domain);
$results = [];

foreach ($dnsServers as $name => $server) {
    $serverArg = escapeshellarg($server);
    // +short خروجی خلاصه. می‌تونی ANY یا رکوردهای خاص رو بعداً اضافه کنی.
    $cmd = "dig @$serverArg $domainArg +short";
    $output = shell_exec($cmd);
    $results[$name] = trim($output) !== '' ? preg_split('/\r\n|\r|\n/', trim($output)) : [];
}

echo json_encode([
    'domain'  => $domain,
    'results' => $results,
], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
