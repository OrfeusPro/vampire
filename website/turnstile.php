<?php
declare(strict_types=1);

function site_turnstile_public(): array {
    $settings = json_decode(file_get_contents(__DIR__ . '/settings.json'), true, 512, JSON_THROW_ON_ERROR);
    return $settings['turnstile'];
}

function site_turnstile_response_allowed(array $response, array $hostnames): bool {
    return ($response['success'] ?? null) === true
        && ($response['action'] ?? null) === 'order'
        && is_string($response['hostname'] ?? null)
        && in_array($response['hostname'], $hostnames, true);
}

/** No request fields, tokens or credentials are logged. TLS and timeouts are mandatory. */
function site_turnstile_request(string $secret, string $token): ?array {
    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $body = http_build_query(['secret' => $secret, 'response' => $token]);
    if (function_exists('curl_init')) {
        $handle = curl_init($url);
        curl_setopt_array($handle, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        $raw = curl_exec($handle);
        $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        if (!is_string($raw) || $status !== 200) return null;
    } else {
        $context = stream_context_create([
            'http' => ['method' => 'POST', 'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                'content' => $body, 'timeout' => 10, 'follow_location' => 0],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $raw = @file_get_contents($url, false, $context, 0, 16385);
        if (!is_string($raw) || !preg_match('~^HTTP/\S+ 200\b~', $http_response_header[0] ?? '')) return null;
    }
    if (strlen($raw) > 16384) return null;
    $response = json_decode($raw, true);
    return is_array($response) ? $response : null;
}

function site_turnstile_verify(mixed $token): string {
    if (!is_string($token) || trim($token) === '' || strlen($token) > 2048) return 'turnstile_failed';
    $path = __DIR__ . '/turnstile.local.php';
    $private = is_file($path) ? require $path : [];
    $secret = $private['secret'] ?? '';
    if (!is_string($secret) || trim($secret) === '') return 'turnstile_unavailable';
    $hostnames = site_turnstile_public()['hostnames'] ?? [];
    if (!is_array($hostnames) || !$hostnames) return 'turnstile_unavailable';
    $response = site_turnstile_request($secret, $token);
    if ($response === null) return 'turnstile_unavailable';
    return site_turnstile_response_allowed($response, $hostnames) ? '' : 'turnstile_failed';
}
