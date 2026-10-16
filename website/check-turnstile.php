<?php
declare(strict_types=1);
require __DIR__ . '/turnstile.php';
function check(bool $condition, string $label): void {
    if (!$condition) throw new RuntimeException($label);
}
$valid = ['success' => true, 'action' => 'order', 'hostname' => 'vampir.top'];
check(site_turnstile_response_allowed($valid, ['vampir.top']), 'Valid scoped response');
foreach ([['success' => false], ['success' => 'true'], ['action' => 'login'],
    ['hostname' => 'evil.example'], ['hostname' => 'localhost'], ['hostname' => '127.0.0.1'],
    ['hostname' => 'vampir.top.evil.example']] as $change) {
    check(!site_turnstile_response_allowed(array_replace($valid, $change), ['vampir.top']), 'Reject wrong scope');
}
check(!site_turnstile_response_allowed([], ['vampir.top']), 'Reject missing response');
check(!site_turnstile_response_allowed($valid, []), 'Reject missing allowlist');
foreach ([null, [], 1, '', str_repeat('a', 2049)] as $token) {
    check(site_turnstile_verify($token) === 'turnstile_failed', 'Reject invalid input');
}
// Official Cloudflare testing keys, never used by the order handler/configuration.
foreach (['1' => true, '2' => false, '3' => false] as $prefix => $expected) {
    $response = site_turnstile_request($prefix . 'x0000000000000000000000000000000AA', 'XXXX.DUMMY.TOKEN.XXXX');
    check($response !== null && ($response['success'] ?? null) === $expected, 'Cloudflare test key response');
    if ($prefix === 3) check(in_array('timeout-or-duplicate', $response['error-codes'] ?? [], true), 'Duplicate token rejection');
}
echo "Turnstile: strict success/action/hostname, input bounds and Cloudflare pass/fail/duplicate fixtures OK\n";
