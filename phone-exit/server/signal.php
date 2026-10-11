<?php
// Bounded, token-protected signaling. No traffic relay or outbound connections.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function respond($code, $data) { http_response_code($code); echo json_encode($data); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') respond(405, ['error' => 'POST required']);
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 65536) respond(413, ['error' => 'Request too large']);
$raw = file_get_contents('php://input', false, null, 0, 65537);
if (strlen($raw) > 65536) respond(413, ['error' => 'Request too large']);
$input = json_decode($raw, true);
if (!is_array($input)) respond(400, ['error' => 'Invalid JSON']);
$token = $input['token'] ?? '';
if (!is_string($token) || !preg_match('/\A[0-9a-f]{64}\z/', $token)) respond(403, ['error' => 'Invalid room key']);
$role = $input['role'] ?? '';
$op = $input['op'] ?? '';
if (!in_array($role, ['pc', 'phone'], true) || !in_array($op, ['send', 'poll'], true)) respond(400, ['error' => 'Invalid operation']);
$dir = getenv('PHONE_EXIT_SIGNAL_DATA') ?: dirname(__DIR__, 2) . '/phone-exit-signal-data';
if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) respond(503, ['error' => 'Storage unavailable']);
// Expire old test rooms. Keep files outside the website directory.
$files = glob($dir . '/*.json');
foreach ($files as $old) { if (filemtime($old) < time() - 900) @unlink($old); }
$path = $dir . '/' . hash('sha256', $token) . '.json';
if (!file_exists($path) && count(glob($dir . '/*.json')) >= 512) respond(429, ['error' => 'Room limit']);
$file = @fopen($path, 'c+');
if (!$file || !flock($file, LOCK_EX)) respond(503, ['error' => 'Storage busy']);
@chmod($path, 0600);
$room = json_decode(stream_get_contents($file), true);
if (!is_array($room)) $room = ['created' => time(), 'messages' => [], 'seq' => 0];
if (time() - $room['created'] > 600) { flock($file, LOCK_UN); fclose($file); respond(410, ['error' => 'Room expired']); }
if ($op === 'send') {
    $message = $input['message'] ?? null;
    if (!is_array($message) || !in_array($message['type'] ?? '', ['offer', 'answer', 'candidate'], true)) respond(400, ['error' => 'Invalid signal']);
    if (($message['type'] === 'offer' && $role !== 'pc') || ($message['type'] === 'answer' && $role !== 'phone')) respond(400, ['error' => 'Wrong role']);
    if (count($room['messages']) >= 100) respond(429, ['error' => 'Signal limit']);
    $room['messages'][] = ['id' => ++$room['seq'], 'from' => $role, 'message' => $message];
}
$encoded = json_encode($room);
if (strlen($encoded) > 262144) respond(413, ['error' => 'Room too large']);
rewind($file); ftruncate($file, 0); fwrite($file, $encoded); fflush($file);
$after = max(0, (int)($input['after'] ?? 0));
$messages = array_values(array_filter($room['messages'], function ($item) use ($role, $after) { return $item['from'] !== $role && $item['id'] > $after; }));
flock($file, LOCK_UN); fclose($file);
respond(200, ['messages' => $messages, 'expiresIn' => max(0, 600 - (time() - $room['created']))]);
