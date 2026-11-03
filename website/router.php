<?php
declare(strict_types=1);
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/xmail' || str_starts_with($path, '/xmail/')) {
    if(in_array($path,['/xmail/xmail.css','/xmail/xmail.js'],true))return false;
    require __DIR__.'/dist/xmail/index.php';return;
}
// Only expose known public resources; everything else gets the language router.
if (preg_match('~^/(?:assets/[A-Za-z0-9_.-]+|favicon\.(?:ico|png)|apple-touch-icon\.png|styles\.css|app\.js|api/order\.php)$~D', $path)) {
    if (is_file(__DIR__ . '/dist' . $path)) return false;
}
require __DIR__ . '/dist/index.php';
