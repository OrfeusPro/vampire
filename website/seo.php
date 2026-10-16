<?php
declare(strict_types=1);

function language_path(string $code): string {
    return $code === 'en' ? '/' : '/' . ($code === 'uk' ? 'ua' : strtolower($code)) . '/';
}
function site_escape(string $text): string { return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function site_text(string $key, bool $html = false): string {
    global $i18n, $currentLanguage;
    $value = $i18n['messages'][$currentLanguage][$key] ?? $key;
    return $html ? strip_tags($value, '<br><em>') : site_escape($value);
}

require_once __DIR__ . '/i18n.php';
$i18n = site_languages();
$productionOrigin = 'https://vampir.top';
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$host = strtolower(explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]);
$isProduction = in_array($host, ['vampir.top', 'www.vampir.top'], true);
require_once __DIR__ . '/language-preference.php';
site_redirect_language_entry($i18n['languages']);

foreach ($i18n['languages'] as &$entry) $entry['path'] = language_path($entry['code']);
unset($entry);

if ($requestPath === '/robots.txt') {
    header('Content-Type: text/plain; charset=utf-8');
    echo $isProduction
        ? "User-agent: *\nDisallow: /api/\nDisallow: /locales/\nSitemap: $productionOrigin/sitemap.xml\n"
        : "User-agent: *\nDisallow: /\n";
    exit;
}
if ($requestPath === '/sitemap.xml') {
    header('Content-Type: application/xml; charset=utf-8');
    if (!$isProduction) header('X-Robots-Tag: noindex');
    echo '<?xml version="1.0" encoding="UTF-8"?>';
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
    foreach ($i18n['languages'] as $entry) {
        echo '<url><loc>' . site_escape($productionOrigin . $entry['path']) . '</loc></url>';
    }
    echo '</urlset>';
    exit;
}

$currentLanguage = null;
foreach ($i18n['languages'] as $entry) {
    $aliases = [$entry['path'], rtrim($entry['path'], '/'), '/' . strtolower($entry['code']), '/' . strtolower($entry['code']) . '/'];
    if (in_array(strtolower($requestPath), $aliases, true)) $currentLanguage = $entry['code'];
}
if ($requestPath === '/' || $requestPath === '/index.php' || in_array($requestPath, ['/en', '/en/'], true)) $currentLanguage = 'en';
// Preserve old shared query links, consolidating them into the language URL.
$legacy = $_GET['lang'] ?? null;
if (is_string($legacy)) {
    if ($legacy === 'ua') $legacy = 'uk';
    if (isset($i18n['messages'][$legacy])) $currentLanguage = $legacy;
}
if ($currentLanguage === null) {
    http_response_code(404);
    header('X-Robots-Tag: noindex');
    echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>Page not found | VAMPIR.TOP</title><h1>Page not found</h1><a href="/">VAMPIR.TOP</a></html>';
    exit;
}
$canonicalPath = language_path($currentLanguage);
if ($requestPath !== $canonicalPath || isset($_GET['lang'])) {
    $query = $_GET;
    unset($query['lang']);
    $suffix = $query ? '?' . http_build_query($query) : '';
    header('Location: ' . $canonicalPath . $suffix, true, 301);
    exit;
}
header('Content-Language: ' . $currentLanguage);
if (!$isProduction) header('X-Robots-Tag: noindex, nofollow');
$i18n['currentLanguage'] = $currentLanguage;
$canonicalUrl = $productionOrigin . $canonicalPath;
$structuredData = [
    '@context' => 'https://schema.org',
    '@graph' => [
        ['@type' => 'WebSite', '@id' => $productionOrigin . '/#website', 'url' => $productionOrigin . '/', 'name' => 'VAMPIR.TOP'],
        ['@type' => 'WebPage', '@id' => $canonicalUrl . '#webpage', 'url' => $canonicalUrl,
         'name' => $i18n['messages'][$currentLanguage]['pageTitle'], 'description' => $i18n['messages'][$currentLanguage]['metaDescription'],
         'inLanguage' => $currentLanguage, 'isPartOf' => ['@id' => $productionOrigin . '/#website']],
    ],
];
