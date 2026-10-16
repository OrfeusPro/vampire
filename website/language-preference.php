<?php
declare(strict_types=1);

/** Negotiate only the entry URL. Explicit language URLs stay stable and crawlable. */
function site_preferred_language(array $enabled, string $header): ?string {
    $choices = [];
    foreach (explode(',', substr($header, 0, 2048)) as $index => $part) {
        if (!preg_match('/^\s*([a-z]{2,3}(?:-[a-z0-9]{2,8})*)\s*(?:;\s*q=(0(?:\.\d{1,3})?|1(?:\.0{1,3})?))?\s*$/iD', $part, $match)) continue;
        $quality = isset($match[2]) ? (float)$match[2] : 1.0;
        if ($quality <= 0) continue;
        $choices[] = ['tag' => strtolower($match[1]), 'quality' => $quality, 'index' => $index];
    }
    usort($choices, static fn($a, $b) => ($b['quality'] <=> $a['quality']) ?: ($a['index'] <=> $b['index']));
    $lookup = array_change_key_case(array_fill_keys($enabled, true), CASE_LOWER);
    foreach ($choices as $choice) {
        $tag = $choice['tag'];
        if ($tag === 'ua') $tag = 'uk';
        while ($tag !== '') {
            if (isset($lookup[$tag])) {
                foreach ($enabled as $code) if (strtolower($code) === $tag) return $code;
            }
            $position = strrpos($tag, '-');
            $tag = $position === false ? '' : substr($tag, 0, $position);
        }
    }
    return null;
}

function site_redirect_language_entry(array $languages): void {
    if (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) !== '/' || isset($_GET['lang'])) return;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') return;
    // Cache must never serve one visitor's negotiated redirect to another visitor.
    header('Vary: Accept-Language, Cookie, User-Agent');
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (!str_contains(strtolower($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') || !str_contains($agent, 'Mozilla/')) return;
    if (preg_match('/bot|crawl|spider|slurp|preview|facebookexternalhit|mediapartners|lighthouse|headless|googleother|inspectiontool|archive|validator|curl|wget/i', $agent)) return;
    $enabled = array_column($languages, 'code');
    $saved = $_COOKIE['vampir_language'] ?? null;
    $target = is_string($saved) && in_array($saved, $enabled, true)
        ? $saved : site_preferred_language($enabled, $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
    if ($target === null || $target === 'en') return;
    $query = $_GET ? '?' . http_build_query($_GET) : '';
    header('Cache-Control: private, no-store');
    header('Location: ' . language_path($target) . $query, true, 302);
    exit;
}
