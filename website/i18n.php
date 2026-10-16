<?php
declare(strict_types=1);
require_once __DIR__ . '/pricing.php';

function site_languages(): array {
    $publicDirectory = is_dir(__DIR__ . '/dist/locales') ? __DIR__ . '/dist' : __DIR__ . '/public_html';
    $root = $publicDirectory . '/locales/';
    $registry = json_decode(file_get_contents($root . 'languages.json'), true, 512, JSON_THROW_ON_ERROR);
    $base = json_decode(file_get_contents($root . 'en.json'), true, 512, JSON_THROW_ON_ERROR);
    $messages = [];
    $languages = [];
    foreach ($registry['languages'] as $entry) {
        if (empty($entry['enabled'])) continue;
        $code = $entry['code'];
        if (!preg_match('/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/D', $code)) throw new RuntimeException('Invalid language code');
        $translation = json_decode(file_get_contents($root . $code . '.json'), true, 512, JSON_THROW_ON_ERROR);
        $translation = array_filter($translation, static fn($value) => is_string($value) && trim($value) !== '');
        $messages[$code] = array_replace($base, $translation);
        $localizedPrice = str_replace('.', in_array(explode('-', $code)[0], ['en', 'mt', 'ga', 'cy', 'gd', 'hy', 'ka', 'az'], true) ? '.' : ',', site_pricing()['priceUsdPer1000']);
        foreach ($messages[$code] as &$text) $text = str_replace('{pricePer1000}', $localizedPrice, $text);
        unset($text);
        $languages[] = $entry;
    }
    if (!isset($messages[$registry['default']])) throw new RuntimeException('Default language is not enabled');
    return ['messages' => $messages, 'languages' => $languages, 'defaultLanguage' => $registry['default'], 'pricing' => site_pricing()];
}
