<?php
declare(strict_types=1);
session_start();
require_once dirname(__DIR__) . '/seo.php';
require_once dirname(__DIR__) . '/turnstile.php';
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
header('Cache-Control: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
$clientI18n = $i18n;
$clientI18n['messages'] = array_intersect_key($i18n['messages'], array_flip(['en', $currentLanguage]));
?>
<!doctype html>
<html lang="<?= site_escape($currentLanguage) ?>">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= site_text('pageTitle') ?></title>
  <meta name="description" content="<?= site_text('metaDescription') ?>">
  <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf'], ENT_QUOTES) ?>">
  <meta name="theme-color" content="#0c0b0d">
  <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="icon" href="/assets/brand-mark.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/styles.css?v=<?= filemtime(__DIR__ . '/styles.css') ?>"><script id="i18n-data" type="application/json"><?= json_encode($clientI18n, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) ?></script><script src="/app.js?v=<?= filemtime(__DIR__ . '/app.js') ?>" defer></script>
  <link rel="canonical" href="<?= site_escape($canonicalUrl) ?>">
  <?php foreach ($i18n['languages'] as $entry): ?><link rel="alternate" hreflang="<?= site_escape($entry['code']) ?>" href="<?= site_escape($productionOrigin . $entry['path']) ?>"><?php endforeach; ?>
  <link rel="alternate" hreflang="x-default" href="https://vampir.top/">
  <meta name="robots" content="<?= $isProduction ? 'index, follow, max-image-preview:large' : 'noindex, nofollow' ?>">
  <meta property="og:type" content="website"><meta property="og:site_name" content="VAMPIR.TOP">
  <meta property="og:title" content="<?= site_text('pageTitle') ?>"><meta property="og:description" content="<?= site_text('metaDescription') ?>">
  <meta property="og:url" content="<?= site_escape($canonicalUrl) ?>"><meta property="og:image" content="https://vampir.top/assets/hero.jpg">
  <meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="<?= site_text('pageTitle') ?>"><meta name="twitter:description" content="<?= site_text('metaDescription') ?>"><meta name="twitter:image" content="https://vampir.top/assets/hero.jpg">
  <link rel="preload" as="image" href="/assets/world.jpg">
  <script type="application/ld+json"><?= json_encode($structuredData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) ?></script>
</head>
<body>
<a class="skip" href="#catalog" data-i18n="skip"><?= site_text('skip', false) ?></a>
<header class="header"><a class="brand" href="#" aria-label="Vampir.top"><img class="brand-symbol" src="/assets/brand-mark.svg" width="42" height="48" alt=""><span>VAMPIR<span class="brand-dot">.TOP</span></span></a>
  <nav id="primary-nav" data-i18n-aria="navigationLabel" aria-label="<?= site_text('navigationLabel') ?>"><a href="#catalog" data-i18n="navShop"><?= site_text('navShop', false) ?></a><a href="#how" data-i18n="navHow"><?= site_text('navHow', false) ?></a><a href="#faq">FAQ</a></nav>
  <div class="language"><span class="language-globe" aria-hidden="true">◎</span><button id="language" data-i18n-aria="languageLabel" class="language-trigger" type="button" aria-label="<?= site_text('languageLabel') ?>" aria-expanded="false" aria-controls="language-menu"><span class="language-current"><?= site_escape($currentLanguage === 'uk' ? 'UA' : strtoupper($currentLanguage)) ?></span><svg width="12" height="8" viewBox="0 0 12 8" aria-hidden="true"><path d="m1 1 5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg></button><div id="language-menu" class="language-menu" role="group" data-i18n-aria="languageLabel" aria-label="<?= site_text('languageLabel') ?>" hidden><?php foreach ($i18n['languages'] as $entry): ?><a href="<?= site_escape($entry['path']) ?>" hreflang="<?= site_escape($entry['code']) ?>" lang="<?= site_escape($entry['code']) ?>" data-language="<?= site_escape($entry['code']) ?>" <?= $entry['code'] === $currentLanguage ? 'aria-current="page"' : '' ?>><span><?= htmlspecialchars($entry['label'], ENT_QUOTES) ?></span><span><?= htmlspecialchars($entry['name'], ENT_QUOTES) ?></span><span class="language-check" aria-hidden="true">✓</span></a><?php endforeach; ?></div></div><button class="menu-toggle" data-i18n-aria="menuLabel" type="button" aria-controls="primary-nav" aria-expanded="false" aria-label="<?= site_text('menuLabel') ?>"><span></span><span></span></button>
</header>
<main>
<section class="hero" aria-labelledby="hero-title">
  <div class="hero-art" aria-hidden="true"></div><div class="hero-shade" aria-hidden="true"></div>
  <div class="hero-content"><p class="eyebrow"><span aria-hidden="true"></span><b data-i18n="heroEyebrow"><?= site_text('heroEyebrow', false) ?></b></p>
    <h1 id="hero-title" data-i18n-html="heroTitle"><?= site_text('heroTitle', true) ?></h1>
    <p class="hero-description" data-i18n="heroDesc"><?= site_text('heroDesc', false) ?></p>
    <button type="button" class="button primary select-package" data-amount=""><span class="diamond">◇</span><span data-i18n="choose"><?= site_text('choose', false) ?></span><span>↗</span></button>
    <div class="hero-note"><span class="line"></span><span data-i18n="heroNote"><?= site_text('heroNote', false) ?></span></div>
  </div>
  <div class="hero-bottom"><span>01 / VAMPIR.TOP</span><a href="#catalog" data-i18n="explore"><?= site_text('explore', false) ?></a><span>PC · ANDROID · iOS</span></div>
</section>
<div class="ribbon"><span data-i18n="ribbon1"><?= site_text('ribbon1', false) ?></span><b>✧</b><span data-i18n="ribbon2"><?= site_text('ribbon2', false) ?></span><b>✧</b><span data-i18n="ribbon3"><?= site_text('ribbon3', false) ?></span><b>✧</b><span>VAMPIR.TOP</span></div>
<section id="catalog" class="section catalog">
  <div class="section-heading"><div><p class="eyebrow" data-i18n="catalogEyebrow"><?= site_text('catalogEyebrow', false) ?></p><h2 data-i18n-html="catalogTitle"><?= site_text('catalogTitle', true) ?></h2></div><p class="section-description" data-i18n="catalogDesc"><?= site_text('catalogDesc', false) ?></p></div>
  <div class="catalog-toolbar"><span class="catalog-label"><span class="diamond">◇</span> <span data-i18n="currency"><?= site_text('currency', false) ?></span></span><div class="payment-badge"><span data-i18n="currencyLabel"><?= site_text('currencyLabel', false) ?></span><strong>USDT</strong></div></div>
  <article class="custom-main featured">
    <div class="diamond-display"><div class="display-top"><span>VAMPIR</span><span>DIAMONDS / 01</span></div><div class="diamond-orbit" aria-hidden="true"><div class="orbit-ring"></div><div class="orbit-ring inner"></div><img src="/assets/diamond-premium.svg" width="400" height="340" alt=""><span class="spark spark-one">✦</span><span class="spark spark-two">✧</span></div><div class="display-bottom"><span data-i18n="artCaption"><?= site_text('artCaption', false) ?></span><span class="display-rule"></span><span>◇</span></div></div>
    <div class="custom-main-controls"><p class="eyebrow" data-i18n="orderEyebrow"><?= site_text('orderEyebrow', false) ?></p><h3 data-i18n="customTitle"><?= site_text('customTitle', false) ?></h3><p class="order-intro" data-i18n="customDesc"><?= site_text('customDesc', false) ?></p>
      <label class="custom-amount-label" for="custom-amount" data-i18n="amountLabel"><?= site_text('amountLabel', false) ?></label><div class="amount-stepper"><button type="button" data-adjust="-1000" data-i18n-aria="decrease" aria-label="<?= site_text('decrease') ?>">−</button><input id="custom-amount" value="1000" type="number" min="1000" max="10000000" step="1" required inputmode="numeric" placeholder="1 000" aria-describedby="amount-hint"><span class="amount-unit" aria-hidden="true">◇</span><button type="button" data-adjust="1000" data-i18n-aria="increase" aria-label="<?= site_text('increase') ?>">+</button></div><span class="minimum-amount">≥ 1 000 ◇</span><span id="amount-hint" data-i18n="rateLabel"><?= site_text('rateLabel', false) ?></span>
      <div class="quick-amounts"><span data-i18n="quickAmounts"><?= site_text('quickAmounts', false) ?></span><button type="button" data-preset="1000" aria-pressed="false">1 000</button><button type="button" data-preset="5000" aria-pressed="false">5 000</button><button type="button" data-preset="10000" aria-pressed="false">10 000</button></div>
      <div class="quote-summary"><span data-i18n="quoteLabel"><?= site_text('quoteLabel', false) ?></span><strong id="price-total" aria-live="polite"><?= site_escape(site_pricing()['priceUsdPer1000']) ?> USD</strong></div><button type="button" class="button primary select-package" data-amount="" data-custom data-i18n="customButton"><?= site_text('customButton', false) ?></button><p class="quote-note"><span aria-hidden="true">◇</span><span data-i18n="quoteNote"><?= site_text('quoteNote', false) ?></span></p>
    </div>
  </article>
</section>
<section id="how" class="section how"><div><p class="eyebrow" data-i18n="howEyebrow"><?= site_text('howEyebrow', false) ?></p><h2 data-i18n-html="howTitle"><?= site_text('howTitle', true) ?></h2><a href="#catalog" class="text-button" data-i18n="goShop"><?= site_text('goShop', false) ?></a></div><ol class="steps"><li><span>01</span><div><h3 data-i18n="step1"><?= site_text('step1', false) ?></h3><p data-i18n="step1Desc"><?= site_text('step1Desc', false) ?></p></div></li><li><span>02</span><div><h3 data-i18n="step2"><?= site_text('step2', false) ?></h3><p data-i18n="step2Desc"><?= site_text('step2Desc', false) ?></p></div></li><li><span>03</span><div><h3 data-i18n="step3"><?= site_text('step3', false) ?></h3><p data-i18n="step3Desc"><?= site_text('step3Desc', false) ?></p></div></li></ol></section>
<section class="world-banner"><div><p class="eyebrow">VAMPIR / DARK FANTASY MMORPG</p><h2 data-i18n-html="worldTitle"><?= site_text('worldTitle', true) ?></h2><a class="button outline" href="https://vampirgb.netmarble.com/en/preorder" target="_blank" rel="noopener noreferrer" id="official-link"><span data-i18n="official"><?= site_text('official', false) ?></span><span>↗</span></a></div></section>
<section id="faq" class="section faq"><div><p class="eyebrow" data-i18n="faqEyebrow"><?= site_text('faqEyebrow', false) ?></p><h2 data-i18n-html="faqTitle"><?= site_text('faqTitle', true) ?></h2></div><div class="faq-list">
<details open><summary data-i18n="q1"><?= site_text('q1', false) ?></summary><p data-i18n="a1"><?= site_text('a1', false) ?></p></details>
<details><summary data-i18n="q2"><?= site_text('q2', false) ?></summary><p data-i18n="a2"><?= site_text('a2', false) ?></p></details>
<details><summary data-i18n="q3"><?= site_text('q3', false) ?></summary><p data-i18n="a3"><?= site_text('a3', false) ?></p></details>
<details><summary data-i18n="q4"><?= site_text('q4', false) ?></summary><p data-i18n="a4"><?= site_text('a4', false) ?></p></details>
</div></section>
<section class="section buying-guide" aria-labelledby="buying-guide-title">
  <h2 id="buying-guide-title" data-i18n="seoHeading"><?= site_text('seoHeading', false) ?></h2>
  <div class="buying-guide-copy"><p data-i18n="seoIntro"><?= site_text('seoIntro', false) ?></p><p data-i18n="seoDetails"><?= site_text('seoDetails', false) ?></p></div>
</section>
</main>
<footer><a class="brand" href="#" aria-label="Vampir.top"><img class="brand-symbol" src="/assets/brand-mark.svg" width="36" height="42" alt=""><span>VAMPIR<span class="brand-dot">.TOP</span></span></a><p data-i18n="footer"><?= site_text('footer', false) ?></p><span>18+</span></footer>
<dialog id="order-dialog" aria-labelledby="order-title"><button class="close-dialog" data-i18n-aria="closeLabel" type="button" aria-label="<?= site_text('closeLabel') ?>">×</button><p class="eyebrow" data-i18n="orderEyebrow"><?= site_text('orderEyebrow', false) ?></p><h2 id="order-title" data-i18n="orderTitle"><?= site_text('orderTitle', false) ?></h2><p class="dialog-description" data-i18n="orderDesc"><?= site_text('orderDesc', false) ?></p>
<div id="order-confirmation" tabindex="-1" role="status" aria-live="polite" hidden><span class="confirmation-icon" aria-hidden="true">✓</span><h2 data-i18n="thankYou"><?= site_text('thankYou', false) ?></h2><p id="confirmation-message"></p><button id="confirmation-close" class="button primary" type="button" data-i18n="closeLabel"><?= site_text('closeLabel', false) ?></button></div>
<form id="order-form"><input type="hidden" name="currency" value="USD"><input type="hidden" name="payment_currency" value="USDT"><div class="quote-summary"><span data-i18n="quoteLabel"><?= site_text('quoteLabel', false) ?></span><strong id="order-price-total" aria-live="polite">— USD</strong></div><label><span data-i18n="amountLabel"><?= site_text('amountLabel', false) ?></span><input name="amount" value="1000" placeholder="1 000" type="number" min="1000" max="10000000" step="1" required inputmode="numeric"></label><div class="form-row"><div class="region-field"><span id="region-label" data-i18n="regionLabel"><?= site_text('regionLabel', false) ?></span><input type="hidden" name="region" value=""><button type="button" id="region-trigger" role="combobox" aria-labelledby="region-label region-value" aria-controls="region-options" aria-haspopup="listbox" aria-expanded="false" aria-required="true"><span id="region-value">—</span><svg width="12" height="8" viewBox="0 0 12 8" aria-hidden="true"><path d="m1 1 5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg></button><div id="region-options" role="listbox" aria-labelledby="region-label" hidden><button type="button" role="option" aria-selected="false" data-region="GLOBAL">Global<span aria-hidden="true">✓</span></button><button type="button" role="option" aria-selected="false" data-region="SEA">SEA<span aria-hidden="true">✓</span></button><button type="button" role="option" aria-selected="false" data-region="KR">Korea<span aria-hidden="true">✓</span></button></div></div><label><span data-i18n="serverLabel"><?= site_text('serverLabel', false) ?></span><input name="server" data-i18n-placeholder="serverPlaceholder" placeholder="<?= site_text('serverPlaceholder') ?>" required maxlength="60" autocomplete="off"></label></div><div class="payment-badge form-payment"><span data-i18n="currencyLabel"><?= site_text('currencyLabel', false) ?></span><strong>USDT</strong></div><label><span data-i18n="nicknameLabel"><?= site_text('nicknameLabel', false) ?></span><input name="nickname" maxlength="80" autocomplete="off"></label><p class="form-note" data-i18n="currencyHelp"><?= site_text('currencyHelp', false) ?></p><label><span data-i18n="contactLabel"><?= site_text('contactLabel', false) ?></span><input name="contact" data-i18n-placeholder="contactPlaceholder" placeholder="<?= site_text('contactPlaceholder') ?>" required minlength="3" maxlength="160" autocomplete="off"></label><label><span data-i18n="commentLabel"><?= site_text('commentLabel', false) ?></span><textarea name="comment" maxlength="1000" rows="2"></textarea></label><label class="consent"><input type="checkbox" name="consent" required><span data-i18n="consent"><?= site_text('consent', false) ?></span></label><p class="form-note" data-i18n="formNote"><?= site_text('formNote', false) ?></p><div class="order-security"><div id="order-turnstile" tabindex="-1" data-sitekey="<?= site_escape(site_turnstile_public()['site_key']) ?>"></div><p id="turnstile-status" class="form-note" role="status" aria-live="polite"></p></div><button class="button primary" type="submit" id="submit-order" data-i18n="submit"><?= site_text('submit', false) ?></button><p id="order-result" role="status" aria-live="polite"></p></form></dialog>
</body></html>
