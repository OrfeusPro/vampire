<?php
declare(strict_types=1);

function site_pricing(): array {
    static $pricing;
    if ($pricing !== null) return $pricing;
    $config = json_decode(file_get_contents(__DIR__ . '/settings.json'), true, 512, JSON_THROW_ON_ERROR);
    $value = $config['price_usd_per_1000'] ?? null;
    if (!is_string($value) || !preg_match('/^[0-9]{1,6}\.[0-9]{2}$/D', $value)) {
        throw new RuntimeException('price_usd_per_1000 must be a positive USD string, for example 8.00');
    }
    [$dollars, $cents] = explode('.', $value);
    $rateCents = (int)$dollars * 100 + (int)$cents;
    if ($rateCents < 1) throw new RuntimeException('Price must be greater than zero');
    return $pricing = ['priceUsdPer1000' => $value, 'rateCents' => $rateCents];
}

function site_order_price(int $amount): array {
    $units = $amount * site_pricing()['rateCents'];
    // Exact integer arithmetic: USD cents per 1,000 diamonds => 1/100,000 USD.
    $price = intdiv($units, 100000) . '.' . str_pad((string)($units % 100000), 5, '0', STR_PAD_LEFT);
    return ['price_usd' => $price, 'price_usd_units_100000' => $units,
        'rate_usd_per_1000' => site_pricing()['priceUsdPer1000']];
}
