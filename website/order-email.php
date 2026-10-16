<?php
declare(strict_types=1);

/** Table layout and inline styles keep order notifications readable in mail clients. */
function site_order_email_html(array $order): string {
    $escape = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $price = rtrim(rtrim((string)$order['price_usd'], '0'), '.');
    $price = number_format((float)$price, max(2, strlen(explode('.', $price)[1] ?? '')), '.', ' ');
    $amount = number_format((int)$order['amount'], 0, '.', ' ');
    $rows = '';
    foreach ([
        'Region' => $order['region'], 'Server' => $order['server'],
        'Character' => $order['nickname'] ?: 'Not provided', 'Contact' => $order['contact'],
        'Customer language' => $order['language'], 'Created (UTC)' => $order['created_at'],
    ] as $label => $value) {
        $rows .= '<tr><td width="36%" valign="top" style="padding:13px 0;border-bottom:1px solid #eee7eb;color:#7a6571;font-size:13px;line-height:22px;">'
            . $escape($label) . '</td><td valign="top" style="padding:13px 0 13px 12px;border-bottom:1px solid #eee7eb;color:#251920;font-size:14px;line-height:22px;font-weight:600;word-break:break-word;overflow-wrap:anywhere;">'
            . $escape($value) . '</td></tr>';
    }
    $id = $escape($order['id']);
    $comment = nl2br($escape($order['comment'] ?: 'No comment provided.'), false);
    $rate = $escape($order['rate_usd_per_1000']);
    $price = $escape($price);
    return <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VAMPIR.TOP order {$id}</title></head>
<body style="margin:0;padding:0;background:#f2edf0;color:#251920;font-family:Arial,Helvetica,sans-serif;">
<div style="display:none;font-size:1px;line-height:1px;color:#f2edf0;max-height:0;max-width:0;opacity:0;overflow:hidden;">New order {$id} · {$amount} diamonds · {$price} USD</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f2edf0"><tr><td align="center" style="padding:28px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:#ffffff;border:1px solid #e5dbe1;border-radius:16px;overflow:hidden;">
<tr><td bgcolor="#1c111b" style="padding:28px 24px;border-bottom:4px solid #b72b50;">
<a href="https://vampir.top/" style="text-decoration:none;color:#f8eef3;font-family:Georgia,serif;font-size:27px;letter-spacing:3px;font-weight:bold;">VAMPIR<span style="color:#e395ad;font-size:17px;letter-spacing:1px;">.TOP</span></a>
<p style="margin:10px 0 0;color:#ccb9c5;font-size:11px;letter-spacing:2px;line-height:18px;">DIAMOND STORE / ORDER NOTIFICATION</p></td></tr>
<tr><td style="padding:28px 24px 12px;"><p style="margin:0 0 10px;color:#a02c50;font-size:11px;letter-spacing:2px;font-weight:bold;">NEW REQUEST</p>
<h1 style="margin:0 0 10px;font-family:Georgia,serif;font-size:30px;line-height:38px;font-weight:normal;color:#281a24;">A new diamond order.</h1>
<p style="margin:0;font-size:14px;line-height:24px;color:#796570;">Order <strong style="color:#4c283d;white-space:nowrap;">{$id}</strong></p></td></tr>
<tr><td style="padding:16px 24px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f8f1f5" style="border:1px solid #ead9e3;border-radius:10px;">
<tr><td width="50%" valign="top" style="padding:20px 14px;"><p style="margin:0 0 8px;font-size:11px;line-height:18px;color:#806777;letter-spacing:1px;">DIAMONDS</p><p style="margin:0;font-size:25px;line-height:34px;font-weight:bold;color:#352130;">{$amount}</p></td>
<td width="50%" valign="top" style="padding:20px 14px;border-left:1px solid #ead9e3;"><p style="margin:0 0 8px;font-size:11px;line-height:18px;color:#806777;letter-spacing:1px;">ORDER TOTAL</p><p style="margin:0;font-size:25px;line-height:34px;font-weight:bold;color:#a3264c;">{$price} <span style="font-size:13px;">USD</span></p></td></tr>
</table><p style="margin:10px 0 0;font-size:12px;line-height:21px;color:#816b79;">Rate: {$rate} USD / 1,000 diamonds &nbsp;·&nbsp; Payment: <strong style="color:#29735b;">USDT</strong></p></td></tr>
<tr><td style="padding:8px 24px 20px;"><h2 style="margin:0 0 4px;font-size:15px;line-height:24px;color:#392432;">Customer &amp; game details</h2><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{$rows}</table></td></tr>
<tr><td style="padding:0 24px 24px;"><h2 style="margin:0 0 10px;font-size:15px;line-height:24px;color:#392432;">Comment</h2><div style="padding:16px;background:#f7f4f6;border:1px solid #ebe3e8;border-radius:8px;font-size:14px;line-height:24px;color:#59414f;word-break:break-word;overflow-wrap:anywhere;">{$comment}</div></td></tr>
<tr><td style="padding:0 24px 28px;"><div style="padding:14px 16px;border-left:3px solid #b72b50;background:#fff6f1;color:#755648;font-size:12px;line-height:21px;">Contact the customer to confirm availability, delivery details and the final USDT amount before payment. This notification confirms a request, not a completed payment.</div></td></tr>
<tr><td bgcolor="#f9f6f8" style="padding:20px 24px;border-top:1px solid #eee5eb;font-size:11px;line-height:20px;color:#8e7886;">VAMPIR.TOP · Automated order notification<br>Customer contact and order details are provided above.</td></tr>
</table></td></tr></table></body></html>
HTML;
}
