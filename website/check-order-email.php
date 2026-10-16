<?php
require __DIR__ . '/order-email.php';
require __DIR__ . '/vendor/autoload.php';
function check(bool $pass, string $label): void {if (!$pass) throw new RuntimeException($label);}
$order=['id'=>'VT-DESIGN-TEST','amount'=>1000,'price_usd'=>'8.00000','rate_usd_per_1000'=>'8.00','region'=>'SEA','server'=>'Server <script>alert(1)</script>','nickname'=>'Test & name','contact'=>'discord: test_only','language'=>'uk','created_at'=>'2026-10-17T01:00:00Z','comment'=>"Line one\n<img src=x onerror=alert(1)> "];
$html=site_order_email_html($order);
check(str_contains($html,'8.00 <span'),'Price formatted');
check(str_contains($html,'1 000'),'Grouped quantity');
check(!str_contains($html,'<script>')&&!str_contains($html,'<img src=x'),'Escaped user fields');
check(str_contains($html,'&lt;script&gt;')&&str_contains($html,'&lt;img'),'Preserved readable text');
check(str_contains($html,'Line one<br>'),'Comment line breaks');
$mailer=new PHPMailer\PHPMailer\PHPMailer(true);$mailer->setFrom('orders@vampir.top');$mailer->addAddress('test@example.com');$mailer->isHTML(true);$mailer->Body=$html;$mailer->AltBody='Plain text order';$mailer->Subject='Test';$mailer->preSend();
$mime=$mailer->getSentMIMEMessage();check(str_contains($mime,'multipart/alternative')&&str_contains($mime,'text/html')&&str_contains($mime,'text/plain'),'Multipart mail');
echo "Order email: escaped user data, formatted totals, multiline comments and HTML/plain MIME OK\n";
$seller = array_replace($order, ['kind'=>'sell','id'=>'VS-TEST','amount'=>5000,'price_usd'=>null,'rate_usd_per_1000'=>null]);
$offer = site_order_email_html($seller);
check(str_contains($offer,'BUYBACK OFFER') && str_contains($offer,'To agree'), 'Seller offer label and negotiated price');
check(!str_contains($offer,'Rate:') && !str_contains($offer,'ORDER TOTAL') && !str_contains($offer,'final USDT'), 'No retail tariff or fixed payment terms on seller offer');
$priced = site_order_email_html(array_replace($seller,['price_usd'=>'35.50']));
check(str_contains($priced,'35.50') && str_contains($priced,'SELLER ASKING TOTAL'), 'Seller asking price');
echo "Seller email: separate offer, asking price and no retail pricing: OK\n";
