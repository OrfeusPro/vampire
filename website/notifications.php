<?php
declare(strict_types=1);
require_once __DIR__ . '/order-email.php';

function site_notify_order(array $order): bool {
    $config = json_decode(file_get_contents(__DIR__ . '/settings.json'), true, 512, JSON_THROW_ON_ERROR);
    $mail = $config['order_email'] ?? [];
    if (empty($mail['enabled'])) return false;
    $recipient = $mail['to'] ?? '';
    $sender = $mail['from'] ?? '';
    if (!is_string($recipient) || !is_string($sender)
        || !filter_var($recipient, FILTER_VALIDATE_EMAIL) || !filter_var($sender, FILTER_VALIDATE_EMAIL)
        || preg_match('/[\r\n]/', $recipient . $sender)
        || !preg_match('/^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$/D', $sender)) return false;
    $lines = [
        'New diamond order from VAMPIR.TOP', 'Order: ' . $order['id'],
        'Created (UTC): ' . $order['created_at'], 'Diamonds: ' . $order['amount'],
        'Price: ' . $order['price_usd'] . ' USD', 'Rate per 1000: ' . $order['rate_usd_per_1000'] . ' USD',
        'Payment currency: USDT (not paid)', 'Region: ' . $order['region'], 'Server: ' . $order['server'],
        'Character: ' . ($order['nickname'] ?: 'Not provided'), 'Contact: ' . $order['contact'],
        'Language: ' . $order['language'], '', 'Comment:', $order['comment'] ?: 'Not provided',
        '', 'This is a request, not proof of payment. Confirm delivery details with the customer.',
    ];
    if (($mail['transport'] ?? 'mail') === 'smtp') {
        try {
            $smtp = require __DIR__ . '/smtp.local.php';
            require_once __DIR__ . '/vendor/autoload.php';
            if (!is_array($smtp) || ($smtp['username'] ?? '') !== $sender || empty($smtp['password'])
                || !in_array($smtp['encryption'] ?? '', ['tls', 'ssl'], true)) return false;
            $mailer = new \PHPMailer\PHPMailer\PHPMailer(true);
            $mailer->isSMTP();
            $mailer->Host = $smtp['host'];
            $mailer->Port = (int)$smtp['port'];
            $mailer->SMTPSecure = $smtp['encryption'];
            $mailer->SMTPAuth = true;
            $mailer->Username = $smtp['username'];
            $mailer->Password = $smtp['password'];
            $mailer->Timeout = 20;
            $mailer->SMTPDebug = 0;
            $mailer->SMTPOptions = ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false]];
            $mailer->CharSet = 'UTF-8';
            $mailer->Encoding = 'base64';
            $mailer->setFrom($sender, 'VAMPIR.TOP');
            $mailer->Sender = $sender;
            $mailer->addAddress($recipient);
            $mailer->Subject = 'VAMPIR.TOP order ' . $order['id'];
            $mailer->isHTML(true);
            $mailer->Body = site_order_email_html($order);
            $mailer->AltBody = implode("\r\n", $lines);
            $mailer->MessageID = '<' . $order['id'] . '.' . bin2hex(random_bytes(8)) . '@vampir.top>';
            $mailer->addCustomHeader('Auto-Submitted', 'auto-generated');
            return $mailer->send();
        } catch (\Throwable $error) {
            error_log('VAMPIR authenticated SMTP failed for order ' . $order['id']);
            return false;
        }
    }
    if (!function_exists('mail')) return false;
    $headers = ['From' => 'VAMPIR.TOP <' . $sender . '>', 'MIME-Version' => '1.0',
        'Content-Type' => 'text/plain; charset=UTF-8', 'Content-Transfer-Encoding' => 'base64',
        'Auto-Submitted' => 'auto-generated'];
    // Contact details go only in the encoded body, never in email headers.
    $body = chunk_split(base64_encode(implode("\r\n", $lines)), 76, "\r\n");
    return @mail($recipient, 'VAMPIR.TOP order ' . $order['id'], $body, $headers, '-f' . $sender);
}

function site_email_rate_limit(string $directory): bool {
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) return false;
    $saltFile = $directory . '/salt';
    if (!is_file($saltFile)) {
        $handle = @fopen($saltFile, 'x');
        if ($handle) { fwrite($handle, random_bytes(32)); fclose($handle); }
    }
    $salt = @file_get_contents($saltFile);
    if (!is_string($salt) || strlen($salt) !== 32) return false;
    $key = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown', $salt);
    $handle = @fopen($directory . '/' . $key . '.json', 'c+');
    if (!$handle || !flock($handle, LOCK_EX)) { if ($handle) fclose($handle); return false; }
    $recent = json_decode(stream_get_contents($handle) ?: '[]', true);
    $recent = array_values(array_filter(is_array($recent) ? $recent : [], static fn($time) => is_int($time) && $time > time() - 600));
    $allowed = count($recent) < 3;
    if ($allowed) $recent[] = time();
    rewind($handle); ftruncate($handle, 0); fwrite($handle, json_encode($recent));
    flock($handle, LOCK_UN); fclose($handle);
    return $allowed;
}
