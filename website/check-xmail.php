<?php
declare(strict_types=1);
require __DIR__.'/xmail-imap.php';
function check(bool $condition,string $message):void{if(!$condition)throw new RuntimeException($message);}
check(XMailImap::quote('a"b\\c')==='"a\\"b\\\\c"','IMAP quoting');
try{XMailImap::quote("a\r\nLOGOUT");throw new Exception('injection accepted');}catch(RuntimeException $e){check($e->getMessage()==='invalid_imap_string','injection rejected');}
check(xmail_decode_header('=?UTF-8?B?0J/RgNC40LLQtdGC?=')==='Привет','MIME encoded header');
$mail=xmail_parse_message("Subject: Test\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\n--xyz\r\nContent-Type: multipart/alternative; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n".base64_encode('Hello <script>no execution</script>')."\r\n--abc\r\nContent-Type: text/html\r\n\r\n<b>alternative</b>\r\n--abc--\r\n--xyz\r\nContent-Type: application/octet-stream; name=test.txt\r\nContent-Disposition: attachment; filename*=UTF-8''test%20file.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n".base64_encode('binary'."\0")."\r\n--xyz--\r\n");
check(str_contains($mail['text'],'Hello')&&!str_contains($mail['text'],'alternative'),'Plain preferred over HTML');
check(count($mail['attachments'])===1&&$mail['attachments'][0]['name']==='test file.txt'&&$mail['attachments'][0]['data']==="binary\0",'Attachment decoding');
$html=xmail_parse_message("Content-Type: text/html; charset=UTF-8\r\n\r\n<head>hidden</head><script>alert(1)</script><p>Hello &amp; world</p><img src=https://tracker.invalid/x>");
check(str_contains($html['text'],'Hello & world')&&!str_contains($html['text'],'alert')&&!str_contains($html['text'],'tracker.invalid'),'HTML converted to inert text');
echo "XMail MIME: header decoding, multipart alternative, binary attachment, RFC2231, HTML-to-text and IMAP quoting OK\n";
