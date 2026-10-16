<?php
declare(strict_types=1);
session_start();
require_once dirname(__DIR__, 2) . '/i18n.php';
require_once dirname(__DIR__, 2) . '/notifications.php';
require_once dirname(__DIR__, 2) . '/turnstile.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function fail(int $status, string $error): never { http_response_code($status); echo json_encode(['error'=>$error]); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Allow: POST'); fail(405, 'method_not_allowed'); }
if (!isset($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) fail(403, 'csrf');
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0)>8192) fail(413,'too_large');
if (isset($_SESSION['last_order']) && time()-$_SESSION['last_order']<15) fail(429,'rate_limit');
$data=json_decode(file_get_contents('php://input',false,null,0,8193),true);
if (!is_array($data)) fail(400,'invalid_json');
$kind=$data['kind']??'buy';
if(!in_array($kind,['buy','sell'],true)) fail(422,'invalid_kind');
$amount=filter_var($data['amount']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>$kind==='sell'?5000:1000,'max_range'=>10000000]]);
if ($amount===false || $amount===null || ($data['consent']??'')!=='on') fail(422,'invalid_order');
$fields=[];
foreach (['region'=>60,'server'=>60,'contact'=>160,'comment'=>1000,'nickname'=>80] as $key=>$max) {
  if(isset($data[$key])&&!is_string($data[$key])) fail(422,'invalid_field');
  $value=trim($data[$key]??'');
  if(strlen($value)>$max*4 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/',$value)) fail(422,'invalid_field');
  if(in_array($key,['region','server','contact'],true)&&$value==='') fail(422,'required');
  $fields[$key]=$value;
}
if(strlen($fields['contact'])<3) fail(422,'invalid_contact');
if(!in_array($fields['region'], ['GLOBAL','SEA','KR'], true)) fail(422,'invalid_region');
$currency=$data['currency']??'USD';$language=$data['language']??'en';
if($currency!=='USD'||($data['payment_currency']??'USDT')!=='USDT'||!is_string($language)||!isset(site_languages()['messages'][$language])) fail(422,'invalid_locale');
$asking=$data['asking_price']??'';
if($kind==='sell' && (!is_string($asking)||($asking!==''&&(!preg_match('/^[0-9]{1,7}(?:\.[0-9]{1,2})?$/D',$asking)||(float)$asking<=0||(float)$asking>1000000)))) fail(422,'invalid_price');
$verification = site_turnstile_verify($data['cf-turnstile-response'] ?? null);
if ($verification !== '') fail($verification === 'turnstile_unavailable' ? 503 : 403, $verification);
if(!site_email_rate_limit(dirname(__DIR__,2).'/var/mail-limits')) fail(429,'rate_limit');
$id=($kind==='sell'?'VS-':'VT-').strtoupper(bin2hex(random_bytes(6)));
$pricing=$kind==='sell'?['price_usd'=>$asking===''?null:number_format((float)$asking,2,'.',''),'rate_usd_per_1000'=>null,'asking_price_usd'=>$asking===''?null:number_format((float)$asking,2,'.',''),'pricing_status'=>'negotiable']:site_order_price($amount);
$order=['id'=>$id,'kind'=>$kind,'created_at'=>gmdate('c'),'status'=>'received','email_status'=>'pending','amount'=>$amount,'currency'=>'USD','payment_currency'=>$kind==='sell'?'TO_AGREE':'USDT','language'=>$language,'consent_at'=>gmdate('c')]+$pricing+$fields;
$directory=dirname(__DIR__,2).'/var/orders';
if(!is_dir($directory)&&!@mkdir($directory,0700,true)&&!is_dir($directory)) fail(503,'storage_unavailable');
$json=json_encode($order,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
if(@file_put_contents($directory.'/'.$id.'.json',$json,LOCK_EX)===false) fail(503,'storage_unavailable');
$_SESSION['last_order']=time();
$accepted=site_notify_order($order);
$order['email_status']=$accepted?'accepted_by_mail_server':'failed';
$order['email_attempted_at']=gmdate('c');
if(@file_put_contents($directory.'/'.$id.'.json',json_encode($order,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),LOCK_EX)===false) error_log('VAMPIR order email status write failed: '.$id);
if(!$accepted) error_log('VAMPIR order email failed: '.$id);
http_response_code(201);echo json_encode(['id'=>$id,'status'=>'received','email_accepted'=>$accepted]);
