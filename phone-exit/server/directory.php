<?php
// Latest encrypted device state; no user traffic or plaintext device credentials.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function reply($status, $value) { http_response_code($status); echo json_encode($value); exit; }
function hex_key($value, $length) { return is_string($value) && preg_match('/\A[0-9a-f]{'.$length.'}\z/', $value); }
function blob($value, $max) { return is_string($value) && strlen($value) <= $max && preg_match('/\A[A-Za-z0-9+\/=]+\z/', $value); }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') reply(405, ['error'=>'POST required']);
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 16384) reply(413, ['error'=>'Request too large']);
$raw=file_get_contents('php://input', false, null, 0, 16385);
if (strlen($raw)>16384) reply(413, ['error'=>'Request too large']);
$input=json_decode($raw,true);
if (!is_array($input) || ($input['version']??0)!==1 || !hex_key($input['token']??null,64)) reply(403,['error'=>'Invalid capability']);
$op=$input['op']??'';
if (!in_array($op,['list','pulse','connect'],true)) reply(400,['error'=>'Invalid operation']);
$id=$input['id']??null;
if ($op!=='list' && !hex_key($id,32)) reply(400,['error'=>'Invalid device']);
if ($op==='pulse') {
    $box=$input['box']??null;
    if (!is_array($box) || !blob($box['ephemeral']??null,256) || !blob($box['iv']??null,32) || !blob($box['data']??null,4096)) reply(400,['error'=>'Invalid announcement']);
}
if ($op==='connect') {
    $request=$input['request']??null;
    if (!is_array($request) || !blob($request['iv']??null,32) || !blob($request['data']??null,4096)) reply(400,['error'=>'Invalid request']);
}
$dir=getenv('PHONE_EXIT_CATALOG_DATA') ?: dirname(__DIR__,2).'/phone-exit-catalog-data';
if (!is_dir($dir) && !@mkdir($dir,0700,true)) reply(503,['error'=>'Storage unavailable']);
$path=$dir.'/'.hash('sha256',$input['token']).'.json';
$files=glob($dir.'/*.json') ?: [];
// Account quota is intentionally independent of the legacy 30-room signal quota.
if (!file_exists($path) && count($files)>=32) reply(429,['error'=>'Account limit']);
$file=@fopen($path,'c+');
if (!$file || !flock($file,LOCK_EX)) reply(503,['error'=>'Storage busy']);
@chmod($path,0600);
$stored=stream_get_contents($file,2097153);
if (strlen($stored)>2097152) reply(503,['error'=>'Storage limit']);
$account=json_decode($stored,true);
if (!is_array($account)) $account=['devices'=>[]];
$now=time();
foreach ($account['devices'] as $key=>$device) {
    if (($device['updated']??0)<$now-86400) unset($account['devices'][$key]);
    elseif (($device['requested']??0)<$now-45) { unset($account['devices'][$key]['request']); unset($account['devices'][$key]['requested']); }
}
if ($op==='pulse') {
    if (!isset($account['devices'][$id]) && count($account['devices'])>=256) reply(429,['error'=>'Device limit']);
    $old=$account['devices'][$id]??[];
    $old['id']=$id; $old['box']=$box; $old['updated']=$now;
    $account['devices'][$id]=$old;
    $response=['request'=>$old['request']??null];
} elseif ($op==='connect') {
    if (!isset($account['devices'][$id]) || $account['devices'][$id]['updated']<$now-45) reply(409,['error'=>'Device offline']);
    $account['devices'][$id]['request']=$request; $account['devices'][$id]['requested']=$now;
    $response=['ok'=>true];
} else {
    $response=['devices'=>array_values(array_map(function($device){return ['id'=>$device['id'],'box'=>$device['box'],'updated'=>$device['updated']];},$account['devices'])),'limit'=>256];
}
$encoded=json_encode($account);
if (strlen($encoded)>2097152) reply(413,['error'=>'Storage limit']);
rewind($file); ftruncate($file,0);
if (fwrite($file,$encoded)!==strlen($encoded) || !fflush($file)) reply(503,['error'=>'Storage write failed']);
flock($file,LOCK_UN); fclose($file);
reply(200,$response);
