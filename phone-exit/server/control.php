<?php
// Separate encrypted command broker. Never change legacy signal/directory files.
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function answer($status,$body){http_response_code($status);header('Content-Type: application/json; charset=utf-8');echo json_encode($body);exit;}
function validhex($x,$n){return is_string($x)&&preg_match('/\A[0-9a-f]{'.$n.'}\z/',$x);}
function boxok($x,$max){return is_array($x)&&is_string($x['iv']??null)&&strlen($x['iv'])===16&&strlen(base64_decode($x['iv'],true)?:'')===12&&is_string($x['data']??null)&&strlen($x['data'])<=$max&&strlen(base64_decode($x['data'],true)?:'')>=16;}
if($_SERVER['REQUEST_METHOD']!=='POST')answer(405,['error'=>'POST required']);
if((int)($_SERVER['CONTENT_LENGTH']??0)>3000000)answer(413,['error'=>'Request too large']);
$raw=file_get_contents('php://input',false,null,0,3000001);
if(strlen($raw)>3000000)answer(413,['error'=>'Request too large']);
$in=json_decode($raw,true);
if(!is_array($in)||($in['version']??0)!==1||!validhex($in['token']??null,64))answer(403,['error'=>'Invalid capability']);
$op=$in['op']??'';
if(!in_array($op,['enqueue','poll','result','get','ack','manifest','package'],true))answer(400,['error'=>'Invalid operation']);
$root=getenv('PHONE_EXIT_CONTROL_DATA')?:__DIR__.'/private';
$account=hash('sha256',$in['token']);
if(in_array($op,['manifest','package'],true)){
    $base=$root.'/releases/'.$account;
    if(!is_file($base.'.json')||!is_file($base.'.apk'))answer(404,['error'=>'No update']);
    $meta=json_decode(file_get_contents($base.'.json'),true);
    if(!is_array($meta)||!isset($meta['versionCode'],$meta['versionName'],$meta['sha256'],$meta['size']))answer(503,['error'=>'Invalid release']);
    if($op==='manifest')answer(200,$meta);
    if(($in['sha256']??'')!==$meta['sha256'])answer(409,['error'=>'Release changed']);
    header('Content-Type: application/vnd.android.package-archive');header('Content-Length: '.filesize($base.'.apk'));
    readfile($base.'.apk');exit;
}
$id=$in['id']??null;if(!validhex($id,32))answer(400,['error'=>'Invalid device']);
$request=$in['request']??null;
if($op!=='poll'&&!validhex($request,32))answer(400,['error'=>'Invalid request']);
if($op==='enqueue'&&!boxok($in['box']??null,16384))answer(400,['error'=>'Invalid command']);
if($op==='result'&&!boxok($in['box']??null,2800000))answer(400,['error'=>'Invalid result']);
// Authenticate against an existing catalog account; random tokens cannot create files.
$catalog=getenv('PHONE_EXIT_CATALOG_DATA')?:dirname($_SERVER['DOCUMENT_ROOT']).'/phone-exit-catalog-data';
$known=json_decode(@file_get_contents($catalog.'/'.$account.'.json')?:'',true);
if(!isset($known['devices'][$id]))answer(403,['error'=>'Unknown device']);
if(!is_dir($root)&&!@mkdir($root,0700,true))answer(503,['error'=>'Storage unavailable']);
$f=@fopen($root.'/'.$account.'.json','c+');
if(!$f||!flock($f,LOCK_EX|LOCK_NB))answer(503,['error'=>'Storage busy']);
@chmod($root.'/'.$account.'.json',0600);
$raw=stream_get_contents($f,8388609);if(strlen($raw)>8388608)answer(503,['error'=>'Storage limit']);
$jobs=json_decode($raw,true);if(!is_array($jobs))$jobs=[];
$now=time();$dirty=false;
foreach($jobs as $key=>&$job){
    if($job['created']<$now-120){unset($jobs[$key]);$dirty=true;continue;}
    if($job['status']==='queued'&&$job['created']<$now-60){$job['status']='expired';unset($job['command']);$dirty=true;}
}unset($job);
$key=$id.':'.$request;
if($op==='enqueue'){
    if(($known['devices'][$id]['updated']??0)<$now-45)answer(409,['error'=>'Device offline']);
    if(isset($jobs[$key])){answer(200,['id'=>$request,'status'=>$jobs[$key]['status']]);}
    $pending=0;$allPending=0;foreach($jobs as $j)if(in_array($j['status'],['queued','delivered'],true)){$allPending++;if($j['id']===$id)$pending++;}
    if($allPending>=32||$pending>=4)answer(429,['error'=>'Queue full']);
    // Consumed metadata does not occupy pending slots; bounded replay history remains.
    if(count($jobs)>=256){foreach($jobs as $k=>$j)if(!empty($j['consumed'])){unset($jobs[$k]);if(count($jobs)<256)break;}}
    if(count($jobs)>=256)answer(429,['error'=>'Result history full']);
    $jobs[$key]=['id'=>$id,'request'=>$request,'created'=>$now,'status'=>'queued','command'=>$in['box']];
    $dirty=true;
    $out=['id'=>$request,'status'=>'queued'];
}elseif($op==='poll'){
    $out=['job'=>null];
    foreach($jobs as &$j)if($j['id']===$id&&$j['status']==='queued'){
        $out=['job'=>['request'=>$j['request'],'box'=>$j['command']]];$j['status']='delivered';unset($j['command']);$dirty=true;break;
    }unset($j);
}elseif($op==='result'){
    if(!isset($jobs[$key])||!in_array($jobs[$key]['status'],['delivered','done'],true))answer(409,['error'=>'No delivered job']);
    if($jobs[$key]['status']!=='done'){$jobs[$key]['status']='done';$jobs[$key]['box']=$in['box'];$dirty=true;}
    $out=['ok'=>true];
}elseif($op==='ack'){
    if(!isset($jobs[$key])||$jobs[$key]['status']!=='done')answer(409,['error'=>'Result unavailable']);
    if(empty($jobs[$key]['consumed'])){unset($jobs[$key]['box']);$jobs[$key]['consumed']=true;$dirty=true;}$out=['ok'=>true];
}else{
    if(!isset($jobs[$key]))answer(404,['error'=>'Job expired or absent']);
    $out=['id'=>$request,'status'=>$jobs[$key]['status'],'box'=>$jobs[$key]['box']??null,'consumed'=>!empty($jobs[$key]['consumed'])];
}
if($dirty){
    $encoded=json_encode($jobs);if(strlen($encoded)>8388608)answer(413,['error'=>'Storage limit']);
    rewind($f);ftruncate($f,0);
    if(fwrite($f,$encoded)!==strlen($encoded)||!fflush($f))answer(503,['error'=>'Storage write failed']);
}
flock($f,LOCK_UN);fclose($f);answer(200,$out);
