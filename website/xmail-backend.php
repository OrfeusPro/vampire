<?php
declare(strict_types=1);
require_once __DIR__.'/xmail-imap.php';

function xm_config(): array {
    static $config;
    if($config===null){$path=__DIR__.'/xmail.local.php';if(!is_file($path))throw new RuntimeException('not_configured');$config=require $path;}
    return $config;
}
function xm_json(array $data,int $status=200): never { http_response_code($status);echo json_encode($data,JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);exit; }
function xm_begin(): void {
    header('Cache-Control: no-store, private');header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');header('Referrer-Policy: no-referrer');header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    $host=strtolower(explode(':',$_SERVER['HTTP_HOST']??'')[0]);
    $secure=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')||(int)($_SERVER['SERVER_PORT']??0)===443;
    if(!in_array($host,['127.0.0.1','localhost','vampir.local'],true)&&!$secure){header('Location: https://vampir.top/xmail/',true,302);exit;}
    ini_set('session.use_strict_mode','1');ini_set('session.use_only_cookies','1');
    session_name('VAMPIR_XMAIL');session_set_cookie_params(['lifetime'=>0,'path'=>'/xmail/','secure'=>$secure,'httponly'=>true,'samesite'=>'Strict']);session_start();
    if(!empty($_SESSION['xm_auth'])&&(time()-($_SESSION['xm_seen']??0)>1800||time()-($_SESSION['xm_started']??0)>28800))$_SESSION=[];
    if(empty($_SESSION['xm_csrf']))$_SESSION['xm_csrf']=bin2hex(random_bytes(32));
}
function xm_auth(): void {
    if(empty($_SESSION['xm_auth']))xm_json(['error'=>'auth_required'],401);
    $_SESSION['xm_seen']=time();
}
function xm_csrf(): void {
    if(!hash_equals($_SESSION['xm_csrf'],$_SERVER['HTTP_X_CSRF_TOKEN']??''))xm_json(['error'=>'csrf'],403);
}
function xm_private_dir(): string {
    $dir=__DIR__.'/var/xmail';if(!is_dir($dir)&&!@mkdir($dir,0700,true)&&!is_dir($dir))throw new RuntimeException('storage');return $dir;
}
/** Locked limiter shared by browser sessions. No usernames, IPs or passwords in state. */
function xm_login_limit(bool $clear=false): bool {
    $key=hash_hmac('sha256',$_SERVER['REMOTE_ADDR']??'unknown',xm_config()['salt']);
    $file=fopen(xm_private_dir().'/login-'.$key.'.json','c+');if(!$file||!flock($file,LOCK_EX))throw new RuntimeException('storage');
    $events=json_decode(stream_get_contents($file)?:'[]',true);
    $events=array_values(array_filter(is_array($events)?$events:[],static fn($t)=>is_int($t)&&$t>time()-900));
    $ok=count($events)<8;if($clear)$events=[];elseif($ok)$events[]=time();
    rewind($file);ftruncate($file,0);fwrite($file,json_encode($events));flock($file,LOCK_UN);fclose($file);return $ok;
}
function xm_account(string $id): array {
    foreach(xm_config()['accounts'] as $account)if($account['id']===$id)return $account;
    throw new RuntimeException('invalid_account');
}
function xm_cache(string $key,int $ttl,callable $fetch): array {
    $path=xm_private_dir().'/cache-'.hash_hmac('sha256',$key,xm_config()['salt']).'.json';
    $handle=fopen($path,'c+');if(!$handle||!flock($handle,LOCK_EX))throw new RuntimeException('storage');
    try{
        $cached=json_decode(stream_get_contents($handle)?:'[]',true);
        if(($cached['at']??0)>time()-$ttl)return $cached['data'];
        $data=$fetch();rewind($handle);ftruncate($handle,0);fwrite($handle,json_encode(['at'=>time(),'data'=>$data],JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR));@chmod($path,0600);return $data;
    }finally{flock($handle,LOCK_UN);fclose($handle);}
}
function xm_folders(array $account): array {
    return xm_cache('folders:'.$account['id'],300,static function()use($account){$imap=new XMailImap($account);return $imap->folders();});
}
function xm_folder(array $account,string $id): string {
    foreach(xm_folders($account) as $folder)if($folder['id']===$id)return base64_decode(strtr($id,'-_','+/'),true);
    throw new RuntimeException('invalid_folder');
}
function xm_api(): never {
    header('Content-Type: application/json; charset=utf-8');
    if(($_SERVER['REQUEST_METHOD']??'')!=='POST')xm_json(['error'=>'method'],405);
    xm_csrf();
    if((int)($_SERVER['CONTENT_LENGTH']??0)>4096)xm_json(['error'=>'too_large'],413);
    $data=json_decode(file_get_contents('php://input',false,null,0,4097),true);
    if(!is_array($data))xm_json(['error'=>'invalid_json'],400);
    $action=$data['action']??'';
    if($action==='login'){
        if(!xm_login_limit())xm_json(['error'=>'login_limit'],429);
        $config=xm_config();$user=$data['username']??null;$password=$data['password']??null;
        if(!is_string($user)||!is_string($password)||strlen($password)>128||strlen($user)>64||!password_verify($password,$config['password_hash'])||!hash_equals($config['username'],$user))xm_json(['error'=>'invalid_login'],401);
        xm_login_limit(true);session_regenerate_id(true);$_SESSION['xm_auth']=true;$_SESSION['xm_started']=$_SESSION['xm_seen']=time();$_SESSION['xm_csrf']=bin2hex(random_bytes(32));xm_json(['ok'=>true]);
    }
    xm_auth();
    if($action==='logout'){$_SESSION=[];session_destroy();setcookie(session_name(),'', ['expires'=>1,'path'=>'/xmail/','secure'=>!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off','httponly'=>true,'samesite'=>'Strict']);xm_json(['ok'=>true]);}
    // Release session lock before IMAP requests so different mailboxes can refresh concurrently.
    session_write_close();
    if($action==='accounts')xm_json(['accounts'=>array_map(static fn($a)=>['id'=>$a['id'],'email'=>$a['email']],xm_config()['accounts'])]);
    $account=xm_account(is_string($data['account']??null)?$data['account']:'');
    if($action==='folders')xm_json(['folders'=>xm_folders($account)]);
    $folderId=is_string($data['folder']??null)?$data['folder']:'';$folder=xm_folder($account,$folderId);
    if($action==='messages'){
        $page=filter_var($data['page']??0,FILTER_VALIDATE_INT,['options'=>['min_range'=>0,'max_range'=>100000]]);if($page===false)xm_json(['error'=>'invalid_page'],422);
        $list=xm_cache('messages:'.$account['id'].':'.$folderId.':'.$page,25,static function()use($account,$folder,$page){$imap=new XMailImap($account);return $imap->messages($folder,$page);});
        xm_json($list+['checked_at'=>gmdate('c')]);
    }
    if($action==='message'||$action==='attachment'){
        $uid=filter_var($data['uid']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>4294967295]]);
        $validity=filter_var($data['validity']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>4294967295]]);
        if(!$uid||!$validity)xm_json(['error'=>'invalid_message'],422);
        $imap=new XMailImap($account);$mail=xmail_parse_message($imap->message($folder,$uid,$validity));
        if($action==='attachment'){
            $index=filter_var($data['attachment']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>0,'max_range'=>149]]);
            if($index===false||!isset($mail['attachments'][$index]))xm_json(['error'=>'invalid_attachment'],422);
            $attachment=$mail['attachments'][$index];
            header('Content-Type: application/octet-stream');header("Content-Disposition: attachment; filename=attachment; filename*=UTF-8''".rawurlencode(preg_replace('/[\x00-\x1f\x7f\/\\\\]/','_',$attachment['name'])));echo $attachment['data'];exit;
        }
        $headers=$mail['headers'];xm_json(['subject'=>xmail_decode_header($headers['subject']??'(Без темы)'), 'from'=>xmail_decode_header($headers['from']??''),'to'=>xmail_decode_header($headers['to']??''),'date'=>xmail_decode_header($headers['date']??''),'text'=>$mail['text'],'attachments'=>array_map(static fn($a)=>['name'=>$a['name'],'size'=>$a['size']],$mail['attachments'])]);
    }
    xm_json(['error'=>'unknown_action'],400);
}
