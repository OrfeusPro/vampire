<?php
declare(strict_types=1);

final class XMailImap {
    private $socket;
    private int $tag = 0;
    public function __construct(array $account) {
        $context=stream_context_create(['ssl'=>['verify_peer'=>true,'verify_peer_name'=>true,'peer_name'=>'mail.vampir.top']]);
        $this->socket=@stream_socket_client('ssl://mail.vampir.top:993',$code,$error,8,STREAM_CLIENT_CONNECT,$context);
        if (!$this->socket) throw new RuntimeException('imap_connect');
        stream_set_timeout($this->socket,12);
        $greeting=fgets($this->socket,8192);
        if (!is_string($greeting)||!str_starts_with($greeting,'* OK')) throw new RuntimeException('imap_greeting');
        $this->command('LOGIN '.self::quote($account['email']).' '.self::quote($account['password']));
    }
    public static function quote(string $text): string {
        if(preg_match('/[\x00\r\n]/',$text)) throw new RuntimeException('invalid_imap_string');
        return '"'.str_replace(['\\','"'],['\\\\','\\"'],$text).'"';
    }
    public function command(string $command): array {
        $tag='X'.(++$this->tag);$wire=$tag.' '.$command."\r\n";$offset=0;
        while($offset<strlen($wire)){ $n=fwrite($this->socket,substr($wire,$offset));if(!$n)throw new RuntimeException('imap_write');$offset+=$n; }
        $records=[];$current='';$literal=null;$total=0;$deadline=microtime(true)+20;
        while(true){
            if(microtime(true)>$deadline)throw new RuntimeException('imap_timeout');
            $line=fgets($this->socket,65536);
            if($line===false)throw new RuntimeException('imap_read');
            $total+=strlen($line);if($total>16000000)throw new RuntimeException('message_too_large');
            if(str_starts_with($line,$tag.' ')){
                if(!str_starts_with($line,$tag.' OK'))throw new RuntimeException('imap_command');
                return $records;
            }
            $current.=$line;
            if(preg_match('/\{(\d+)\}\r\n$/D',$line,$match)){
                $length=(int)$match[1];if($length>12000000||$total+$length>16000000)throw new RuntimeException('message_too_large');
                $bytes='';while(strlen($bytes)<$length){if(microtime(true)>$deadline)throw new RuntimeException('imap_timeout');$chunk=fread($this->socket,min(65536,$length-strlen($bytes)));if($chunk===false||$chunk==='')throw new RuntimeException('imap_literal');$bytes.=$chunk;}
                $total+=$length;$literal=$bytes;continue;
            }
            $records[]=['line'=>$current,'literal'=>$literal];$current='';$literal=null;
        }
    }
    public function folders(): array {
        $folders=[];
        foreach($this->command('LIST "" "*"') as $record){
            $line=$record['line'];
            if(!preg_match('/^\* LIST \(([^)]*)\) (?:NIL|"(?:[^"\\\\]|\\\\.)*") (.+)\r\n$/isD',$line,$m))continue;
            if(stripos($m[1],'\\Noselect')!==false)continue;
            $name=$record['literal'];
            if($name===null){$name=trim($m[2]);if(str_starts_with($name,'"'))$name=preg_replace('/\\\\(.)/s','$1',substr($name,1,-1));}
            $label=function_exists('mb_convert_encoding')?@mb_convert_encoding($name,'UTF-8','UTF7-IMAP'):$name;
            $folders[]=['id'=>rtrim(strtr(base64_encode($name),'+/','-_'),'='),'name'=>$label?:$name];
        }
        usort($folders,static fn($a,$b)=>(strcasecmp($a['name'],'INBOX')===0?-1:1)<=>(strcasecmp($b['name'],'INBOX')===0?-1:1)?:strcasecmp($a['name'],$b['name']));
        return $folders;
    }
    public function examine(string $folder): array {
        $validity=0;$count=0;
        foreach($this->command('EXAMINE '.self::quote($folder)) as $record){
            if(preg_match('/UIDVALIDITY (\d+)/',$record['line'],$m))$validity=(int)$m[1];
            if(preg_match('/^\* (\d+) EXISTS/',$record['line'],$m))$count=(int)$m[1];
        }
        if(!$validity)throw new RuntimeException('imap_validity');
        return ['validity'=>$validity,'total'=>$count];
    }
    public function messages(string $folder,int $page): array {
        $status=$this->examine($folder);$end=$status['total']-$page*50;
        if($end<1)return $status+['messages'=>[],'more'=>false];
        $start=max(1,$end-49);$messages=[];
        foreach($this->command('FETCH '.$start.':'.$end.' (UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE MESSAGE-ID)])') as $record){
            if($record['literal']===null||!preg_match('/\bUID (\d+)/',$record['line'],$uid))continue;
            $headers=xmail_headers($record['literal']);$date=$headers['date']??'';
            preg_match('/INTERNALDATE "([^"]+)"/',$record['line'],$internal);
            $messages[]=['uid'=>(int)$uid[1],'validity'=>$status['validity'],'subject'=>xmail_decode_header($headers['subject']??'(Без темы)'),
                'from'=>xmail_decode_header($headers['from']??''),'to'=>xmail_decode_header($headers['to']??''),'date'=>$date,
                'timestamp'=>strtotime($internal[1]??$date)?:0,'unread'=>!preg_match('/FLAGS \([^)]*\\\\Seen\b/i',$record['line'])];
        }
        return $status+['messages'=>array_reverse($messages),'more'=>$start>1];
    }
    public function message(string $folder,int $uid,int $validity): string {
        $status=$this->examine($folder);if($status['validity']!==$validity)throw new RuntimeException('folder_changed');
        $records=$this->command('UID FETCH '.$uid.' (RFC822.SIZE)');
        $size=null;foreach($records as $r)if(preg_match('/RFC822.SIZE (\d+)/',$r['line'],$m))$size=(int)$m[1];
        if($size===null)throw new RuntimeException('message_missing');if($size>12000000)throw new RuntimeException('message_too_large');
        foreach($this->command('UID FETCH '.$uid.' (BODY.PEEK[])') as $r)if($r['literal']!==null)return $r['literal'];
        throw new RuntimeException('message_missing');
    }
    public function __destruct(){if(is_resource($this->socket))fclose($this->socket);}
}
function xmail_headers(string $raw): array {
    $raw=preg_replace('/\r?\n[ \t]+/',' ',$raw);$result=[];
    foreach(preg_split('/\r?\n/',$raw) as $line)if(preg_match('/^([A-Za-z0-9-]+):\s*(.*)$/D',$line,$m))$result[strtolower($m[1])]=$m[2];
    return $result;
}
function xmail_decode_header(string $text): string {
    $decoded=@iconv_mime_decode($text,ICONV_MIME_DECODE_CONTINUE_ON_ERROR,'UTF-8');
    return $decoded===false?mb_convert_encoding($text,'UTF-8','UTF-8,Windows-1251,ISO-8859-1'):$decoded;
}
function xmail_parameter(string $header,string $name): string {
    if(preg_match('/(?:^|;)\s*'.preg_quote($name,'/').'\*\s*=\s*([^;]+)/i',$header,$m)){
        $v=trim($m[1]," \t\"");if(preg_match("/^([^']*)'[^']*'(.*)$/s",$v,$p))return @iconv($p[1]?:'UTF-8','UTF-8//IGNORE',rawurldecode($p[2]))?:rawurldecode($p[2]);
    }
    if(preg_match('/(?:^|;)\s*'.preg_quote($name,'/').'\s*=\s*(?:"((?:[^"\\\\]|\\\\.)*)"|([^;\s]+))/i',$header,$m))return xmail_decode_header(preg_replace('/\\\\(.)/s','$1',($m[1]??'')!==''?$m[1]:($m[2]??'')));
    return '';
}
function xmail_parse_message(string $raw): array {
    $texts=[];$html=[];$attachments=[];$parts=0;
    $walk=function(string $raw,int $depth=0)use(&$walk,&$texts,&$html,&$attachments,&$parts){
        if($depth>12||++$parts>150)throw new RuntimeException('mime_limits');
        $pair=preg_split('/\r?\n\r?\n/',$raw,2);$headers=xmail_headers($pair[0]);$body=$pair[1]??'';
        $typeHeader=$headers['content-type']??'text/plain';$type=strtolower(trim(explode(';',$typeHeader)[0]));
        if(str_starts_with($type,'multipart/')){
            $boundary=xmail_parameter($typeHeader,'boundary');if(!$boundary)return;
            $pieces=preg_split('/^--'.preg_quote($boundary,'/').'(?:--)?[ \t]*\r?$/m',$body);
            foreach(array_slice($pieces,1,-1) as $part)$walk(ltrim($part,"\r\n"),$depth+1);
            return;
        }
        $encoding=strtolower($headers['content-transfer-encoding']??'');
        if($encoding==='base64')$body=base64_decode(preg_replace('/\s/','',$body),true)?:'';
        elseif($encoding==='quoted-printable')$body=quoted_printable_decode($body);
        $disposition=$headers['content-disposition']??'';
        $filename=xmail_parameter($disposition,'filename')?:xmail_parameter($typeHeader,'name');
        if($filename||str_starts_with(strtolower($disposition),'attachment')||!in_array($type,['text/plain','text/html'],true)){
            $attachments[]=['name'=>$filename?:'attachment','size'=>strlen($body),'data'=>$body];return;
        }
        $charset=xmail_parameter($typeHeader,'charset')?:'UTF-8';
        $body=@iconv($charset,'UTF-8//IGNORE',$body)?:mb_convert_encoding($body,'UTF-8','UTF-8');
        if($type==='text/plain')$texts[]=$body;
        else{
            $body=preg_replace('~<(script|style|head)\b[^>]*>.*?</\1>~is','',$body);
            $body=preg_replace_callback('~<a\b[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>~is',static fn($m)=>strip_tags($m[2]).' ['.$m[1].']',$body);
            $body=preg_replace('~<(?:br\b[^>]*|/(?:p|div|tr|h[1-6]))>~i',"\n",$body);
            $html[]=html_entity_decode(strip_tags($body),ENT_QUOTES|ENT_HTML5,'UTF-8');
        }
    };
    $walk($raw);
    return ['headers'=>xmail_headers(preg_split('/\r?\n\r?\n/',$raw,2)[0]),'text'=>implode("\n\n",$texts?:$html),'attachments'=>$attachments];
}
