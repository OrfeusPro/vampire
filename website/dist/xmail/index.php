<?php
declare(strict_types=1);
require_once dirname(__DIR__,2).'/xmail-backend.php';
try {
    xm_begin();
    $path=parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH);
    if($path==='/xmail'){header('Location: /xmail/',true,301);exit;}
    if($path==='/xmail/api'){xm_api();}
    if($path!=='/xmail/'&&$path!=='/xmail/index.php'){http_response_code(404);exit;}
    $authenticated=!empty($_SESSION['xm_auth']);if($authenticated)$_SESSION['xm_seen']=time();
    $csrf=$_SESSION['xm_csrf'];session_write_close();
}catch(Throwable $error){header('Content-Type: application/json; charset=utf-8');$allowed=['imap_connect','imap_greeting','imap_write','imap_timeout','imap_read','imap_literal','imap_command','message_too_large','message_missing','folder_changed','mime_limits','invalid_account','invalid_folder','not_configured'];$code=in_array($error->getMessage(),$allowed,true)?$error->getMessage():'server_error';xm_json(['error'=>$code],503);}
?>
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><meta name="csrf-token" content="<?= htmlspecialchars($csrf,ENT_QUOTES) ?>"><title>XMail · VAMPIR.TOP</title><link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="/xmail/xmail.css?v=<?= filemtime(__DIR__.'/xmail.css') ?>"><script src="/xmail/xmail.js?v=<?= filemtime(__DIR__.'/xmail.js') ?>" defer></script></head>
<body data-authenticated="<?= $authenticated?'yes':'no' ?>">
<?php if(!$authenticated): ?>
<main class="login-wrap"><section class="login-card"><div class="brand">◇ <span>XMAIL<small>VAMPIR.TOP</small></span></div><p class="eyebrow">ЛИЧНАЯ ПОЧТА</p><h1>Все ящики.<br>Один вход.</h1><p class="muted">Закрытая почта VAMPIR.TOP</p><form id="login-form"><label>Логин<input name="username" autocomplete="username" required maxlength="64" autofocus></label><label>Пароль<input name="password" type="password" autocomplete="current-password" required maxlength="128"></label><button class="primary" type="submit">Войти</button><p id="login-error" role="alert"></p></form></section></main>
<?php else: ?>
<header class="topbar"><a class="brand" href="/xmail/">◇ <span>XMAIL<small>VAMPIR.TOP</small></span></a><div class="top-actions"><span id="sync-status" role="status">Подключаем ящики…</span><button id="refresh">Обновить</button><button id="logout">Выйти</button></div></header>
<main class="workspace"><aside class="sidebar"><p class="eyebrow">ПОЧТОВЫЕ ЯЩИКИ</p><button id="all-accounts" class="account active">Все ящики <span id="account-count"></span></button><div id="accounts"></div><p class="privacy-note">Автообновление каждые 30 секунд, пока вкладка видима. Письма на сервере не изменяются.</p></aside>
<section class="mailbox"><div class="mailbox-head"><div><p class="eyebrow">ВХОДЯЩИЕ И ПАПКИ</p><h1 id="mailbox-title">Вся почта</h1></div><span id="message-count"></span></div><div class="filters"><label class="search-label">Поиск в загруженных письмах<input id="search" type="search" placeholder="Тема, отправитель, ящик…"></label><label>Папка<select id="folder-filter"><option value="">Все папки</option></select></label><label>Показать<select id="read-filter"><option value="">Все письма</option><option value="unread">Непрочитанные</option></select></label></div><p id="list-info" class="muted">Загружаем последние письма из всех папок…</p><div id="messages" class="messages"></div><button id="load-more" hidden>Загрузить более ранние письма</button></section>
<section id="reader" class="reader" aria-label="Просмотр письма"><div class="empty-reader"><span>◇</span><h2>Выберите письмо</h2><p>Оно откроется здесь без внешних картинок и скриптов.</p></div></section></main>
<?php endif; ?></body></html>
