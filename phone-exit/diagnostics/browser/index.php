<?php
header('Cache-Control: no-store');
header('Content-Type: text/html; charset=utf-8');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
?><!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phone Exit · проверка Chrome</title>
<style>body{background:#101722;color:#e9f1fa;font:17px/1.5 system-ui;margin:0;padding:24px}main{max-width:660px;margin:auto}h1{font-size:26px}section{background:#1b2939;padding:20px;border-radius:18px;margin:18px 0}button{background:#57dfbb;color:#092620;border:0;border-radius:12px;padding:14px 20px;font:inherit;margin:8px 8px 0 0}button:disabled{opacity:.5}textarea{box-sizing:border-box;width:100%;background:#101722;color:white;border:1px solid #596b7c;border-radius:8px;padding:10px;font:inherit}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.5 monospace}.muted{color:#adbdcf}</style>
<main><h1>Проверка WebRTC в Chrome</h1>
<p>Открой эту страницу на UgPhone. Тест сравнит Chrome с приложением Phone Exit на той же сети.</p>
<section><label for="link">Ссылка проверки с ПК</label><textarea id="link" rows="2" autocomplete="off" spellcheck="false" placeholder="Вставь ссылку из файла на ПК"></textarea>
<p class="muted">Нужна отдельная ссылка сопряжения. Она действует 10 минут. Не отправляй её посторонним.</p>
<button id="start">Начать проверку</button><button id="stop" disabled>Остановить</button></section>
<section role="status" aria-live="polite"><strong id="status">Готов к проверке</strong><pre id="report"></pre></section>
<p class="muted">Камера и микрофон не нужны. Только пять проверочных сообщений по защищённому WebRTC. Без VPN, SOCKS и TURN. Проверяются UDP-кандидаты IPv4; успех не подтверждает работу всех игр или длительную стабильность. Сеть, разрешения и настройки не меняются.</p>
<p class="muted">HTTPS передаёт служебные SDP/ICE только в тестовой комнате. В отчёт не записываются IP, SDP, ключи или содержимое пользовательского трафика. Не закрывай Chrome во время проверки: до 90 секунд после ответа ПК.</p>
<p class="muted">Для нового прогона обнови страницу и используй новую ссылку с ПК.</p>
<script type="module" src="probe.js"></script></main></html>
