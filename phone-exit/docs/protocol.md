# Протокол TCP v1

Сигнализация совместима с `webrtc-probe/signal.php`: HTTPS POST JSON,
token (64 hex), role pc/phone, op send/poll, after (курсор). offer/answer/candidate
содержат value в формате WebRTC. Комната нужна только для установки связи;
после открытия управляющего канала опрос останавливается. Срок сопряжения 10 мин.

ПК создаёт ordered/reliable DataChannel `phone-exit-control-v1` (без audio/video).
Телефон отвечает `{"type":"hello","version":1}`. Только после этого ПК
слушает SOCKS5 на 127.0.0.1. Транспорт — ICE/STUN + DTLS/SCTP, без TURN.
ПК каждые 2 с передаёт `{"type":"ping","id":"число"}`, телефон отвечает
`{"type":"pong","id":"то же число"}`. Без подтверждений ПК останавливает
прокси за 8–10 с, телефон без ping — за 12–14 с. При обычной остановке телефон
передаёт `{"type":"bye"}`; ПК также посылает bye перед закрытием, чтобы телефон
быстро вернулся в ожидание следующего соединения. Heartbeat не проходит через PHP.

Каждый SOCKS CONNECT создаёт канал `phone-exit-tcp-v1-<число>`.
Первое сообщение ПК: `{"type":"open","host":"example.com","port":443}`.
Телефон разрешает имя через Wi-Fi, проверяет все полученные адреса, открывает
TCP через socketFactory Wi-Fi и отвечает `{"type":"ready"}` или
`{"type":"error","code":1}`. До ready бинарные сообщения запрещены.

Бинарные кадры содержат TCP-байты (не более 16384). У каждой стороны окно
кредита 262144 байта. После записи кадра в TCP получатель отправляет
`{"type":"credit","bytes":N}`. Отправитель вычитает байты при отправке,
не превышает окно и не накапливает бесконечные очереди.

`{"type":"eof"}` означает завершение только направления отправителя.
После записи всех предыдущих кадров получатель делает shutdownOutput/end.
Обратное направление остаётся открытым. Закрытие TCP после обоих EOF закрывает
DataChannel; ошибочное/неожиданное закрытие DataChannel уничтожает TCP.

Максимум 32 TCP-канала, 1024 байта на JSON, таймаут открытия 15 с.
Адреса локальных сетей и служебные диапазоны не разрешены на Android.
BIND отклоняется. UDP согласуется отдельно через features в hello; старые APK
без udp-v1 продолжают отклонять UDP ASSOCIATE.

## UDP v1, APK 0.3.1

Hello сохраняет version=1 и добавляет features:["udp-v1"],
limits:{tcp:128,udp:64,mtu:1400}. Старый ПК игнорирует поля и продолжает TCP;
новый ПК ограничивает старый APK прежними 32 TCP-сокетами. Для нового APK
доступно 128 TCP и 64 UDP-ассоциации одновременно, 192 локальных SOCKS-сокета.

SOCKS5 UDP ASSOCIATE сохраняет управляющее TCP-соединение, возвращает локальный
IPv4 UDP-порт. Закрытие TCP завершает UDP. Первая допустимая датаграмма закрепляет
порт отправителя; принимается только 127.0.0.1, другие отправители игнорируются.
WebRTC канал phone-exit-udp-v1-N: ordered=false, maxRetransmits=0. Открытие
JSON {type:"open"}, повтор каждые 500 мс до {type:"ready"}; таймаут 15 секунд.

Бинарный кадр — SOCKS5 UDP envelope: RSV=0, FRAG=0, ATYP, адрес, порт, payload.
Адрес IPv4/IPv6/ASCII-domain. Один кадр — одна датаграмма, максимум 1400 байт.
Фрагментация не поддерживается; пустые, большие или ошибочные пакеты отбрасываются.
Буфер WebRTC ограничен 64 КиБ; переполнение отбрасывает пакет, не блокирует TCP.
Android отправляет через DatagramSocket, привязанный к физическому Wi-Fi;
DNS идёт через ту же сеть. Private/link-local/multicast назначения запрещены.
До 32 адресов назначения на ассоциацию, запись живёт 60 секунд после отправки;
ответ принимается только с адреса и порта, куда ранее отправляли. Очередь
отправки 64 пакета. Readers UDP отделены от блокирующего пула TCP.
Освобождение JNI observers/channel/peer/factory выполняется последовательно
отдельным executor после выхода из callbacks, без отложенного unregister
после уничтожения peer. Это устраняет наблюдавшийся native SIGSEGV на vivo.

## Приватный каталог v1 и привязка v2

Код привязки: JSON version=2, mode=directory, signal (тот же HTTPS endpoint),
id (32 hex), name (1–40 символов), token (64 hex, постоянный ключ устройства).
Он передаётся один раз пользователем; хранение защищено DPAPI/Android Keystore.

`bucket=floor(unixMilliseconds/300000)`;
ключ комнаты = HMAC-SHA256(key=hexDecode(token),
message=UTF8("phone-exit-directory-v1:" + bucket)), нижний hex.
Опрос текущего и предыдущего периода, курсор отдельный для каждого ключа.
Внешний формат существующего PHP: type=candidate, value — метаданные каталога.
Это отдельные комнаты; метаданные никогда не передаются в WebRTC как ICE.

Телефон → ПК: value {directory:1,type:"presence",at:unixMilliseconds,
country:"UA" или "",busy:boolean}. Каждые 15 с, TTL 45 с.
ПК → телефон: value {directory:1,type:"connect",at:unixMilliseconds,
request:32hex,pairing:{version:1,signal,token:новый64hex}}.
Телефон принимает только свежие запросы и не исполняет повтор request;
при занятом выходе новый запрос не заменяет уже подключённый ПК.
Далее используется прежний протокол TCP v1 в отдельной одноразовой комнате.
Опрос каталога продолжается и во время TCP-сессии; трафик через PHP не идёт.

## Персональная регистрация v2 без кодов

APK asset `phone-exit-account.json` (только в игнорируемой сборке) содержит version=1,
signal, feedToken=64hex, publicKey=base64 EC P-256 SPKI. Закрытого ключа ПК в APK нет.
ПК хранит public/private PKCS8/SPKI, feedToken и blocked ids в DPAPI account.bin.
APK даёт право регистрации в этот личный список; публичное распространение не входит
в разрешённый режим. Каждый телефон создаёт отдельные id=32hex и token=64hex.

Комната регистрации: HMAC-SHA256(hexDecode(feedToken),
UTF8("phone-exit-registration-v1:"+floor(unixMilliseconds/300000))).
Телефон посылает candidate.value={directory:2,type:"register",box:{ephemeral,iv,data}}.
ephemeral=base64 SPKI нового EC P-256 ключа, key=SHA256(ECDH(ephemeralPrivate,PCPublic));
iv=12 случайных байт, data=base64 AES-256-GCM(ciphertext||16-byte-tag),
AAD=UTF8("phone-exit-registration-v1"). Зашифрованный JSON:
{id,name,token,at:unixMilliseconds,country,busy}. Регистрация каждые 15 с.
ПК расшифровывает только своим закрытым ключом; свежесть 45 с. Неверный аккаунт,
повреждённый GCM, старые сообщения, заблокированный id и смена ключа существующего
id отклоняются. Новый допустимый id автоматически сохраняется в список (макс. 4).
Удаление id из ПК добавляет его в blocked; APK-переустановка создаёт новую личность.
Подключение использует прежнюю отдельную комнату per-phone и свежий session token v1.
