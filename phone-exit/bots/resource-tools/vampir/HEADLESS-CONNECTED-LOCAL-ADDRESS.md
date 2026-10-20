# Локальный адрес соединения в Version и граница SOCKS

20 октября 2026. Продолжение [проверки страны сервера](HEADLESS-SERVER-COUNTRY-POLICY.md).
Источник — код и данные Windows-клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Исправленное различие

Прежний runner передавал в Version результат connection.getsockname()[0].
На PySocks-сокете это адрес подключения Windows к локальному прокси —
127.0.0.1. Это не наблюдённый локальный адрес исходящего соединения телефона
с игровым сервером. PySocks отдельно предоставляет get_proxy_sockname(),
содержащий BND.ADDR / BND.PORT из ответа SOCKS CONNECT.

Текущий Phone Exit в pc/src/socks.js возвращает для успешного TCP CONNECT
фиксированные 0.0.0.0:0. Адрес исходящего Android-сокета этот ответ не передаёт.
Нельзя объявлять эти нули или loopback адресом игрового соединения и нельзя
подставлять публичный IP, страну выхода или произвольный адрес.

Добавленный socks_game_address_context использует только SOCKS bound metadata.
При неизвестном endpoint возвращает address=None; Version builder кодирует
его пустой строкой. При конкретном допустимом IPv4 / ненулевом порте сохраняет
этот наблюдённый адрес. Loopback, link-local, multicast и unspecified также
считаются неподдерживаемым контекстом; неверная форма metadata отклоняется.
IPv6 / DNS в IPv4 metadata не преобразуются. Адрес скрыт в repr; диагностика
сохраняет только source socks_bound_ipv4 / socks_bound_unavailable.

Это политика нашего SOCKS-клиента для виртуального соединения. Она не означает,
что в игре обнаружена поддержка SOCKS или что её getsockname действительно
завершался ошибкой в живой сессии. Правки Phone Exit / Android не потребовались.

## Проверка native-ветвей

Ранее экспортированные Ghidra-функции Socket_ConnectedEndpoint 0x1445e7680,
Transport_ConnectedInputs 0x144aac520 и подготовка Version 0x1467a9cd0
сопоставлены с инструкциями. Getter вызывает getsockname, затем inet_ntoa,
сохраняет текст и порт после ntohs. Успех устанавливает AL=1 на 0x1445e7782;
ошибка устанавливает AL=0 на 0x1445e7797. Псевдокод Ghidra ошибочно показывает
возвращаемый тип void; caller реально проверяет AL.

При ошибке transport callback пропускает перенос адреса и передаёт заранее
пустой FString через connection delegate. Подготовка Version сохраняет его
по packet+0x58. Это не remote peer address и не результат getpeername.

[replay-connected-local-address.py](replay-connected-local-address.py)
исполняет настоящий getter, callback, delegate, подготовку и constructor
Version на одних fixture objects. Пять сценариев:

- Успешный getsockname с loopback, private IPv4, documentation IPv4 и
  0.0.0.0 переносит соответствующий текст без замены в Version+0x58.
- Ошибка getsockname переносит пустую строку, а не предыдущий адрес.

Winsock getsockname / inet_ntoa / ntohs — fixtures. Их IAT ordinals проверены
по закреплённому в прежнем отчёте WS2_32.dll с проверкой SHA. SSO / FString
memory helpers и преобразование ASCII IPv4 в UTF-16 — ограниченные fixtures.
Унаследованные readiness / scheduler / ownership fixtures сохранены; Version
sender захвачен. Сеть, игра, профиль и реальные адреса в replay не используются.
Getter accessor 0x141408910 проверен как пять bytes LEA [RCX+8] / RET.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/connected-local-address-replay.json`.
SHA256: `931fdc838530a3003d4ef2af3063a9307ee90aab23e8cf4d1d0a1a4cd05817c2`.
Источник Ghidra: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-258411d5e987`,
366 функций / 172 предупреждения. functions.json SHA256:
`eef1fe17b98fda70d66ffefb18bb13ec994e2c6207b731fd8532c1cb4383a7be`.
Новых seeds и повторной декомпиляции не потребовалось.

## Реальная проверка на том же JP-сервере

Через подтверждённый JP-выход заново пройдены SDK / lobby вход и ID 104.
SDK country HK проходит array50 всех 20 JP-записей. Явно выбран server ID 251 /
group ID 251. Game address source — socks_bound_unavailable, то есть поле
Version+0x58 пустое. Получены VersionResult 0 и LoginResult 58 / BlockedIp,
body 131 байт. Игровой обмен — 641 байт отправлено / 94 получено; уменьшение
на девять отправленных байт соответствует удалённому тексту 127.0.0.1.

Прежняя версия с loopback отправляла 650 байт. Замена loopback на пустой
контекст отказ не устранила. Это не доказывает, что сервер не проверяет
правильный адрес, и не устанавливает географическую / ASN / другую причину.
Список персонажей не отправлен. Сокеты закрыты, временный JP-клиент завершён
с exit 0, stderr пуст. Новых маршрутов или автоматических повторов не добавлено.

Снимки в `F:/PhoneExit Resources/Vampir`:

- `public-cdn-snapshots/3b24e1a96354043f9f1155ce59ff9b67c701a33b6f6b40629a2ceaa571c90f05/manifest.json`, 6000 байт.
- `public-gmc2-snapshots/625225089f45c588c035cf7aae9564589cb775008b0c55579e373aa58388cdc6/manifest.json`, HTTP 200, 13 773 байта.

## Проверки и продолжение

Прошли четыре local address, три Login runner, четыре selected Version,
четыре SOCKS route с реальным локальным SOCKS / TLS и пять Version probe —
всего 20 проверок. Проверены воспроизведение native-отчёта, пустое поле Version,
изолированное изменение этого поля, использование bound metadata без чтения
proxy hop, скрытый repr и отклонение неподдерживаемых metadata.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-connected-local-address.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_connected_local_address.py
```

Далее — оставшиеся условия доступности выбранного сервера и полный контекст
Login до успешного входа, списка / выбора персонажа и позиции. Не объявлять
проверенные state / country / Version достаточными для успешной игровой сессии.
