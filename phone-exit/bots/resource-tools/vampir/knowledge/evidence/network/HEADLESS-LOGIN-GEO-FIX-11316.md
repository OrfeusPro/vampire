# Исправление игрового входа 1.13.16 через HK

25 октября 2026. Аккаунт `bot-hk-test@vampir.top`, JP / Franz 2,
server 256 / group 253. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.

## Ошибка клиента и результат

В `probe-lobby-sdk-login.py` добавление свежих `I_ConnectIP` и `I_CountryCD`
было вложено в условие `source_sha == METADATA_TID_SOURCE_SHA256`, которое
поддерживало только старый EXE. Поэтому `candidate-11316` успешно получал
GMC2, но не переносил его сетевые поля в metadata игрового Login.
Такой же состав полей уже оказался достаточным для принятого Login
[предыдущей сборки](../auth/HEADLESS-RELEASE-GMC2-GEO.md).

Теперь geo-поля используют отдельно проверенный набор `GEO_SOURCES` и тот же
короткоживущий `SdkInputs`, с совпадением SHA, аккаунта, маршрута и свежести.
`I_ConnectIP` берётся из GMC2 `clientIp`, `I_CountryCD` — из `geoLocation`,
а не из `isoCountry`. Сохраняются текущие правила sentinel A1/a1.
Значения адреса и страны не копируются из захвата и не записываются в отчёт.
TID guard сохранён: новая ветвь не читает и не генерирует I_TID.

На свободном HK Infinix X6525 поднят отдельный native WebRTC/SOCKS маршрут
loopback 17948. Для обеих попыток выбран launcher auth, язык 1, ClientVersion
262487 и `sdk-with-partial-metadata`. SDK joined country HK; SDK / lobby /
Game Version прошли. Каждая попытка использовала свежую авторизацию и GMC2.

| Ветка | Game Login | Список персонажей | Game send / recv |
| --- | --- | --- | --- |
| Initial Ping, прежний subset без geo | 16 / InvalidState | Не отправлен | 887 / 114 байт |
| Initial Ping + свежие I_ConnectIP / I_CountryCD | 0 | Получена одна запись | 946 / 460 байт |

Во второй ветке metadata — 267 байт; lobby send / recv — 814 / 11466 байт.
Исправление устранило отказ входа в проверенной попытке. Отдельная обязательность
каждого geo-поля, независимый эффект времени / новой авторизации и серверная
внутренняя причина InvalidState не изолированы. Код блокировки IP 58 не получен.
Создание, выбор, world entry и игровые команды не выполнялись; существующий
персонаж не заменялся. Сокеты и тестовый маршрут закрыты. Пароль передавался
через скрытый stdin; назначения, реальные профили и привязки не менялись.

Приватные сводки без credentials, адресов и raw bodies:

| Отчёт в F:/PhoneExit Resources/Vampir/live-checks/hk-20261025/ | SHA256 |
| --- | --- |
| hk-initial-ping-result.json | 0a8ec7c58a9dc04465f0152d943c36f8e0d29c005abe389bcbf20708ad3142b3 |
| hk-fresh-geo-result.json | f90d899718be10d725f1b94e2a0e12374b1100227a9c8f30e69ab06aa6548ddb |

CDN HTTPS manifest:
`6dde7ecb6ff6a029eb1828105517bd1c9630bec40d03fd92b2aa207481d46201`,
7632 байта. Предварительная попытка без нового Ping и geo приведена
[отдельно](HEADLESS-HK-EXISTING-CHARACTER-11316.md#повтор-по-запросу-пользователя-25-октября).

## Current clock / initial Ping

При переносе профиля также не подключался initial Ping из-за старого clock SHA.
Один этот дефект не объяснил отказ: live с initial Ping остался на коде 16.
Периодический heartbeat и world guards этим исправлением не расширены.
Явный `candidate-11316` теперь требует дополнительно два immutable native reports.

Кандидаты найдены [ограниченным поиском](../../../inspect-login-ping-candidates.py)
по historical prefix с масками RIP / относительных переходов. Это только поиск:
полные текущие roots экспортированы через prepare / collect и проверены отдельно.
Request `c1b0c39b3dfef7457a120cb51a3764b718a5ce3517b94818064e35a8409f3d34`;
экспорт `run-c1a78cdce3ea`, SHA
`668693173de2937329146b842edce0394664e4c66b438a36bd006c87e360e7b5`.
Пути и полный SHA закреплены в [карте экспорта](../../native-contexts/login-ping-exports-11316.json).

Первый collect завершился отказом Ghidra на tail JMP за unwind обработчика
лобби. В новом request явно добавлен target `145d5d010`: границы исходного
обработчика не расширялись. Отдельная ошибка замены общего search.sqlite3
устранена выбором собственного индекса исследования; чужие процессы не завершались.

| Native участок | Текущие адреса | Проверка |
| --- | --- | --- |
| Clock initialize / refresh / setter / tick | 1445d3d50 / 1445d9ed0 / 1445d7bc0 / 1445d7cb0 | 24 случая UTC epoch, leap date, signed minutes и раздельных server/local cache |
| UTC / platform / calendar | 14156acd0 / 1415da870 / 1415482f0 | Actual calendar arithmetic; OS GetSystemTime — fixture |
| Lobby handler / clock getter | 1467ab7a0 / 1445cd3c0 | 10 synthetic decoded packets; signed +38 и +30 server sample ведут в setter |
| Ping producer / readiness core | 1467cf680 / 144ab2280 | 36 случаев порога D > 5000, readiness, outstanding/recovery и tracking slots |
| Constructor / ID getter | 1456d7870 / 14140d380 | Actual vptr / ID 16 и поля N / N-last |

Native reports:
`code-clues/login-clock-11316/d9be90c721a67fc92d6692baa78cc0801fa6c237eeeb84c75662b75b639a175f/manifest.json`
и `code-clues/login-ping-11316/0cea49eb9a34d5993b03752fd3f7c4a071a3997815b3d6ea172aa46a5c82d216/manifest.json`.
Имя каждого каталога совпадает с полным SHA manifest. Хранятся вне Git.

Fixtures: GetSystemTime, valid-date month length, local offset cache, cookie,
контекст / mode, base update, send/recovery, cleanup, maintenance / manager / tail.
Clock handler получает synthetic decoded packet; полный lobby reader/dispatch
не исполнен. Native replay не доказывает активный factory, TCP-доставку или
необходимость Ping серверу. Новая живая попытка отдельно подтвердила Game Login.

```powershell
$env:PYTHONPATH='phone-exit/bots/vampir-shared;phone-exit/bots'
python -X utf8 -m unittest test_vampir_login_ping_11316 test_vampir_lobby_joined_country test_vampir_session_clock test_vampir_candidate_game_profile test_vampir_selected_game_login test_vampir_game_login_probe
```

74 теста прошли: native replay, повреждённый export, clock source guard,
current geo без неподтверждённого TID и локальная цепочка Login / списка.

Следующий шаг — перенос текущих selection / world / periodic heartbeat checks
и явный вход существующего персонажа после свежего принятого списка.
Отдельный эксперимент с исключением каждого geo-поля возможен только при новой
диагностической необходимости; рабочий состав не убирать ради повторения 16.
