# Отдельный владелец сессий Windows

26 октября 2026. Проверка выполнялась с текущим EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это изменение запуска Python-процесса, не новая роль native-функции игры.
Причина: пользователь перезапустил Codex, после чего прежний owner / API /
транспорт исчезли. [Прежние живые данные](../scenarios/HEADLESS-LIVE-TUTORIAL-11316.md).

## Запуск и управление

run-live-sessions.py --detached создаёт Windows-процесс с DETACHED_PROCESS,
CREATE_NEW_PROCESS_GROUP и CREATE_BREAKAWAY_FROM_JOB. Отказ breakaway завершает
запуск ошибкой; перехода к обычному дочернему процессу нет. Параметры и пароли
передаются только через ограниченный anonymous stdin pipe, максимум 1 MiB.
Пароли не попадают в argv, accounts JSON, stdout, API или файлы результата.
Проверенные источники / profile / собственные session IDs остаются прежними.

До начала SDK-входов child создаёт loopback API и отправляет единственное
ограниченное readiness сообщение: собственный PID, sessions и UI URLs.
Parent проверяет PID и формат. Далее stdout child направлен в NUL, startup
pipe закрыт. Поэтому выход parent не ломает последующие emit и игровую сессию.
Status ready означает готовность API, не вход в игровой мир.
Read / write handshake ограничены timeout; при ошибке startup процесс закрывается.

В отдельном режиме lifetime — 86400 секунд. Timer закрывает registry и все
входящие в него sessions; обычный режим сохраняет прежнее поведение без этого
таймера. Stop конкретной сессии остаётся через существующий токен loopback API.
После завершения всех workers API и child закрываются. Повторных входов нет.
Phone Exit / выбранный телефон должны также оставаться запущенными; отделение
game owner само по себе не удерживает сторонний процесс транспорта.

Необязательный --result задаёт новый файл итоговых кодов, до 65536 байт.
Существующий файл отклоняется; перезаписи нет. Результат не содержит email,
пароля, packet bodies или содержимого трафика. Без явного флага файла нет.

## Проверки Windows и живой попытки

test_vampir_detached_worker.py: 3 теста прошли на Windows. Настоящий breakaway
child получил synthetic Unicode credential по pipe, пережил выход dispatcher,
продолжил отвечать по loopback HTTP и завершился по explicit stop.
Проверены неверный readiness, слишком большой input и worker, не читающий pipe:
timeout завершает его. Пароль отсутствовал в stdout / stderr dispatcher.
Это проверка завершения запускающей программы, не перезапуска самого Codex.

test_vampir_live_session.py: 8 тестов прошли, включая 50 synthetic accounts,
ограничение параллельного входа, readiness API перед workers, lifetime stop и
изоляцию Stop. CLI --help и py_compile прошли. SDK / игровой сервер тестами
не вызываются.

Для отдельной живой попытки каталог показал Itel itel P662L / HK онлайн и
свободным. Транспорт запущен тем же breakaway helper, HTTPS через SOCKS 1087
подтвердил прежний IPv4 129.227.134.151. Свежий CDN manifest:
`44a9c0aecf73967d4c5aff4480be874ebf897f06706c979305f6d4bf84db702b`.
Game owner PID 9808 и transport owner PID 31360 подтвердили запуск; после
завершения launcher API продолжал отвечать (uptime 9,6 секунды, connecting).
Новая session ac63ed67bf92d30a96bfa7ada486ba3e дошла до Game Login и получила
58 / BlockedIp. В мир не вошла; новые quests / HP / движение не получены.

--result сохранил game_login_probe / connection_closed / code 58 / BlockedIp.
Оба PID и listener 1087 / 17947 затем отсутствовали: transport helper отслеживал
PID game owner и закрыл собственный PC-процесс. Повтор через этот IP не делался;
пользователю отправлен запрос нового выхода. Raw auth / тела пакетов не сохранялись.
Приватные scripts / startup metadata / terminal result находятся в
F:/PhoneExit Resources/Vampir/live-checks/persistent-itel-20261026/ вне Git.

## Открыто

После сообщения пользователя о новом телефоне выполнен отдельный вход через
Redmi M2006C3LC / HK: IPv4 122.10.196.228, свежий CDN manifest
9bae1a19b77af4f998f6a190a5a7ea569399afd7b70f09e60a6f55f469da3b77.
Owner PID 32636, transport PID 43344. Launcher завершился, owner вошёл в мир
10012 и продолжил работать: Okly, уровень 1, HP 2700/2700, MP 2000/2000.
На uptime 1195 секунд heartbeat 232 / 232, session ID
18b0758bd54fefd33699dd00d5094158 сохранился. Получен реальный ID 1854:
одна запись 110120, group 0 / state 2 / progress raw08 0 / raw10 0 / raw18 0,
общий suffix 110110, ошибок декодирования 0. Активный локальный шаг не установлен.
Соединение оставлено работать; Stop или игровые команды не отправлялись.
Приватные startup / snapshots: persistent-redmi-m2006c3lc-20261026 в live-checks.

Перезапуск Codex с настоящим онлайн-персонажем в новом режиме ещё не проверен;
не объявляется достигнутой длительная стабильность или работа нескольких реальных
аккаунтов. Отдельный transport helper имеет grace / PID / stop-file / 24 h
ownership, но его PID reuse и аварийные сценарии не объявляются закрытыми.
Далее новый выход → живой ID 1854 / правая панель, затем проверка сохранения
соединения при перезапуске Codex и действие квеста по подтверждённому контракту.
