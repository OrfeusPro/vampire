# Постоянный независимый owner 1.13.18

27 октября 2026 пользователь явно запросил соединение без таймера и
независимость от закрытия Codex. Добавлен opt-in `--keep-online`.
Обычный candidate-11318 сохраняет предел 300 секунд. При явном opt-in
owner не создаёт lifetime Timer, current world loop не завершает наблюдение
через 300 секунд, а задача Windows получает ExecutionTimeLimit=PT0S.
Stop, потеря связи и обработка ошибок сохраняются. Автоматического повторного
входа после неизвестного результата нет. Quest / tutorial / map capabilities
не расширялись, source guards не ослаблялись.

## Отдельный процесс и проверка источника

Первый detached запуск обнаружил локальный SourceProfileNotVerified:
Scheduler broker работал через pythonw.exe, тогда как native proof definition
закрепляет python.exe. Родительский source preflight при этом проходил.
Game API не был открыт, игровой вход на этих отказах не выполнялся.

Broker теперь запускает точную проверенную команду python.exe скрыто через
CREATE_NO_WINDOW. Payload и readiness передаются анонимными каналами; broker
ждёт завершения child и сохраняет принадлежность задаче Windows на весь срок.
После readiness определение одноразовой задачи удаляется, работающий процесс
остаётся. Пароли / токены на диск и в логи не записываются.

## Проверки

Общий зарегистрированный on_update runtime набор: 42 теста passed.
Добавлены explicit opt-in / default bound / конфликт timer / handoff / Stop /
virtual time +301, проверка точного интерпретатора и cleanup broker.
Две настоящие Windows Scheduler регрессии также passed: timeout cleanup и
сохранение synthetic HTTP worker после завершения дерева dispatcher;
worker дополнительно проверяет, что sys.executable — python.exe.
Native игровые доказательства с неизменными inputs повторно не выполнялись.

## Фактический запуск

Личный Samsung SM-J701F / HK, native WebRTC, SOCKS loopback 1087.
Транспорт и игра запущены отдельными задачами Windows без lifetime limit;
transport наблюдает именно новый PID game owner и закрывается после его выхода.
До публикации owner действует только startup grace 300 секунд.
Game API: 127.0.0.1:17947, UI server: 127.0.0.1:17946.
Ready подтверждает keep_online=true, max_runtime_seconds=null.
Запускающая консоль завершилась; API затем подтвердил connected, присутствие
персонажа и поступающие PingResult, error=null. Соединение не останавливалось
после проверки. Baseline / PID / session ID сохранены приватно:
`live-checks/persistent-hk-11318-20261027/restart-baseline.json`
в `F:/PhoneExit Resources/Vampir/`.

Принудительное закрытие настоящего Codex не выполнялось из этого процесса;
независимость подтверждена структурой Windows Scheduler, завершившимся launcher
и отдельным настоящим ancestry тестом. Не обещается бессрочная доступность
сети / телефона / сервера или автоматический reconnect. Длительная стабильность
и все read-only проекции не подтверждены этим коротким наблюдением.
Квесты по последнему уточнению пользователя доделываются на базе 1.13.16;
перенос на 1.13.18 отложен. Остаток сверки новой версии — 36 строк.
