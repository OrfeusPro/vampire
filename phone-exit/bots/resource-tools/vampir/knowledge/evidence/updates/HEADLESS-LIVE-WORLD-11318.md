# Ограниченный живой вход 1.13.18

27 октября 2026 выполнен один повторный вход после исправления локального
CDN resolver. Предыдущая попытка завершилась до авторизации:
[локальный отказ](HEADLESS-LIVE-PREFLIGHT-11318.md).

Источник EXE: `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Профиль: явный candidate-11318. Транспорт: личный Samsung SM-J701F / HK,
штатный native WebRTC, loopback SOCKS 1087; HTTPS ipify и CDN получены
через этот выход с проверкой TLS. Конфигурация real 1.13.18:
`public-cdn-snapshots/eafe5898c1241b785138f4be8eede2b413ee2702dab8c30765beda41fb6cc12a/manifest.json`
в `F:/PhoneExit Resources/Vampir/`. ClientVersion прочитан штатным parser из
установленного `Saved/PersistentDownloadDir/Patch/windows.manifestlist`.

Цепочка фактически прошла NID → launcher token / sign-in → lobby exchange →
выбор JP 256 → game connect → Login → список / выбор персонажа с индексом 0 →
вход в мир → ограниченное наблюдение. Итог:

- status: game_login_probe;
- game.status: world_observation_complete;
- login_result_code: 0;
- error: null;
- periodic_ping_queued: 12;
- ping_results_received: 13.

Наблюдение ограничено 60 секундами после входа, затем probe штатно закрыл
принадлежащий ему сокет. Верхний game_session_ready=false — прежний флаг
отчёта probe, а не состояние постоянного owner; это не проверка persistent API.
Queued не означает отправку; полученные PingResult подтверждены отдельно.
Учётные данные передавались в памяти, содержимое пакетов не сохранялось.

Исправление добавляет только точную пару config SHA / HTTPS URL в resolver.
Проверки manifest / body SHA, маршрута, публичного адреса и региональных
ограничений сохранены. Общий offline набор расширен с 26 до 31 теста:
настоящий сохранённый CDN manifest → настоящий endpoint resolver → SDK boundary;
подмены URL/config/route/body и private targets отклоняются. SDK boundary
в тесте synthetic, настоящий SDK подтверждён только описанным живым прогоном.
Новый набор включён в существующий on_update check и общий кэш.

Границы: не проверены длительная сессия, восстановление после потери сети,
постоянный owner / UI, другие серверы и аккаунты, полные HP/MP/position
проекции, квесты и tutorial новой версии. Автоматическая активация профиля
и расширение этих capabilities не выполнялись. Остаток очереди — 36 строк;
это не 36 отдельных ручных экспериментов. Следующий пакет — current read-only
данные мира / координат и связанные bindings, затем квесты / tutorial.
