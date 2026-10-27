# Первый сетевой прогон 1.13.18: локальный отказ перед авторизацией

27 октября 2026 найден свободный Samsung SM-J701F / HK через личный каталог.
Штатный native WebRTC открыл loopback SOCKS 1087. Проверка HTTPS ipify через
этот выход успешна. CDN 1.13.18 получен тем же маршрутом, HTTP 200, real:
`public-cdn-snapshots/eafe5898c1241b785138f4be8eede2b413ee2702dab8c30765beda41fb6cc12a/manifest.json`
в `F:/PhoneExit Resources/Vampir/`.

Один запуск candidate-11318 завершился за 2.746 секунды:
source_validation → lobby_preparation → selected_game_login_not_completed.
Game Login не выполнен, ответ BlockedIp не получен, персонаж онлайн не подтверждён.
В selected_endpoint списка разрешённых config SHA нет текущего
`f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251`.
Проверка выполняется до загрузки SDK inputs и авторизации. Это локальный
пропущенный переход, а не доказательство сетевого отказа игры.

Следующий шаг: добавить точную пару текущего config SHA / HTTPS URL и
интеграционную проверку настоящего сохранённого CDN manifest; проверить
неизменность source/route/body guards. Затем один повторный bounded вход.
Native доказательства, квесты и tutorial этим наблюдением не подтверждаются.
