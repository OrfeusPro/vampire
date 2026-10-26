# Живая попытка проверки окружения, 26 октября 2026

Источник EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверялось [подключение ID 301 к изолированной модели](HEADLESS-INITIAL-ENVIRONMENT-11316.md).
Попытка не дошла до персонажа: игровой сервер JP 256 вернул code 58,
который текущий decoder сопоставил с `BlockedIp`.

## Фактический порядок

Каталог Phone Exit успешно прочитан через штатный HTTPS с системным CA Node;
TLS verification не отключалась. OPPO CPH2471 / HK был онлайн и свободен.
Запущен отдельный PC native WebRTC transport, получен loopback SOCKS 1087.
HTTPS ipify через SOCKS5 hostname показал IPv4 `129.227.134.172`.
Это проверка данного HTTPS TCP-сценария, не нового UDP / системного VPN proof.

Первая подготовка остановилась до SDK-входа: сохранённый public CDN manifest
`54bbe08ec7ca8fe490c126b572ecb65c04633e23c8b2c44abe3060391685e6c0`
имел transport port 17948, а выбранный route — 1087. `selected_endpoint`
отклонил несовпадение. Проверка не отключалась; по этому запуску нельзя делать
вывод об отказе игрового сервера или пароле.

Через текущий route выполнен один новый публичный HTTPS fetch конфигурации:
`public-cdn-snapshots/07e377c1fcc9dd09dd036c4ef39ae014a76bb924f2754ff34a3a86d4b12e9014/manifest.json`.
HTTP 200, 7632 bytes, environment real; TLS verification включена, redirects
не использовались. Manifest сохранён content-addressed вне Git.

После замены только явного manifest input выполнены официальный launcher SDK
sign-in, получение SDK token, lobby connect / exchange и selected lobby login.
Затем прошли game target selection / connect / Login exchange. Итог:

- `status=game_login_probe`, `game.status=connection_closed`;
- `login_result_code=58`, `login_result_key=BlockedIp`;
- `error=login_response_failed`, `world_entry_state=closed`;
- world finish не получен, periodic Ping 0, Ping replies 1;
- событий 301 / 302 / 324 получено 0, итоговая сессия disconnected.

Пароль передан скрытым вводом, в JSON / stdout / Git не записывался.
Packet bodies / auth captures не сохранялись. Приватный наблюдатель сохраняет
только whitelist metadata, ограниченные environment event summaries и snapshots;
до окружения он не дошёл. Его результат:
`F:/PhoneExit Resources/Vampir/live-checks/initial-environment-20261026/live-result.json`.
Неудачная preauth подготовка сохранена отдельно, без перезаписи.

## Закрытие и следующий шаг

Повторного игрового входа через этот выход не выполнялось. Собственный транспорт
получил Stop, завершился с code 0; отсутствие loopback listeners 1087 и 17947
проверено после завершения. Профили / привязки и настройки ОС не менялись.

Точная причина серверной IP-политики не установлена. Code 58 подтверждает
ответ `BlockedIp`, но не объясняет, почему конкретный выход попал под неё.
Для нового live proof нужен доступный другой выход. Декодер / модель / UI
сохраняют прежний offline статус; текущая попытка не доказывает живой SightEnter,
порядок относительно world finish, HP/MP окружения, позицию на карте или
одновременные игровые сессии. Пока выход недоступен, можно продолжать source-first
проверку применения текущих stats / движения к уже известным actor keys.
