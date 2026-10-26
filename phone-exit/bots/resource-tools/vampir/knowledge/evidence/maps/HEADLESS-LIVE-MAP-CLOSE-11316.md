# Завершение часовой сессии и повторный вход

26 октября 2026. Продолжение [живой карты](HEADLESS-LIVE-MAP-11316.md).
EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.

Сессия OnePlus PGP110 / HK дошла до установленного предела транспорта 1 час.
До закрытия snapshot показал uptime 3573,7 секунды с авторизацией,
heartbeat 701 / 701, stat decode errors 0. Итоговый результат:
Game Login 0, world finish 0, 701 periodic Ping и 702 ответа, connection_closed,
game error null. Transport завершился с code 0. Это тест до заданного срока,
не доказательство бесконечной работы или UDP / системного VPN.

Получен один ID 302 размером 5 байт при известных world / own key:
decoded_packets 1, decode_errors 0, entities 0. Reader требует точную длину:
это пустые actor / quest collections и reason byte. Сам reason не сохранялся.
Удаление реального actor этим пакетом не подтверждено. ID 301 / 324 не получены;
близкие NPC / игроки остаются неизвестными.

Итоги вне Git в `live-checks/map-projection-oneplus-pgp110-20261026/`:
live-result.json и live-state-first-leave.json. После завершения старого owner
планировалась проверка нового decoder; первый процесс остановился до ввода
credentials, его handle отсутствовал и активных процессов / listeners не было.

Новая проверка в `live-checks/tutorial-oneplus-pgp110-resume-20261026/`:
тот же свободный телефон и HTTPS IPv4 162.128.225.22, свежий CDN manifest
`e169d9b2fd8782d70a613a7a5a4f76150684a5557aa88cf42b70f956721164ab`.
SDK / launcher / лобби прошли, но JP 256 вернул `58 — BlockedIp` до world.
Новый tutorial state не получен; причина и область блокировки неизвестны.
После отказа транспорт закрылся с code 0, listeners 1087 / 17947 отсутствовали.
Повтор через этот выход не выполнялся; пользователь сообщил, что создаёт телефон.

Helper нового транспорта связан с PID игрового owner и Stop file, имеет grace
для старта и аварийный предел 24 часа. При завершении owner / результата
транспорт закрывается. Удержание новой успешной сессии этим helper ещё не
проверено: последняя попытка закончилась отказом до мира.
