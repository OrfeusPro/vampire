# Настоящий LobbyLoginResult через HK

20 октября 2026. Получены **LobbyVersionResult с кодом 0** и
**LobbyLoginResult с кодом 0** на одном соединении собственного клиента.
Это подтверждённый вход в лобби. Список игровых серверов, игровой Login,
персонажи и позиция ещё не получены.

## Выбранный контекст собственного клиента

Прежний [native replay preparation](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-PREPARATION.md)
проверил отдельную ветвь: SDK auth присутствует, NID UserInfo отсутствует.
Она передаёт SDK player ID / SDK access token / NMDeviceKey / отдельный NID,
оставляя country и metadata пустыми. Для первой headless-попытки выбран
именно этот явный режим `sdk-without-nid-info`. Данные UserInfo не подделываются.
Полная поддержка NID metadata остаётся отдельной задачей; для проверенной
ветви она больше не является условием перехода к списку серверов.

Локальный начальный kind выбран равным 0. Это политика нашего клиента,
не найденное начальное значение kind у игры. Native preparation отображает
такой kind в поле +0x14 = 0. Server ID 0 соответствует прямой записи
constructor `GamePeer_Construct` 0x144aab540 в peer+0x270. Native preparation
переносит его в LobbyLogin+0x68. Остальные числа: platform 2, +0x6c = 0;
последний raw byte равен 7. При включённом Version flag +0x14 отправка Login
блокируется до реализации дополнительного numeric context.

`build-lobby-login-context-index.py` сохранил 49 проверенных direct calls
к lobby getter / game server setter. Две записи по смещению +0x64 —
только кандидаты других объектов, не доказательство kind у lobby wrapper.
Не использовать совпадение смещения как идентичность объектов.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/lobby-login-context-index.json`.
SHA256: `bebcca12fddb4bc3717770ca238c2fda5c322f994ff4d4dfda7e58a27ad6bb58`.

## Реализация и порядок обмена

`probe-lobby-sdk-login.py` проверяет явный recovered-base профиль и устройство,
получает свежий NID credential штатным WebView2 и выполняет SDK SignIn.
Provider credential удерживается в памяти для отдельного NID; SDK token
берётся из SDK response. Пароль принимается только через stdin, не аргумент CLI.
SDK SignUp, создание аккаунта и автоматический повтор не выполняются.

`exchange_lobby_login` владеет подключённым сокетом до закрытия:

1. Отправляет отдельный LobbyVersion / ID 1 / sequence 0.
2. Разбирает ответ ID 2, требует code 0 и flag +0x14 == false.
3. Отправляет LobbyLogin / ID 3 / sequence 1.
4. Разбирает отдельный LobbyLoginResult / ID 4 и закрывает сокет.

Ожидание VersionResult до отправки credentials — локальная политика probe;
native wrapper может отправлять Version и исходный запрос подряд. Порядок
пакетов сохраняется. При отказе версии / дополнительном numeric context
Login не отправляется. Есть timeout / byte / packet budgets, bounded decoder,
явные ошибки и закрытие при завершении. ServerListRead и игровые пакеты
этот probe не отправляет. Decoded response возвращается скрытым из repr,
для CLI выводится только безопасный summary.

## Реальная проверка

Свежие конфигурации получены через один личный HK-транспорт, SOCKS 17948:

| Snapshot | Manifest SHA256 / имя каталога |
| --- | --- |
| public-cdn-snapshots, HTTP 200, 6000 байт | 5b9fef7245f893405f2a91891bea0640db1cb47ce361341b881909c90ddae069 |
| public-gmc2-snapshots, HTTP 200, 13777 байт | 3fdf02d6abbf127205745561cf484255d0d71066a6976d206e3c1473563e4ca6 |

Оба лежат в `F:/PhoneExit Resources/Vampir/`; внутри каталогов `manifest.json`.
SDK SignIn принят. Одна попытка lobby exchange дала:

| Показатель | Результат |
| --- | --- |
| Отправлено / получено | 460 / 123 байта |
| Packet IDs | 2, затем 4 |
| LobbyVersionResult code | 0 |
| LobbyLoginResult code | 0 |
| Тело LobbyLoginResult | 90 байт |
| Запрос списка серверов | Не отправлялся |

Тестовый аккаунт HK зарегистрирован ранее; новых аккаунтов в этом этапе нет.
Игра не запускалась. SDK token / поля ответа Login не сохранялись в файлы и
не выводились; приватный профиль WebView2 переиспользован. Все сокеты закрыты,
временный HK-клиент остановлен с exit 0, системные маршруты не менялись.

## Источник и проверки

EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Собранный код клиента, не исходный C++ проект. Ghidra 12.1.4: 334 функции,
153 предупреждения; экспорт
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-0dabaa920541`.
Manifest SHA256: `2d2b956bae7420d7c5948379afd3a1b74f304b8f7b12b3ce551e4af396d5572d`.
functions.json SHA256: `1acab7cac3550bfca80ed21e9a2614e2d803b55e245ca5cd4b6bc5b49de0b16f`.

Три новых теста проверяют source context index, настоящий socketpair с Version /
Login / дроблением ответа, codes 0 / 1602, запрет Login при отказе версии /
numeric flag, закрытие и redaction. Также прошли четыре preparation, четыре
writer / binding, 13 ReceiveStream и три проверки Ghidra: всего 27 проверок.

Далее — ServerListRead / ID 103 и bounded decoder ответа ID 104, выбор
игрового endpoint, затем игровой вход и список / выбор персонажа.
