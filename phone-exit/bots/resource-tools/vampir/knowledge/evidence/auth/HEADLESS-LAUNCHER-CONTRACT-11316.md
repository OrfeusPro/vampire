# Launcher request / response в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Прежний источник для сравнения:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [явного экспорта](../tools/HEADLESS-REQUESTED-GHIDRA.md) и
[предыдущего launcher-контракта](HEADLESS-RELEASE-LAUNCHER-CONTRACT.md).
Проверка статическая; авторизация, HTTP и игра не запускались.

## Точные новые связи

| Запрос | Начало функции | UTF-16 suffix | Callback thunk → root | HTTP wrapper |
| --- | --- | --- | --- | --- |
| Token | `0x1444ee9d0` | `0x149531050`, launcher/token | `0x1444dedb0` → `0x1444cc1b0` | `0x144522c90` |
| SignIn | `0x144503b10` | `0x149531260`, launcher/sign-in | `0x1444deea0` → `0x1444d3730` | `0x144522e10` |

ASCII authUrl находится в `0x14952f180`; ссылки есть в обоих запросах.
E9 thunks: `e9fbd3feff` и `e98b48ffff`. Корни определены по реальным байтам,
без переноса адресов по общему сдвигу. Полные exports wrappers сохранены;
их внешние зависимости / реальный HTTP этой проверкой не исполняются.

| Ключ | Initializer | Global FString | UTF-16 literal |
| --- | --- | --- | --- |
| buildCode | `0x1411b0170` | `0x14b561cb0` | `0x14952b3e8` |
| gameCode | `0x1411b03e0` | `0x14b561ca0` | `0x14952b3d0` |
| launcherToken | `0x1411b04a0` | `0x14b561cf0` | `0x14952b468` |
| countryCode | `0x1411b0260` | `0x14b561d70` | `0x14952b588` |
| credential | `0x1411b0290` | `0x14b561d20` | `0x14952b4b8` |
| deviceKey | `0x1411b02f0` | `0x14b561d00` | `0x14952b488` |
| errorCode | `0x1411b0350` | `0x14b561da0` | `0x14952b5e0` |
| nmDeviceKey | `0x1411b04d0` | `0x14b561d10` | `0x14952b4a0` |
| os | `0x1411b0500` | `0x14b561d80` | `0x14952b5a0` |
| resultData | `0x1411b05c0` | `0x14b561df0` | `0x14952b660` |

У каждого initializer проверены literal, destination и call `0x141426b30`.
Есть и другие initializers тех же строк в EXE. Нужный вариант выбран по
destination, реально используемому новыми запросами / callbacks; порядок
совпадений или похожее имя функцией не доказывают.

В двух requests проверены ссылки на четыре общих поля nmDeviceKey / deviceKey /
countryCode / os. Token также использует gameCode / buildCode / credential;
SignIn — launcherToken. Смысл размещения тела и заголовка прослежен в прежней
ветке; новые instruction shapes совпали, но внешние callee targets остаются
отдельной границей проверки.

Token response использует строковый getter `0x14447d160` и dispatcher
`0x1444e54f0`. SignIn response — object getter `0x14447cf10` и dispatcher
`0x1444e67c0`. В обоих есть ссылки на errorCode / resultData. Проверка отсутствия
direct SignUp для нового SHA не заявляется: новый target SignUp здесь не разобран,
поле direct_sign_up_reference равно null.

## Целостность и сравнение

`audit-release-launcher-contract.py --source-sha256 <полный SHA>` теперь имеет
две явные схемы старого и нового источников. Неизвестный SHA отклоняется.
Проверяются полные SHA EXE / exports, байты каждой инструкции, ссылки, ключи,
суффиксы и E9. Для нового SHA проверяется покрытие всего native unwind root
листингом Ghidra и сравнение с прежними 16 функциями.

Всего 16 функций / 2 863 инструкции. После маскирования RIP displacement и
direct CALL/JMP immediates остальные байты совпали; локальные branch destinations
сверены отдельно относительно начала функции. Это сохраняет проверку констант
и локального ветвления, включая прежние HTTP gates. Но маскирование адресов
не доказывает содержимое globals, поведение внешних getters / parsers / dispatchers
или принятие запроса сервером. Это **не native replay** целой цепочки.

Библиотека `F:/PhoneExit Resources/Vampir/`:

| Материал | Путь / SHA256 |
| --- | --- |
| Два requests | `ghidra/request-exports/<новый SHA>/run-e6508b986175/details.json` / `c9923787de462d4bdca9e03cdcf59a9ff333003cae0b574e9ee43c74fb71e101` |
| 14 дополнительных функций | `ghidra/request-exports/<новый SHA>/run-aa8c16b9c37f/details.json` / `68a258e1f298e7e607337b366ef673deb7af1fece47a33bf24442fbc9647cd0e` |
| Статический audit | `code-clues/release-launcher-contract/35442dbd0c73c11a6649fd10d575104fa8a09ed4b3102dee0d352865ab4d7983/manifest.json` |
| Обновлённый поиск ориентиров | `code-clues/update-targets/be1e307051e89138ad2ba6451e775b9d927ec8a64d77d4e56ad82f0d91fe1821/manifest.json` |

Шесть launcher tests проверяют обе версии, новые связи / shapes и отказ на
неизвестный SHA, изменённый EXE или export. Check release-launcher-contract
допускает новый SHA. Остальные auth checks не объявлены перенесёнными.

## Для следующего обновления

[Машинный план](../../release-update-targets.json) дополнен десятью key literals
с точными старыми SHA / адресами и required checks. Короткий UTF-16 os требует
предшествующего NUL, чтобы не принять окончание чужой строки. При числе roots
больше 32 бюджет распределяется между ориентирами по очереди; непроверенные
ссылки сохраняются с причиной исчерпания бюджета, а не дают ложный unique match.
Семь offline locator tests проверили эти границы, включая fixture с 33 roots.

Дальше — текущие SDK defaults, GMC2 URL / headers, zone / market / game override.
Новый runtime profile, активные настройки клиента и живая EU-сессия ещё не
подтверждены. Guards прежнего профиля не отключались.
