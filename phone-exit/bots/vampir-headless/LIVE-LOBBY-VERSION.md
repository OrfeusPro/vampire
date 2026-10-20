# Настоящий LobbyVersionResult через HK

20 октября 2026. Первый подтверждённый ответ протокола лобби собственного
клиента: **ID 2, result code 0, body 23 байта**. Это результат запроса версии,
не вход аккаунта и не игровая сессия. Login и ServerListRead не отправлялись.

## Адрес CDN связан с native connect

Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Использованы существующие Ghidra exports и проверенный CDN parser, без нового
повторного экспорта. [Предыдущая граница connect](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOBBY-CONNECT-FLOW.md).

В `_SetServerList` адрес destination на 0x145662389 равен global FString
0x14b520cd0, port store на 0x1456623c5 пишет dword global 0x14b520cb0.
Именно эти globals читает lobby connect 0x144aa90c0, затем записывает
peer+0x250 / +0x260 и создаёт endpoint для общего lower connect.

Новый `replay-cdn-lobby-endpoint.py` исполняет весь выбор CDN и затем весь
lobby connect на одной машине, с теми же globals. FString assignment fixture
теперь материализует descriptor global, а не только записывает capture text.
20 сценариев: короткий / длинный ASCII host, пять port strings, true / false
нижнего connect. Host доходит без замены. Port сужается из uint32 до word:
65536 → 0, -1 → 65535, `2junk` → 2. Это native поведение, не политика runtime:
существующий endpoint selector требует корректный public IPv4 и порт 1..65535.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/cdn-lobby-endpoint-replay.json`.
SHA256: `9331f30e9398181e0e63587bc0f397627d10ed2818fe3c3ec9c52824ae340113`.
JSON / FString / allocator / narrow conversion — ограниченные fixtures,
последняя поддерживает только ASCII. Endpoint constructor исполняется с copy
fixture; lower connect — capture. Startup / active config cache не заявляются.

## Исправлен режим приёма лобби

Прежние [native transport scenarios](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-TRANSPORT-STAGE.md)
уже подтверждали: для несжатых блоков peer A сохраняет первые три байта
(offset 0), peer B удаляет их (offset 3). Первоначальный новый probe ошибочно
использовал ReceiveStream с игровым offset 3. Поэтому из 28 полученных байт
не выделялся packet. Это ошибка настройки probe, не отказ сервера.

`ReceiveStream` и `take_transport_frame` теперь принимают явный
`uncompressed_offset=0` или `3`. Прежнее default 3 сохранено для game owner,
лobby probe явно выбирает 0. Автоматического угадывания / fallback нет.
Compressed blocks в обоих случаях начинают decoder после трёх байтов,
а распакованный output передаётся целиком. Byte budgets учитывают сохранённый
header при offset 0. Проверены все разрезы raw / compressed кадра лобби,
склеенные кадры, output limit и некорректные значения offset.

## Probe и реальный обмен

`probe-lobby-version.py` использует явный recovered-base профиль с проверкой
SHA EXE / PAK / INI, AppVersion 1.12.14 и свежий CDN snapshot. У наблюдённого
тестового HK-профиля проверяются сохранённые идентификаторы и текущие три
ключа устройства. Никакие ключи не генерируются и не заменяются.

Поля LobbyVersion следуют обычной Windows ветви 0x1467aae20:
AppVersion, наблюдённый Windows suffix, GetComputerNameW, NMDeviceKey, пустая
строка; raw bytes 0 / 3 и compiled DWORD 1. CPU, локальный IPv4 и compiled tag
игрового Version сюда не подставляются. Подготовка обоснована предыдущими
source bindings; полное native preparation body в новом replay не исполняется.

`exchange_lobby_version` отправляет один ID 1 / sequence 0 и принимает только
ограниченный ответ версии. Есть budgets времени / байтов / пакетов, безопасные
summary ошибок и закрытие сокета при завершении. Login, подтверждение устройства,
запрос списка и повтор запроса этот owner не выполняет. OS / device values и
сырые ответы не выводятся и не сохраняются.

Свежий CDN получен через личный HK-транспорт: HTTP 200, 6000 байт, real / REAL.
Snapshot: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/53ff47822e44930fa3c7d95b7d70b747bea0b94301e2e1dad5dc47a1e6376e60/manifest.json`.
SHA manifest совпадает с именем каталога. Выполнены три отдельные попытки:

1. Первая завершилась общим исключением; подробный этап не был сохранён.
2. После добавления безопасных counters получены 28 байт на отправленные 94;
   при неверном offset 3 итог protocol_error без выделенного packet.
3. После исправления на source offset 0 отправлены 94 байта, получены 28;
   выделен ID 2 / body 23, result code 0, flag +0x14 = false.

Login / SDK token / ServerListRead не отправлялись ни в одной попытке.
Версия содержит NMDeviceKey и имя компьютера по подтверждённой схеме.
Все сокеты закрыты; временный HK-клиент остановлен, exit 0. Настройки системной
маршрутизации не менялись. Ответ не сохранён в сыром виде; code / flag / lengths
выше — безопасный summary, а не доказательство авторизации аккаунта.

## Проверки и продолжение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-cdn-lobby-endpoint.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_version_probe.py -v
```

Три новых теста: воспроизводимость native handoff / поля preparation,
настоящий socketpair с дроблёным ответом, timeout / EOF / безопасная ошибка.
Дополнительно прошли 13 ReceiveStream, девять GameConnection, пять native
transport stage и шесть block decoder tests: всего 36 целевых проверок.

Далее — SDK-контекст LobbyLogin, его настоящий ответ, decoder ID 104 со
списком игровых серверов, затем игровой Version / Login → персонажи → позиция.
Ближайшая цель списка и выбора персонажа остаётся открытой.
