# Version: локальный адрес и ограниченная сетевая проверка

20 октября 2026. Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники callback и начального состояния

Ghidra 12.1.4: 297 функций, 123 предупреждения. Экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-f2fe5a5a3934`.
Manifest SHA256: `c1d6bd19efc80d82dfe7399aca682f47dcfcced2e2831a7584c0561623f048d9`.
functions.json SHA256: `d2c01cc4939a1283356e1b62dd1fe7d39bbb4288bb88a54575bd6e93564cd255`.
Воспроизведение экспорта — по [порядку инструментов](../resource-tools/vampir/ANALYSIS-TOOLS.md)
и [manifest builder](../resource-tools/vampir/build-ghidra-manifest.py).

`Transport_ConnectedInputs` (0x144aac520) получает peer interface P+0x200,
обнуляет sequence по P+0x240 и ключ по P+0x248. Затем через getter сокета
вызывает `Socket_ConnectedEndpoint` (0x1445e7680). Тот читает socket handle
по this+0x38 и вызывает getsockname, inet_ntoa и ntohs через IAT.
Endpoint содержит IPv4-строку по +0x8 и порт по +0x28. Дальнейший callback
передаёт только строку: **локальный IPv4 без порта**, затем она попадает
в Version+0x58. Это не внешний IP телефона и не адрес игрового сервера.

Тип возврата getter в псевдокоде ошибочно void: в инструкциях по
0x1445e7782 находится `mov al,1`, по 0x1445e7797 — `xor al,al`.
Success/failure нужно читать по машинным инструкциям. Проверка здесь
статическая; положительная ветвь системных API в native emulator не исполнялась.

## Реализация и проверки

`vampir_core.version_probe.exchange_version` владеет уже подключённым сокетом,
отправляет один Version, обрабатывает смену ключа ID 11 / ack ID 12 и читает
VersionResult ID 2. Начальные ключ и sequence равны нулю. Есть пределы времени,
байтов, пакетов и смен ключа; завершение закрывает очередь, decoder и сокет.
Login и запросы персонажей этот путь не отправляет, повторов нет.

`probe-game-version.py` собирает обычный Windows Version из явного AppVersion,
наблюдённых CPU / Windows / NMDeviceKey и getsockname текущего соединения.
Четыре неиспользуемые строки остаются пустыми; integers — 0, 207, 1;
compiled tag — `AC7F34E3AFA91ED417BE86CD45BF18C8`. Происхождение остальных
полей описано в [индексе входов](../resource-tools/vampir/HEADLESS-GAME-LOGIN-INPUTS.md).
При SOCKS локальный адрес относится к соединению ПК с прокси.

Пять новых тестов проверяют настоящий socketpair, дробление key notification,
CRC / sequence / ack под старым ключом, ответ под новым ключом, timeout,
закрытие, повреждённый ответ, поля Version и отказ от неявного выбора лобби.
Также прошли девять тестов GameConnection и 11 тестов ReceiveStream.

## Одна внешняя попытка и её границы

Свежий CDN получен через личный HK-транспорт, HTTP 200, 6000 байт.
Snapshot: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/0d71d75ef9ed897f4e5233c1a535d34ecfb39b324c58a47d61039c5a544d98de/manifest.json`.
SHA manifest совпадает с именем каталога. Выбрана запись real / REAL,
её CDN-лобби `183.110.205.25:12000`. Один Version передал 199 байт;
за 10 секунд получено 0 байт, итог timeout. Login и SDK token не отправлялись;
Version содержит NMDeviceKey. Сырые auth-данные и значения устройства не сохранялись.
Сокет закрыт; временный HK-клиент остановлен, exit 0.

**Назначение CDN-лобби для игрового Version не было доказано до попытки.**
Это диагностическая отправка, а не проверка входа на установленный игровой
endpoint. Timeout не устанавливает ни совместимость Version, ни отказ аккаунту.
Теперь CLI требует явный `--diagnostic-cdn-lobby` и сообщает непроверенную роль
адреса. Повторная внешняя попытка без новых источников не выполнялась.

[BeginGameImpl](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md)
берёт игровую запись из master model; её host и порт использует
[ConnectToServer](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).
У LobbyLogin / LobbyLoginResult отдельные схемы и регистраторы, хотя ID 3 / 4
совпадают с игровыми Login / LoginResult. Смешивать эти контексты нельзя.
[Native drain](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md) передаёт очередь
прямо в Winsock send, без дополнительной оболочки на этом этапе.

Далее — цепочка лобби, загрузка игровых server records и остальные Login inputs.
Настоящий игровой VersionResult, список персонажей и выбор ещё не получены.
