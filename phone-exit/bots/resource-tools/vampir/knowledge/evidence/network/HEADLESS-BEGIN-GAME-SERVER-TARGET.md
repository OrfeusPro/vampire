# BeginGameImpl: ID сервера, поиск записи и цель транспорта

19 октября 2026. Продолжение [BeginGame SDK gate](../auth/HEADLESS-TITLE-AUTH-STATE.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-begin-game-server-target.py](../../../replay-begin-game-server-target.py) создаёт
`F:/PhoneExit Resources/Vampir/code-clues/begin-game-server-target-replay.json`.
SHA256: `e292d527fcce9d8dabb6d3454a7a34cf1d98d04084e1f59961aff028cecc40a1`.
Сохранены tool/source/entry SHA, полные fragments с bytes/file offsets,
bounded lookup/setter spans и literal provenance.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-begin-game-server-target.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 4096 instructions на сценарий.

## Выбор и поиск

BeginGameImpl 0x146425730 получает master через getter 0x145d37270.
Читает dword master+0x308; diagnostic связывает его с GetLastPlayedServerId.
Если он равен dword global 0x14961a380, подставляется dword global 0x14b125534.
Имена/реальная инициализация этих globals неизвестны. В replay значения
0xffffffff и 42 — **явные fixtures**, не доказанные production constants.

Нулевой выбранный ID имеет отдельную ветвь: сравниваются master+0x90/+0xbc.
При различии достигаются внешние actions, а lookup пропускается. При равенстве
продолжается lookup ID 0. Эти actions captures, точный UI/policy смысл открыт.

Lookup 0x145d39440 исполняется реально. Он проверяет counts +0x90/+0xbc,
берёт bucket array +0xc8 (или inline +0xc0), bucket count +0xd0,
маскирует ключ count-1 и идёт по records +0x88 со stride 0x80.
Key лежит в entry+0, collision next index в entry+0x78.
Успех возвращает **entry+8**, то есть value subobject. Разобраны все leaf
ветви до 0x145d394e9, включая второй success хвост после ранних RET.

Map layout в replay source-bound, содержимое synthetic: один bucket и
линейная chain. Исполнены попадание во вторую запись и конец chain без совпадения.
Это не проверка загрузки настоящего server list или всех вариантов hash layout.

## Передача в транспорт

После найденной записи проверяется byte state+0x38 через getter 0x145d37220.
Ненулевой byte останавливает этот запуск до setters. При нуле native caller
записывает 1, затем получает transport wrapper 0x144aaa9d0 и вызывает:

| Caller / setter | Источник | Назначение в impl wrapper+0x10 |
| --- | --- | --- |
| 0x146425a43 → 0x144aab510 | выбранный ID | dword +0x270 |
| 0x146425a54 → 0x144aab500 | record value+0x20, FString | FString +0x278 |
| 0x146425a66 → 0x144aab520 | word value+0x30 | word +0x288 |
| 0x146425a78 → 0x144aab4f0 | word value+0x32 | word +0x28a |

Четыре setters исполняются native; строковый setter JMP в FString assignment
0x14143c260, который заменён bounded copy fixture. Строка и оба words передаются
точно, включая пустую строку и words 0/65535. Их имена и роль в endpoint/protocol
пока не доказаны: не выдавать два raw words за подтверждённые TCP/UDP порты.

Остановка успешной ветви на 0x146425a7d, сразу после setters, до UI/connection tail.
Не было socket connect, packet Login или server-compatible session.

## Одиннадцать сценариев и проверки

Direct ID, fallback ID, missing ID, empty map, busy, zero ID/empty map,
zero ID/selection branch, collision second, collision miss, word boundaries,
empty text. Missing/busy/zero-selection сохраняют прежние target fields.
Busy byte меняется только на достигнутой успешной setter ветви в этих fixtures.

Исходные targets 777/old-target-fixture/111/222 остаются нетронуты при отказе.
Этот результат касается только указанных native branches; concurrent запуск,
state recovery и rollback после ошибки дальнейшего соединения не проверены.

[Три regression tests](../../../../../test_vampir_headless_begin_game_server_target.py)
проверяют SHA-bound воспроизводимость, exact stores/lookup/call sites,
коллизии/fallback и сохранение targets при отказе. Семь смежных title-state/
packet-binding tests прошли. Runtime не менялся; полный suite 316 из предыдущего
runtime milestone повторно не запускался.

Getters master/state/wrapper, formatting/logging, строковые primitives и
zero-ID actions — fixtures/captures. Реальные records/last server/profile,
Sentinel/fallback configuration и busy lifecycle неизвестны. Игра не запускалась;
память процесса, Saved/profile, credentials и HTTP/сокеты не использованы.

Следующий шаг — consumers transport+0x270/+0x278/+0x288/+0x28a,
connection setup и связь с packet Login. Сетевые роли raw fields устанавливать
по реальным consumers, не по похожим названиям или размеру значения.
