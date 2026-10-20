# Лобби: отдельный Version и запрос списка серверов

20 октября 2026. Продолжение [Lobby Login](HEADLESS-LOBBY-LOGIN.md).
Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Ghidra 12.1.4: 318 функций, 145 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-c4e9ee19a160`.
Manifest SHA256: `b8a184eec9b4c0c8f1fda1511385f4d97249c8959f7cdf2e9c532456da9d4167`.
functions.json SHA256: `c181aec272bb785857817143054a8500e6bd88df1c88756aa66ff3bd89cd85a0`.
Перед новым разбором прочитаны прежний экспорт и [индекс инструментов](../../../ANALYSIS-TOOLS.md).

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-lobby-server-bindings.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-handshake-codecs.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_server_bindings.py -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_packets.py -v
```

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Имя | SHA256 |
| --- | --- |
| lobby-server-bindings.json | c054f2919e8b76d601699f4089ebf03bf7021e805dcd4da714fbdc2b07957797 |
| lobby-handshake-codecs.json | 8206f08addf5a9cb9fc655987203efe924add601b52df064d96912f3fac21c16 |

Discovery проверяет SHA клиента, единственный name getter, aligned pointer
на него в .rdata и установку начала packet table в object vptr. Для этих
stores сохраняются исходные bytes / offsets / SHA; constructor boundary по
ним не выводится, среди найденных точек есть destructors. ID getters имеют
проверенные `mov eax, imm; ret`; все четыре исполнены в отдельном native test.

## Отдельные packet bindings

| Тип | ID | Vtable | Writer | Reader |
| --- | --- | --- | --- | --- |
| PktLobbyVersion | 1 | 0x1498f0320 | 0x145757490 | 0x14574b090 |
| PktLobbyVersionResult | 2 | 0x1498f0380 | 0x145757550 | 0x14574b170 |
| PktLobbyServerListRead | 103 | 0x1498f0e58 | 0x145757260 | 0x14574ad80 |
| PktLobbyServerListReadResult | 104 | 0x1498f0f48 | 0x1457572f0 | 0x14574ae20 |

ID 1 / 2 совпадают с игровыми Version / VersionResult, но схемы отличаются.
Диагностическая отправка игрового Version к CDN-лобби из прежнего этапа
не проверяла этот handshake. Повторной отправки на новом этапе не было.

## Привязка к RdLobbyPeer и подготовка полей

Network construction 0x1467a79e0 устанавливает таблицу 0x149d84d78 в lobby
wrapper: LEA на 0x1467a7a75, затем запись object vptr. Проверены slots:

| Slot | Target | Назначение по связям |
| --- | --- | --- |
| +0x8 | 0x1467aa090 | initialize, устанавливает отдельный lobby dispatcher |
| +0x38 | 0x1467a9360 | RdLobbyPeer::Login |
| +0x40 | 0x1467aae20 | создаёт и заполняет PktLobbyVersion |

Последний target уже был экспортирован с аналитической меткой
`Network_VersionDiagnostics`; существующее тело переиспользовано, дубль seed
не добавлялся. [Lobby sender](HEADLESS-LOBBY-LOGIN.md) при state == 2 вызывает
slot +0x40 до сборки своего кадра. Он использует отдельный send-A с sequence
peer+0x228 и fallback XOR. Полный connect / flush / первый пакет на wire
ещё не исполнялись вместе: нельзя считать эту таблицу доказательством live-входа.

Статически восстановленные источники обычного LobbyVersion:

| Object field | Источник в preparation |
| --- | --- |
| byte +0x10 | constructor очищает поле; полная preparation replay ещё впереди |
| FString +0x18 | AppVersion из global 0x14b520d10 |
| FString +0x28 | Version_CombinedSuffix |
| byte +0x38 | platform selector; для selector 3 записывается 3 |
| FString +0x40 | 0x1415be7e0: cache / GetComputerNameW |
| FString +0x50 | NMDeviceKey через 0x1445c63a0 |
| FString +0x60 | constructor очищает строку, preparation её не заполняет |
| uint32 +0x70 | global 0x14b125530, в проверенном EXE равен 1 |

Имя компьютера не является версией engine: тело getter проверено в Ghidra,
оно вызывает GetComputerNameW. Реальные значения компьютера / устройства
на этом этапе не читались и не сохранялись. Назначение неизвестных raw fields
и принятие сервером не выводятся из совпадения offsets.

## Native codecs и переносимый runtime

`replay-lobby-handshake-codecs.py` исполняет два полных writer и reader
LobbyVersionResult. Использованы прежние настоящие archive primitives и
UTF-8 routines. Allocation / string assignment / free / cookie остаются
ограниченными fixtures; packet и вложенные TimeBase — явные initialized
fixtures. Constructors, подготовка, framing и сеть в новый replay не входят.

| Body | Порядок wire | Минимум |
| --- | --- | --- |
| LobbyVersion | byte +10; строки +18/+28; byte +38; строки +40/+50/+60; LE32 +70 | 16 байт |
| LobbyServerListRead | строки +10/+20; LE32 +30; bytes +34/+35 | 10 байт |
| LobbyVersionResult | LE32 +10; bool +14; два raw LE64 TimeBase; LE16 +38 | 23 байта |

Строки имеют LE16 длину UTF-8 в байтах. Writer сохраняет оба сырых byte values,
включая bool slot запроса списка. Reader нормализует bool к 0 / 1. Полные
20 writer cases проверяют разные строки и raw bytes 0 / 2 / 3 / 255.
Четыре ответа проверяют bool и крайние integer bits; 23 коротких префикса
отклонены. Native reader оставляет extra bytes; runtime требует точный body.

`vampir_core.lobby_packets` содержит три отдельных immutable типа и bounded
encoders / decoder. Все поля заданы явно; нет чтения ОС, генерации идентичности
или перехода к игровым пакетам. Строки скрыты из repr. Локальные бюджеты,
валидация текста и exact-body policy не заявляются правилами сервера.

## Оставшаяся цепочка

Полный ID 104 reader экспортирован: он содержит две record arrays, ещё одну
переиспользуемую array routine, две map collections и дополнительные поля.
Его коллекции ещё не проверены, portable decoder ID 104 не добавлен.
Успешный handler вызывает master model Update только в ветви packet+0x110 == 0;
эта граница уточняет прежнюю краткую запись о source master model.

Подготовка ID 103 найдена в 0x145d45030 и 0x1467aa9f0: конструктор
0x1457451d0 совпадает с таблицей пакета. Поля зависят от настроек, SDK
Netmarble ID и platform selector; неизвестные настройки не заменены догадками.

Прошли шесть новых тестов, четыре прежних LobbyLoginResult и шесть Login
context. Три проверки экспорта Ghidra проверяют источник и текущие таблицы.
Реальная сессия лобби / игры ещё не получена. Далее — connect / flush send-A,
полная подготовка LobbyVersion и decoder списка серверов до игрового endpoint.
