# Vampir — общий указатель найденных функций и связей

## Список secret constants, 19 октября: H04b-secret partial

Общий SHA Windows EXE ниже. `0x1444ddc10`: Mid(2,length−4), split `","`,
chunk helper `0x14451d5c0`, append фрагментов и запятых, замена последней на `}`.
Пустой chunk прерывает сборку; 9 основных и 4 граничных native сценария.
String/RSA/UTF-8 helpers shimmed; native JSON parser/cleanup не исполнялись.
Общий decode_sdk_secret_constants, шесть тестов; один trailing NUL снимается
по связи `0x14451d9ce..0x14451d9dd`. Полная GMC2-конфигурация не получена.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SECRET-LIST.md).
Дальше normal/secret merge и lookup `0x1450e2895` → `0x144553700` для authTokenUrl.

## OAEP checker и один secret chunk, 19 октября: H04b-secret partial

Общий SHA Windows EXE ниже. `0x148405020` исполнен: 24 корректных и 69 ошибочных
входов, SHA/MGF1/memory/error/stack shims, без клиентского RSA arithmetic.
Caller `0x14451d6f2` → формат `0x1494e2540`: BEGIN RSA PRIVATE KEY, тело `%s`.
Диагностики caller подтверждают названия PEM_read_bio_RSAPrivateKey,
RSA_private_decrypt и RSA_padding_check_PKCS1_OAEP_mgf1.
Общий sdk_secret.py: один chunk, optional cryptography backend, Windows synthetic
RSA 2048/3072/4096; полный список/Android не проверены.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-OAEP.md).

## Секретные константы GMC2, 19 октября: H04b partial

Общий SHA Windows EXE ниже. Root `0x14451d5c0`: Base64 wrapper `0x141523200`
→ core `0x14150cd70`; private-key reader chain `0x148405720/0x148433880`;
RSA wrapper `0x148404190`, OAEP `0x148405020`, digest getter `0x148404110`.
Descriptor `0x14a722610` сопоставлен с SHA-256 в OpenSSL 1.1.1t.
26 корректных и 8 граничных native Base64 входов, 16 подготовок аргументов OAEP.
Вызов OAEP перехвачен; RSA/OAEP не исполнены. Общий bounded Base64 decoder,
пять тестов. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SECRET.md).

## Строка GMC2 и передача DECKEY, 18 октября: H04b partial

Общий SHA Windows EXE ниже. Constructor связывает manager+`0xB0` с именем
DECKEY. Root `0x1444c8c60`: lookup через virtual slot `0x28` → локальная строка
ключа → parser `0x1444f0e80` на `0x1444c9587`. Метод lookup ещё не идентифицирован.
Extractor `0x1444e3bc0` → unescape `0x1444f2670` → DecryptXOR `0x1444ddf50`.
43 корректных и 7 граничных native входов, три составных искусственных JSON;
общий sdk_constants.py, пять тестов. Secret constants требуют отдельной обработки.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).

## Параметры SDK и XOR GMC2, 18 октября: H04b partial

Для общего SHA Windows EXE ниже getter `0x144524390` возвращает литерал
`5.2.11`; RefreshSDKConstants вызывает его на `0x1444f3bb3`. Getter
`0x14452b820` получает settings+`0x48` для build, выбирает глобальные строки,
инициализированные `A/B/C` функциями `0x1411b3220/3250/3280`.
Это другое поле, чем окружение GMC2 settings+`0x49`; активные значения неизвестны.
Цикл DecryptXOR `0x1444ddf50` проверен на 42 искусственных входах:
16-битные единицы, повторяющийся ключ, ограниченный захват append.
Общий `sdk_constants.py`, пять тестов; получение ключа и внешняя упаковка открыты.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).

## SDK configuration GMC2, 18 октября: H04b partial

Для общего SHA Windows EXE ниже связаны constructor `0x1444bd970`,
Start `0x144501970`, RefreshSDKConstants `0x1444f38e0`, RequestGMC2 `0x1444f5320`,
callback `0x1444edbb0`, parser `0x1444f0e80`, DecryptXOR `0x1444ddf50`.
7 literals / 8 LEA / 7 roots / 48 constants. Native selector
`0x144501a11..0x144501a46` проверен для всех 256 byte values: settings+0x49
выбирает manager+0x150/160/170/180; unknown values ведут на dev.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Активный mode, template/build/market values и response→auth bases ещё неизвестны.

## SDK auth, 18 октября: H04 partial

Общий SHA Windows EXE ниже. FAuthImpl SignIn root1444fb800 использует
`authUrl/v1/sign-in`; NetmarbleID code/refresh roots1450e2640/1450e2f50 —
`authTokenUrl/v2/access-token`, form client_id/device_key/code или refresh_token.
POST helper14451c570→14451c600, form builder144586a30; native whitelist141c06750
и uppercase hex1415ad670 исполнены 512 раз.24 SDK literals/34 LEA/24 roots.
[Полные source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-AUTH.md).
Общий auth_request.py — offline plan, не login. Config bases/browser code и
SDK→game handoff ещё unknown; пароль не подставлять в PktLogin по догадке.

## Уточнение 18 октября: queue drain → send

Для общего SHA Windows EXE ниже constructor `0x1445e2b7f/0x1445e2b86`
связывает peer+50 с vtable `0x149503b58`, slot 20 → `0x1445e8b70`.
Drain вызывает ordinal WS2_32 import на `0x1445e8c0d`, имя send подтверждено
export table локальной DLL (её SHA в JSON). Consume `0x1445e5ef0`, partial
memmove; errors22/23/37 сохраняют очередь. 61 native cases/5 tests.
[Source/offsets и границы](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
Socket/error/close fixtures; real loopback TCP проверяет только portable pump.

## Уточнение 18 октября: send-B и очередь копии

Общий SHA Windows EXE ниже. Slice `0x144aace6d..0x144aacf89`: ID/sequence/body,
CRC/XOR key=peer+248, sequence=peer+240. Queue call `0x144aacf7d` → `0x1445eac20`
→ append `0x1445e4a90` для peer+170: отдельная копия ciphertext до возврата.
40 native cases/5 tests, preallocated capacities/CRT shims/wake capture;
source overwrite и key variant не меняют queue. Shared send-B encoders/OutboundFrames.
[Source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-SEND-B.md).
Drain/socket и весь Notify→wire не проверены.

## Уточнение 18 октября: receive-B и ID bookkeeping

Общий SHA Windows EXE ниже. Wrapper `0x144aacb50`, key=subobject+0x48,
XOR frame+3, IDword+3 → getter `0x144aa7c40` → lookup `0x144aa8120` →
remove `0x144aa7f40` → sparse free `0x14142eff0`; empty-table notify `0x144aa7870`.
39 native cases/4 tests, manager/listener/registry fixtures, notification list empty;
OnHandler entry capture. Remove идёт до reader, даже для short body. CRC в
исполненном B route не найден; не вывод обо всём транспорте.
[Отчёт, source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-RECEIVE-B.md).

## Уточнение 18 октября: Dispatch и wrapper OnHandler

Общий SHA Windows EXE ниже: `0x14679f510` исполняет ID lookup/body reader и
handler+8 → `0x141535f20` (`488b0148ff6010`) → handler+0x10.
Для PingResult vtable `0x149d810f8` это OnHandler `0x1467670c0`; вход перехвачен,
побочные действия не исполнены. 24 native cases/4 tests, synthetic registry,
native TLS setter `0x144aa6240` и archive destructor chain. Shared receive_packet.py.
[Отчёт, source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-DISPATCH.md).

## Уточнение 18 октября: native второй receive loop

Для общего SHA Windows EXE ниже исполнен slice `0x1445ed572..0x1445ed730`:
helper `0x1445dede0`, thunks `0x1415f6848`/`0x1437113e4`, length probe
`0x144aa9a90`, receive-A `0x144aa9c00`/XOR `0x144aa6ca0` и compaction.
44 cases/5 tests; final callback capture, snapshot/cleanup/free/expired-cleanup
заданы fixtures, не native lifecycle. Shared receive_frame.py: take_receive_a_frame.
[Происхождение, отчёт и пределы](../resource-tools/vampir/HEADLESS-LISTENER-LOOP.md).

## Уточнение 18 октября: block decoder и listener linkage

Источник/SHA — общий Windows EXE, указанный ниже. Native decoder `0x14141ba60`:
166 valid / 86 invalid executions, literal/match/LE16 offset/extended lengths;
copy tables `0x14898cd78`. Общий код block_decode.py, explicit bounded output.
Второй stage root `0x1445ed3e0`: call `0x1445ed723` → thunk `0x1415f6848`
→ slot+0x38 length probe; LEA `0x1445ed65a` → thunk `0x1437113e4` → helper
`0x1445dede0` / indirect call `0x1445def22` → slot+0x40 receive wrapper.
Связь статическая; полный listener loop не replayed. [Provenance и границы](../resource-tools/vampir/HEADLESS-BLOCK-DECODE.md).

Обновлено 18 октября 2026. Начинать с [README.md](README.md).
Общий для экранного бота, [самостоятельного сетевого бота](../vampir-headless/README.md)
и исследования карты. Это навигационный указатель, не полный список функций EXE.
Подробные доказательства и инструменты остаются у соответствующего направления.

Общие данные и исполняемые компоненты: [vampir-shared/README.md](../vampir-shared/README.md).

## Как пользоваться и обновлять

Перед новым исследованием искать здесь и в подробном отчёте. Добавлять найденные
функции сюда, а шаги и историю — в TASKS/WORKLOG соответствующего направления.
Запись должна содержать назначение, адрес/тип адреса, источник и SHA, уровень
подтверждения, ограничения, путь отчёта и способ воспроизведения. Большие таблицы
и дизассемблирование здесь не дублировать. Не заменять старые подтверждения новой
гипотезой; при обновлении клиента хранить результаты отдельно по версии/SHA.

Уровни: **байты/строка** → **ссылка из инструкций** → **связь/vtable** →
**изолированное исполнение** → **живая проверка**. Верхний уровень не следует
автоматически из нижнего. В частности, имя пакета не доказывает ID, wire-format
или пригодность его отправки серверу.

## Источник текущих адресов

Windows `ProjectRED-Win64-Shipping.exe`, собранный клиент, не исходный C++ проект.
Путь: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса ниже — VA с image base `0x140000000`, не файловые смещения.
Версия Windows не объявлена равной Android 1.0.14. При другом SHA адреса
не применять без повторной проверки. Полные provenance — в указанных JSON.

## Вход, обмен и состояние персонажа

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Повторение: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-network-index.py`.
27 точных строк, 31 проверенная LEA-ссылка, 27 unwind roots, 32 фрагмента,
1020 инструкций; missing/rejected=0. Для строк подтверждены bytes/offset/SHA,
для ссылок — границы инструкций и chained unwind root. Root со строкой не
объявляется реализацией одноимённого метода. Getter/serializer/ID ещё связать.

| Найденная строка / назначение | Root VA со ссылкой | Подтверждение / следующий пробел |
|---|---|---|
| UTitleUI::OnSuccessNetmarbleSDKAuth() | 0x14641d560 | Строка/ссылки; не восстановлен обмен почты/пароля на сессию |
| UTitleUI::ProcessNetmarbleSDK() | 0x14641ee20 | Строка/ссылки; вызовы SDK и токены ещё исследовать |
| PacketDispatcher::Dispatch | 0x14679f510 | Строка/ссылки; весь путь receive→decode→dispatch не доказан |
| PacketDispatcher::GetPacketHandler | 0x14679f7b0 | Строка/ссылка; семантику lookup ещё проверить |
| PacketDispatcher::_AddPacketHandler | 0x1467a7250 | Регистрация двух пар дополнительно подтверждена, см. ниже |
| PktLobbyLogin / Result | 0x145754ff0 / 0x145755020 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktLogin / Result | 0x1456e3410 / 0x1456e3440 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktCharacterListRead / Result | 0x1456e2f90 / 0x1456e2fc0 | Строки/ссылки; wire-schema неизвестна |
| PktCharacterSelect / Result | 0x1456e30e0 / 0x1456e3140 | Строки/ссылки; отдельно найден result-handler |
| PktCharacterPosition | 0x1456cd420 | Строка/ссылка; поля позиции ещё не восстановлены |
| PktCharacterMove / Result / Notify | 0x1456cd2d0 / 0x1456cd390 / 0x1456cd360 | Строки/ссылки; отправка движения не реализована |
| PktWorldInfo / UpdateNotify | 0x14581bc60 / 0x14584bef0 | Строки/ссылки; live zone/world ещё не получены |
| PktPing / Result | 0x1456e36b0 / 0x1456e36e0 | Строки/ссылки; частота/формат игрового heartbeat неизвестны |
| PktSkillCastingStart / Result | 0x14583e7a0 / 0x14583e800 | Строки/ссылки; боевые команды не реализованы |
| PktSkillStart / Result / Notify | 0x14583eb00 / 0x14583eb90 / 0x14583eb60 | Строки/ссылки; серверный боевой цикл неизвестен |
| PktActorCombatStateChangeNotify | 0x1456b5940 | Строка/ссылка; поля и применение ещё исследовать |

## Сетевые пакеты: H02, 18 октября

Подтверждены name→vtable→constructor/ID/reader/writer targets для 10 типов
и registration для пяти ответов. Подробная таблица, доказательства, SHA и
команды: [HEADLESS-PACKET-BINDINGS.md](../resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md).
Данные: `code-clues/headless-packet-bindings.json` в общей библиотеке.
ID: Login/LobbyLogin=3, их Result=4; CharacterListRead/Result=101/102,
CharacterSelect/Result=109/110, Ping/Result=16/17.
**ID3/4 совпадают у разных типов**: использовать контекст, не единый глобальный
ID→schema. Доказаны разные фабрики/registration targets; runtime selection ещё unknown.
Name slot+0x38, ID+0x28; writer+0x10/reader+0x20 — targets, не wire-schema.
10 native ID сценариев/4 audit tests прошли, сеть/игра не запускались.

Новые handler targets: LoginResult146765540, LobbyLoginResult14677ec50,
CharacterListReadResult14675dce0, CharacterSelectResult14675e9a0,
PingResult1467670c0 (VA, префикс 0x). Getter/constructor/read/write VA и
registration callsites см. в подробной таблице, не выводить их из ID.

## Primitive IO и Ping payload: H03a, 18 октября

[HEADLESS-PING-CODEC.md](../resource-tools/vampir/HEADLESS-PING-CODEC.md) содержит
полную цепочку, provenance и `code-clues/headless-ping-codec.json`.
Receive Dispatch14679f510 → reader ctor144aa6260 → vtable14961a520 →
u64 reader144aa5bc0/u32 reader144aa59c0 → raw read144aa5ce0.
Dispatch явно передаёт swap=0; тела little-endian16 байт Ping/12 байт Result.
Writer ctor144aa62f0 → vtable14961a5c0 → u64 writer144aa61e0/u32 writer144aa6090
→ raw write144aa6120. Counter helpers144aa68c0/1445ead30; bswap64/32
1445d9f60/1445d9f30. Все адреса VA, префикс 0x; полные source SHA выше.

Primitive IO исполнен настоящими инструкциями, только CRT memcpy подменён
bounded shim. 126 native cases/5 tests, 6 дополнительных replays прошли.
Переносимый stdlib codec: `vampir-shared/vampir_core/ping.py`.
H03 остаётся частичным: output callers144aa9da0/144aaccf0, helpers1445f1230/
144aa6ca0 и framing требуют разбора. Размер 5 до body относится к dispatcher
input, не ко всему wire frame. Handler dispatch вызывает slot+8; связь с
OnHandler+10 ещё проследить. Signedness/field timing semantics не установлены.

## Более глубокие подтверждения

Первый receive transport: `UxTcpPeer::_HandleRecvBuffer`, root0x1445ed3e0,
диагностическая LEA0x1445ed4cc. Native slice0x1445ed403..0x1445ed562:
length 23/compressed bit 23 → copy/decompress0x14141ba60 → второй буфер,
append0x1445e4a90/resize0x1445de6e0/memmove. 62 native cases / 5 tests.
[HEADLESS-TRANSPORT-STAGE.md](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md),
report `code-clues/headless-transport-stage.json`, shared transport_header.py.
Общий decompressor/listener loop/CRC и send queue ещё не готовы.
Length probe0x144aa9a90 — второй уровень, не raw compressed framing.

H03b.2b keyflow: бывший candidate0x144aab330 подтверждён как setter peer+248.
PktKeyChangeNotifyHandler0x146765050 строит PktKeyChanged, вызывает send+38,
затем setter+40. IDs Notify11/ack12, тела raw64LE8 байт; 20 native flow cases
подтвердили old key во время send и update после него, даже при send false.
[HEADLESS-KEY-CHANGE.md](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md),
`code-clues/headless-key-change.json`; shared `vampir_core/key_change.py`.
Полные packet/vtable/IO/registration адреса в таблице отчёта. Server key generation,
initialauth/receive integrity/send queue всё ещё неизвестны.

H03b.2b partial: length probe0x144aa9a90 подтверждён 156 native cases;
wrapperA0x144aa9c00 —13 native cases до callback. Vtables0x14961af58/0x14961b8f0
у main+200 имеют length+38/receive+40. Factory0x14678ec40 через setter0x144aab300
назначается в peer+238; wrapperBcallback из того же поля вызывает Dispatch0x14679f510.
Статическая linkage доказана, end-to-end replay нет. Candidate keysetter0x144aab330
ещё без caller/source семантики. [HEADLESS-RECEIVE-ENVELOPE.md](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md),
`code-clues/headless-receive-envelope.json`; shared receive_frame.py имеет
дополнительную local bounds policy. CRC/incoming layout/keyflow ещё unknown.

H03b.2a: native send-A slice0x144aa9e6a..0x144aa9f45 подтверждён 20 сценариями;
length 24+CRC32+(ID16+sequence16+body), XOR от offset 3. Ping frame 27 байт.
Sequence connection+228 обновляется native16bit с wrap 65535→0.
Stream append0x144aa6330, buffer getter0x144aa5f80, word writer0x144aa6060;
подробный provenance/[HEADLESS-SEND-FRAME.md](../resource-tools/vampir/HEADLESS-SEND-FRAME.md).
Общий `vampir_core/send_frame.py`, `code-clues/headless-send-frame.json`.
Receive/context/key ещё unknown; layout перед Dispatch не отождествлять с send frame.

H03b.1: CRC initializer0x1418ba360/update0x1445f1230/table0x1495046f0,
XOR0x144aa6ca0. Подтверждены 252 native executions/5 tests; общий модуль
`vampir-shared/vampir_core/frame_primitives.py`. Send roots0x144aa9da0/0x144aaccf0,
receive0x144aa9c00/0x144aacb50; XOR пропускает 3 байта. Session key source,
полный frame и receive validation ещё unknown.
[HEADLESS-FRAME-PRIMITIVES.md](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md),
`code-clues/headless-frame-primitives.json` в общей библиотеке.

| Функция/структура | Адреса VA | Подтверждение и подробный источник |
|---|---|---|
| ContentsUnlockListReadResult / RequestResult | handlers 0x146763cd0 / 0x146763da0, registration 0x1467a7250 | Пары handler/packet, vtable и getters ID1007/1009; не сетевой API. [UNLOCK-REGISTRATION.md](../resource-tools/vampir/UNLOCK-REGISTRATION.md), `code-clues/lock-registration-events.json` |
| PktCharacterSelectResultHandler::OnHandler | 0x14675e9a0 (LEA имени 0x14675e9d3) | Имя и отдельные readiness-вызовы; весь state initialization не доказан. Тот же отчёт |
| Guard результата пакета | 0x1467a8e10 | Статические ветви результата/ошибок. [PACKET-RESULT-GUARD.md](../resource-tools/vampir/PACKET-RESULT-GUARD.md) |
| PktStat reader / writer | 0x1457f0540 / 0x1457f4360 | key 32/raw64 и native исполнения с synthetic primitive IO, wire неизвестен. [ATTRIBUTES.md](../resource-tools/vampir/ATTRIBUTES.md), `code-clues/stat-packet-evidence.json` |
| PktStatCategoryData reader / writer | 0x1457f0590 / 0x145784940 | category8/raw64, read clamp≤29; реальные категории не установлены. Тот же отчёт |
| Форматирование значения характеристики | 0x145dda3a0 | Native ветви scaling/display; не формулы урона. ATTRIBUTES.md, `code-clues/stat-format-routes.json` |
| Проекция координат на navmesh | 0x1452451b0 | Изолированное исполнение с explicit inputs; не live position. [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md) |
| Polygon query | 0x1452457b0 | Native offline query; active mesh/permissions отдельно. MAP-ATLAS.md |
| Straight path/funnel | 0x145248b20 | Native offline corridors; не подтверждение движения персонажа. MAP-ATLAS.md |
| Базовая инициализация nav-фильтра | 0x1452b7120 | Native explicit SupportedArea/CDO scenarios; live selection отдельно. MAP-ATLAS.md |

## Другие общие индексы

- [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md): CSV, архивы, карты, изображения.
- [NATIVE-UI-LINKS.md](../resource-tools/vampir/NATIVE-UI-LINKS.md): код→окна; `query-native-ui.py` ищет с проверкой источника.
- [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md): окна, контролы, контейнеры и геометрия.
- [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md): квест→задача→действие/обучение.
- [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md): полная история карты и специализированные native отчёты.

## Автобой — пока отдельные зацепки

В `native-enums.json`: EAICombatMode Auto=0/Target=1;
ESupportModeBehaviorAutoCombatType CombatStatsRecord=0/LocationMemory=1/Area=2.
В CSV: Skill. SyncAutoCombat (pakchunk1 entry1505), OnEntryAutoCombat/
AutoCombatLeaveWorld/movePacketIntervalTime (entry1574). Источники и SHA CSV —
`table-study/index-pakchunk1-Windows.json`. Это данные/enum, не найденные
реализации функций и не доказательство серверного автономного фарма.
