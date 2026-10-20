# Vampir: где искать данные

## Поля UserInfo и writer NID map, 20 октября

Двенадцать native-сценариев writer, 33 прямые связи, optional gates и getter
updates. Verified callers указывают следующие функции 0x1445ab9f0 / 0x144550e40;
runtime и сеть не менялись.
[Источники, SHA и таблица](HEADLESS-NID-USER-INFO-FIELDS.md).

## Основная строка NID metadata, 20 октября

Шесть native-сценариев collector / selector и bounded encoder; повтор I_World,
пустой и недоступный UserInfo различены. Реальные значения и optional branches
ещё не проверены; runtime Login не менялся.
[Источники, SHA и границы](HEADLESS-NID-METADATA.md).

## ClientVersion установленного manifestlist, 20 октября

Пять native-сценариев связали JSON key ClientVersion с patch object+0x1b0.
Snapshot содержит Revision258392; parser и явный ввод runner добавлены.
Реальный Login с этим числом снова вернул InvalidState 16.
[Источники, SHA и границы](HEADLESS-PATCH-CLIENT-VERSION.md).

## Число Login из patch-контекста, 20 октября

Десять native-сценариев BeginGame до global store, настоящий системный _wtoi,
отдельный server ID. Актуальная строка revision ещё требует проверки
загрузчика patch state; runtime и сеть не менялись.
[Источники, SHA и границы](HEADLESS-LOGIN-REVISION-INPUT.md).

## Новый ответ Login 16 / InvalidState, 20 октября

После сообщённой замены телефонов на прежнем аккаунте / JP 251 получен
Version 0 / Login 16. Полный native mapper связал код с InvalidState;
runtime label и закрытие без запроса персонажей проверены. 13 проверок прошли.
[Источники, SHA и границы](HEADLESS-RESULT-ERROR-16.md).

## Локальный адрес соединения в Version, 20 октября

Пять native-сценариев настоящего endpoint getter до Version; SOCKS bound
metadata отделены от loopback proxy hop. JP 251 с пустым контекстом снова
вернул Login 58; 20 проверок прошли. Причина отказа не доказана.
[Источники, SHA и границы](HEADLESS-CONNECTED-LOCAL-ADDRESS.md).

## Проверка SDK-страны по серверной записи, 20 октября

15 native-сценариев SDK response → country setter / getters → полный predicate.
Свежий SDK HK проходит array50 всех 20 JP-записей. Runtime получил фильтр
и проверку списка без игрового сокета; 20 проверок прошли.
[Источники, SHA и границы](HEADLESS-SERVER-COUNTRY-POLICY.md).

## Состояние выбранного сервера и проверка JP, 20 октября

256 исполнений native-условия record+0x35 и сброса двух выбранных ID.
Свежие JP 251–270 не имеют исключаемых значений 2/3; JP 251 снова вернул
Login 58. Array50 сравнивается с GetJoinedCountryCode; заполнение SDK settings,
имена состояний и остальные flags ещё требуют связи.
[Источники и границы](HEADLESS-SERVER-ENTRY-STATE.md).

## Вызов owner slot из кода движка, 20 октября

`replay-world-owner-dispatch.py`: 45 сценариев функции `0x14430da70` с указателем
в `+0x158`. Подтверждена передача получателя в настоящий метод владельца.
Заполнение поля и выбор класса после ID110 ещё открыты. Ghidra: 203 функции,
82 предупреждения.
[Адреса, SHA, команды и границы](HEADLESS-WORLD-OWNER-DISPATCH.md).

## Владельцы с policy 3 и путь к ID205, 20 октября

`replay-world-finish-owner.py`: 39 основных сценариев, 6 отдельных callbacks,
6 исполнений настоящей подготовки состояния 4. Конструкторы и таблицы связаны
с сервисным путём ID205. Ghidra: 198 функций, 80 предупреждений.
Источник engine-вызова и реальное перемещение ещё не проверены.
[Источники, SHA, команды и границы](HEADLESS-WORLD-FINISH-OWNER.md).

## ID206: коллекции, декодер и общий сценарий, 20 октября

`replay-world-move-finish-collections.py`: 16 непустых тел, 309 коротких префиксов.
`replay-world-move-finish-pipeline.py`: семь сценариев чтения до обработчика.
Общий декодер поддерживает всё тело с явными лимитами. Ghidra: 190 функций,
74 предупреждения. Реальная сессия ещё не выполнена.
[Источники, API, SHA и команды](HEADLESS-WORLD-MOVE-FINISH-DECODER.md).

## Минимальное тело ID206, 20 октября

`replay-world-move-finish-reader.py`: 18 полных тел с пустыми массивами,
81 отклонённый короткий префикс. Ghidra: 189 функций, 74 предупреждения.
Новые readers массива `+0xe8` экспортированы; непустое исполнение ещё открыто.
[Схема, источники, SHA и команды](HEADLESS-WORLD-MOVE-FINISH-READER.md).

## ID205: условие, пустое тело и кадры, 20 октября

`replay-world-move-finish-send.py` проверяет все значения состояния, отложенный
переход, конструктор и четыре кадра. Общий encoder совпал с native-результатами.
Ghidra: 182 функции, 74 предупреждения. Источник вызова после ID110 ещё открыт.
[Адреса, SHA, команды и границы](HEADLESS-WORLD-MOVE-FINISH-SEND.md).

## ID206 и переход после завершения перемещения, 20 октября

`replay-world-move-finish.py`: обработчик ответа → метод сервиса → настоящий
виртуальный слот `+0x78` → состояние 6. Проверены 10 сценариев и привязка
пакета по регистрации, таблице и ID. Объект ответа задаётся тестом;
его wire-тело ещё не декодируется. Ghidra: 180 функций, 74 предупреждения.
[Адреса, SHA, команды и границы](HEADLESS-WORLD-MOVE-FINISH.md).

## Потребитель состояния и отдельный переход, 20 октября

`replay-selection-status-consumer.py` проверяет все 256 значений байта,
конструктор запроса, короткие методы и общий сценарий с ID110 и отдельно
вызванным методом жизненного цикла. Автоматический переход не доказан.
Ghidra: 177 функций, 72 предупреждения.
[Источники, SHA и воспроизведение](HEADLESS-SELECTION-STATUS-CONSUMER.md).

## Запись состояния после ID110, 20 октября

`replay-selection-status.py`: 64 отдельных сценария и 6 путей от ответа до
`service+0x30`. Функция `0x1456140f0` записывает состояние и передаёт текст;
прежнее обозначение как события с подписчиками уточнено. Ghidra экспортировала
173 функции, получены 70 предупреждений.
[Источники, SHA и ограничения](HEADLESS-SELECTION-STATUS.md).

## ID110: обработчик и перенос данных, 20 октября

`replay-character-select-handler.py` связывает тело ответа, функции чтения,
фильтр результата, обработчик и применение данных. Сценарии проверяют записи
в состояние и вызовы на границах подсистем. В Ghidra отдельно разобраны
получение объекта персонажа и функция обновления заголовка окна.
[Источники, SHA, сценарии и ограничения](HEADLESS-CHARACTER-SELECT-HANDLER.md).

## ID110: обе таблицы и общий декодер, 20 октября

`replay-character-select-maps.py` проверяет обе необязательные таблицы, вложенные
массивы и повторные ключи. `replay-character-select-fields.py` проверяет скаляры
и строки, включая Unicode. Общий `character_select_result.py` читает всё тело
ответа с явными лимитами. Принятие выбора и реальная сессия ещё требуют проверки.
[Источники, схемы, API и воспроизведение](HEADLESS-CHARACTER-SELECT-DECODER.md).

## ID110 nonempty arrays, 20 октября

Ghidra 165 функций/63 warnings; replay-character-select-collections.py:
34 whole bodies/465 short prefixes, все 11 arrays, actual append/construct/read.
Bounded allocator/cleanup captures; both maps/portable decoder/handler/live
остаются открытыми. Следующие map98 readers указаны без повторного поиска.
[Адреса, схемы, отчёты, SHA и команды](HEADLESS-CHARACTER-SELECT-COLLECTIONS.md).

## ID110 минимальный reader и spatial apply, 20 октября

Ghidra 151 функций/63 warnings. Отдельный math export через собственные Ghidra
machine blocks, source/tool/file/range SHA. replay-character-select-result.py:
268 минимальных 203 byte bodies/all256 headings, actual SSE2 math/CRT imports.
replay-character-select-apply.py:22 cases/raw vector copy/angles. Непустые
collections/полный decoder/handler/session/world position semantics открыты.
[Отчёты, SHA, адреса и границы](HEADLESS-CHARACTER-SELECT-RESULT.md).

## ID109 callers/send и rawF0 source, 20 октября

Ghidra 109 функций/58 warnings. Existing validated E8 scanner: state getter
105 calls/0 failures; +f0 candidates не означают receiver identity.
replay-character-state-f0.py: ID102→actual setter, 45+12 cases.
replay-character-select-send.py: WaitingEnd и signed index callers до полной
очереди, 27+34 cases/19 frames. Shared selected-record builder без I/O.
[Источники, SHA, callback/field addresses и продолжение](HEADLESS-CHARACTER-SELECT-SEND.md).

## ID102 extensions и body→handler, 20 октября

Ghidra 106 функций/53 warnings. replay-character-list-extensions.py:
30 whole bodies/489 short prefixes, actual appearance/optional readers и insert.
replay-character-list-handler.py: 45 native cases до covered state/UI captures.
Общие decoder обеих ветвей и preferred_character_index, три обязательных budgets.
[Адреса, схемы, SHA и продолжение](HEADLESS-CHARACTER-LIST-EXTENSIONS.md).

## CharacterList/Select codecs и actual owner, 20 октября

Ghidra 101 функция/53 предупреждения; actual constructor/policy 1→RequestA,
12 native list bodies/229 short prefixes, 16 select writer vectors и общие
bounded codecs. Две list extensions остаются unsupported; lifecycle/handler 102/
ID110/live session открыты. [Источники и продолжение](HEADLESS-CHARACTER-CODECS.md).

## Прямой caller slot 90, 20 октября

Существующий E8 scanner: 505 checked getter calls, 16 unresolved, 9 root
decode failures. Найден caller 0x1468f1d70. Новый native replay проверяет
32 комбинации до actual RequestA/constructor/send capture.
[Источники, SHA и ограничения](HEADLESS-CHARACTER-LIST-CALLER.md).

## Selection lifecycle: общий результат, 20 октября

Ghidra export расширен до 76 функций/42 предупреждений.
replay-selection-lifecycle.py сохраняет 8 native cases с SHA участков в
code-clues/selection-lifecycle-replay.json. Регистрация delegates статическая;
слот 90 и runtime завершение загрузки не подтверждены.
[Источники, SHA и ограничения](HEADLESS-SELECTION-LIFECYCLE.md).

## World.Id2 → CharacterSelect LevelPath

replay-world-state-label.py: actual ctor/field-store/lookup/getter, real base
и audited current patch CSV rows. Runtime map population не исполнялась.
[HEADLESS-WORLD-STATE-LABEL.md](HEADLESS-WORLD-STATE-LABEL.md).

## Selection state lookup/data boundary

replay-selection-state-lookup.py: 13 native hash/descriptor/label-caller cases.
Key2 label остаётся unknown; generic registry loaders только static-export.
[HEADLESS-SELECTION-STATE-LOOKUP.md](HEADLESS-SELECTION-STATE-LOOKUP.md).

## Selection state2/deferred boundary

replay-selection-state-transition.py: 10 preparation + 12 callback native cases,
SDK/readiness gates, actual state/pending/flags и schedule capture.
[HEADLESS-SELECTION-STATE-TRANSITION.md](HEADLESS-SELECTION-STATE-TRANSITION.md).

## Selection singleton/derived table/CharacterSelect handoff

replay-selection-service.py: 2 constructor-prefix outcomes и 4 native select
cases. Derived slot 90=requestA, slot 50→actual packet 109/handoff110 capture;
slot 40 пока static-only. [HEADLESS-SELECTION-SERVICE.md](HEADLESS-SELECTION-SERVICE.md).

## WaitingEndNotify handler → CharacterList request

replay-waiting-end-character-request.py: 24 cases, registration/table/ID 27,
actual predicate type gates, tail requestB→ID 101 send capture.
[HEADLESS-WAITING-END-CHARACTER-REQUEST.md](HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## Post-Login reset и отдельные CharacterList requests

replay-character-list-boundary.py: 8 reset cases, 2 request entries,
actual singleton ctor/getter/derived slot, ID 101/empty writer leaf.
Send/container backends captured, Login→request caller edge ещё не доказан.
[HEADLESS-CHARACTER-LIST-BOUNDARY.md](HEADLESS-CHARACTER-LIST-BOUNDARY.md).

## LoginResult handler / result gates / state writes

replay-login-result-handler.py: 38 body→handler cases, native memory-write
trace, signed early exit, selected-server update, SDK и covered error gates.
Ghidra: 33 функции, включая post-state target. Backends/callbacks captured.
[HEADLESS-LOGIN-RESULT-HANDLER.md](HEADLESS-LOGIN-RESULT-HANDLER.md).

## LoginResult body / nested time readers

replay-login-result-reader.py: 21 full vectors, 332 short inputs и trailing
case. Actual constructor/readers/stdstring/UTF-8; assign/growth/alloc fixtures.
Shared LoginResultBody decoder. Ghidra seeds/export: 32 функции/15 warnings.
[Порядок полей, SHA и границы](HEADLESS-LOGIN-RESULT-READER.md).

## Login request handoff и полный send до очереди

replay-login-send-path.py: 34 native cases, 29 frame vectors, source-bound
singleton getter/derived send table, lookup collision chain и timeout.
Request container mutation/notify captured; drain/socket/LoginResult открыты.
[HEADLESS-LOGIN-SEND-PATH.md](HEADLESS-LOGIN-SEND-PATH.md).

## Login packet writer и переносимый body

replay-login-packet-writer.py: 25 native vectors, 40 raw IO failure fixtures,
packet writer/archive vtables, UTF-8 и raw bool bytes. LoginPayload общий,
проверяет всё тело до возврата. Request handoff/frame/server ещё открыты.
[Порядок полей, SHA и границы](HEADLESS-LOGIN-PACKET-WRITER.md).

## Выбор инструментов: Ghidra / CUE4Parse / Dumper-7

[ANALYSIS-TOOLS.md](ANALYSIS-TOOLS.md): постоянное правило выбора, установка
с закреплёнными SHA/lock-файлом, проверка четырёх PAK и трёх loose headers,
сборка Dumper-7 без внедрения. Все дистрибутивы и отчёты вне Git.

## Ghidra batch / псевдокод и call graph

install-ghidra-tools.py + pinned lock, build-ghidra-manifest.py, Java exporter,
run-ghidra-export.py и verify-ghidra-export.py. 22 функции, отдельный reusable
проект и immutable runs вне Git; стабильный ghidra/INDEX.md в библиотеке.
[Инструкция и проверенные ограничения](HEADLESS-GHIDRA.md).

## Login packet field replay

replay-login-packet-fields.py: 16 native scenarios prefix/constructor/cached
SDK getters/field copies. Source NetmarbleId/token consumers разделены;
string/policy/collector/handoff fixtures, old cache не fresh auth proof.
[Источники, SHA и границы](HEADLESS-LOGIN-PACKET-FIELDS.md).

## VersionResult native handler replay

replay-version-result-handler.py: 39 scenarios ID2/read 17/Dispatch/handler/
bounded result gate. Constructor/registration/table/name source-bound;
Login routine captured at entry, full body/SDK inputs не исполнены.
[Источники, SHA и границы](HEADLESS-VERSION-RESULT-HANDLER.md).

## Version full send path replay

replay-version-send-path.py: 18 scenarios wrapper/thunk/send-B/Version writer/
CRC/XOR/owning queue. 14 frames независимо сверены, 4 gates без writer/queue.
Metadata/filter/allocator/cleanup fixtures; actual socket/server response нет.
[Источники, SHA и границы](HEADLESS-VERSION-SEND-PATH.md).

## Version packet writer replay

replay-version-packet-writer.py: 14 native vectors actual writer/UTF-8/archive.
Тело пакета перенесено в общий version_packet.py, bounded strict local policy.
Allocation/capacity fixtures; frame/send/server response ещё открыты.
[Источники, SHA и границы](HEADLESS-VERSION-PACKET-WRITER.md).

## Connected version packet replay

replay-connected-version-packet.py: 6 native scenarios, actual game callback
и PktVersion ctor/name/ID/send binding. Getters/string primitives/send fixtures;
packet writer и VersionResult/Login не исполнялись.
[Источники, SHA и границы](HEADLESS-CONNECTED-VERSION-PACKET.md).

## Transport connected delegate replay

replay-transport-connected-delegate.py: 12 native scenarios, constructor tail,
actual allocator wrapper/bridge/action и source-bound game vtable target.
Resize/identity fixtures; game callback body/Login не исполнялись.
[Источники, SHA и границы](HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).

## Socket ready notification replay

replay-socket-ready-notification.py: 10 native scenarios, две реальные
рассылки и transport recipient, source-bound constructor/registration/vtables.
Owner callback, configuration/endpoint helpers остаются captures/fixtures.
[Источники, SHA и границы](HEADLESS-SOCKET-READY-NOTIFICATION.md).

## Socket error option replay

replay-socket-error-option.py: 8 native readiness integrations и 95 direct
selector calls, source vtable/PE import/DLL export. Code и switch data
разделены; syscall/notification recipients остаются fixtures.
[Источники, SHA и границы](HEADLESS-SOCKET-ERROR-OPTION.md).

## Socket readiness job replay

replay-socket-readiness-job.py: 14 native scenarios, mode scheduling,
real ioctl wrapper/select caller и completion leaf. Worker ограничен
одной iteration; syscall/scheduler/option/dispatch fixtures.
[Источники, SHA и границы](HEADLESS-SOCKET-READINESS-JOB.md).

## Winsock error mapping replay

replay-winsock-error-mapping.py: 43 native integrations mapper/wrapper,
constructor/global/vtable binding, отдельно code/switch table и DLL export.
Системный last error/прочие engine slots — fixtures, real readiness не проверена.
[Источники, SHA и границы](HEADLESS-WINSOCK-ERROR-MAPPING.md).

## Socket connect result replay

replay-socket-connect-result.py: 16 native scenarios lower/wrapper,
sockaddr bytes, imports/exports, raw error allowlist и wait gates.
Platform/mode/error/wait/lifetime остаются fixtures/captures.
[Источники, SHA и границы](HEADLESS-SOCKET-CONNECT-RESULT.md).

## Resolved socket setup replay

replay-resolved-socket-setup.py: 7 native scenarios, listener dispatch,
recipient и socket creator. Source-bound vtables и local DLL export SHA;
Winsock/mode/connect/options и lifetime primitives — fixtures/captures.
[Источники, SHA и границы](HEADLESS-RESOLVED-SOCKET-SETUP.md).

## Resolver job run/results replay

replay-resolver-job-results.py: 8 native integrations с source-bound
job slots/imports, family traversal/order swap и completion gates.
Winsock/vector/dispatch/scheduler остаются fixtures/captures.
[Источники, SHA и границы](HEADLESS-RESOLVER-JOB-RESULTS.md).

## Connect resolver handoff replay

replay-connect-resolver-handoff.py: 12 native scenarios, actual lower
connect/registration insert/lexical helper/job stores. Resolver parser,
queue/reset/lookup и lifecycle явно ограничены fixtures/captures.
[Источники, SHA и границы](HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## Game connect target replay

replay-game-connect-target.py: 13 native scenarios полного connect caller
после BeginGame target setters, primary/override/port guards, inline/heap
string и endpoint constructor. ASCII primitives/lower connect fixtures.
[Источники, SHA и границы](HEADLESS-GAME-CONNECT-TARGET.md).

## BeginGame server lookup/target replay

replay-begin-game-server-target.py: 11 native scenarios, actual collision
walk/value+8 и четыре setters. Sentinel/map/state inputs — fixtures;
успешный stop до connection/UI tail и socket calls.
[Источники, SHA и границы](HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## Title state/BeginGame gate replay

replay-title-auth-state.py: 10 native сценариев отдельных title head/tail
и реального IsSignIn wrapper/getter/call-site gate. UI middle/blacklist,
context/string effects и полный BeginGameImpl остаются за границей.
[Источники, SHA и границы](HEADLESS-TITLE-AUTH-STATE.md).

## Title auth-success notification replay

replay-title-auth-notification.py: семь native сценариев полного
silent/game manager routing с реальным broadcast/action и source-bound
title target. CDO/channel/idp/policy и UI handler явно ограничены fixtures.
[Источники, SHA и границы](HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## Game PGS branch replay

replay-game-pgs-branch.py: четыре native интеграции, реальный provider
virtual call/Windows SignIn body, diagnostic/vtable provenance. Acquisition,
result constructor/helper и TFunction lifecycle имеют явные fixture boundaries.
[Источники, SHA и границы](HEADLESS-GAME-PGS-BRANCH.md).

## Game success broadcast replay

replay-game-success-broadcast.py: 12 native integrations с empty/live/
expired/null/mixed/two-live списками и child pointer null/non-null.
Array lifecycle/prune и дочерний virtual target — fixtures/captures.
[Источники, SHA и границы](HEADLESS-GAME-SUCCESS-BROADCAST.md).

## Silent dispatcher/game integration

replay-silent-game-dispatch.py: 12 native cases, silent dispatcher/bridge/
game callback в одной цепочке. Response JSON gates и scheduler — отдельные
неисполненные границы; source/SHA и дальнейшие задачи сохранены.
[Источники, SHA и границы](HEADLESS-SILENT-GAME-DISPATCH.md).

## Channel silent handoff

replay-channel-silent-handoff.py: 8 channel и 4 Auth gate scenarios.
Native support/GetAuth, forwarding player/callback и проверка No PlayerID.
Provider selection и request/response silent path ещё открыты.
[Источники, SHA и границы](HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## Game AutoSignIn result replay

replay-game-auto-sign-in-result.py: 15 native cases, leaf getters,
weak-owner/result branches и source-bound descriptor chain.
Внешние действия и success game instance — captures/fixture.
[Источники, SHA и границы](HEADLESS-GAME-AUTO-SIGN-IN.md).

## SDK result dispatcher и delegate bridge

replay-sdk-result-dispatch.py: 8 базовых и 8 native binding сценариев.
Фактические dispatcher/binder/clone/invoke; task scheduler и TFunction storage
имеют явные fixture boundaries. Отчёт, SHA и дальнейшие связи сохранены.
[Источники, SHA и границы](HEADLESS-SDK-RESULT-DISPATCH.md).

## SDK sign-in completion

replay-sdk-sign-in-completion.py: 16 сценариев, фактический SetSignIn,
idpInfo/channel и capture вызова dispatcher. Общий offline parser отделён
от более разрешающего поведения native callback.
[Источники, SHA и границы](HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## Native response variant/string conversion

replay-sdk-response-variant.py: 10 cases, реальный converter/AsString/
TryGetString и _wtoi. JSON object/factory selection/FString assignment fixtures.
[Source/SHA/границы](HEADLESS-SDK-RESPONSE-VARIANT.md).

## SDK response validation gates

replay-sdk-sign-in-response-gates.py: 18 native cases, 4 leaf getters/predicates
и actual Windows _wtoi import. Variant converter только static, JSON fixtures.
[Source/SHA/границы](HEADLESS-SDK-RESPONSE-GATES.md).

## SDK sign-in response field traversal

replay-sdk-sign-in-response-fields.py: auth constructor и 13 native status/
resultData/playerInfo/player cases. Earlier errors/full callback не исполнены.
[Отчёт/SHA/границы](HEADLESS-SDK-SIGN-IN-RESPONSE.md).

## Native migration allocation wrapper chain

replay-sdk-migration-allocation.py: 10 cases native wrappers → fixture backend,
затем native byte/AES/HEX. Wrapper не гарантирует zero tail; реальный backend
не установлен. [Отчёт/SHA/границы](HEADLESS-SDK-MIGRATION-ALLOCATION.md).

## Token container и channelKey migration

replay-sdk-token-payload.py: 16 native caller fixtures с explicit primitives.
replay-sdk-channel-migration-path.py: 8 native length/byte/AES/HEX cases.
[Source/SHA/границы подписи и tail initialization](HEADLESS-SDK-TOKEN-PAYLOAD.md).

## NID suffix native byte/AES replay

replay-sdk-nid-path-suffix.py: 6 synthetic cases, actual AES-NI code,
caller transform и hex writer loop. AES dispatch/key conversion/formatting
fixtures явно ограничены. [Source/SHA](HEADLESS-SDK-NID-SUFFIX.md).

## SDK auth-specific directory gate

replay-sdk-storage-auth-path.py: 8 native Load gate/compare/join fixtures;
SetupServiceSettingPath и auth command-context extraction статические sources.
[Отчёт/SHA/границы](HEADLESS-SDK-AUTH-PATH.md).

## Load device fields и полный default filename

replay-sdk-load-device-fields.py: 16 native field-copy/dispatch fixtures.
replay-sdk-storage-filename.py: 3 constructor/default filename/join fixtures.
[Source/SHA](HEADLESS-SDK-LOAD-DEVICES.md). Active context и файловый I/O не проверены.

## NID web/token device key mapping, 19 октября

replay-nid-device-context.py: 3 native key/getter/pair slices. Web deviceKey
и OAuth device_key берут NID-specific getter, не SDK sign-in DeviceKey.
[Source/SHA/границы](HEADLESS-NID-DEVICE-CONTEXT.md).

## SDK Save/Load/path и NID device key, 19 октября

build-headless-sdk-storage.py: 26 static fragments и initializer bindings.
replay-sdk-storage-path.py: 6 native directory fixtures с explicit base getter.
[Отчёты/SHA и открытые зависимости](HEADLESS-SDK-STORAGE.md).

## SetDeviceKey compare/write body, 19 октября

replay-device-key-setter.py: 56 native setter cases + 12 getter integrations.
Native ASCII compare/table reused; platform/storage/FString dependencies
ограничены явно. Save/path source fragments сохранены для следующего этапа.
[Отчёт/SHA/границы](HEADLESS-DEVICE-SETTER.md).

## Native device lifecycle, 19 октября

replay-device-key-lifecycle.py: 8 full NM getter fixtures с повторным вызовом,
12 DeviceKey source/save-gate fixtures. Native constructor/default formatter
и hex writer; storage/parser/platform/setter/Save fixtures/captures.
[Отчёт/SHA/границы](HEADLESS-DEVICE-LIFECYCLE.md).

## SDK device identity, 19 октября

build-headless-device-identity.py: static storage/getter/PE imports, 19 fragments.
replay-device-guid-format.py: три native format=0 fixtures.
[Источник, SHA и открытые зависимости](HEADLESS-DEVICE-IDENTITY.md).
Фактическая identity не читалась; Android/server challenge не доказаны.

## SDK SignIn request preparation, 19 октября

replay-sdk-sign-in-body.py: 4 native body + 8 native default header/method
fixtures, key/build initializers и auth constructor leaf; JSON/getters/network
зависимости явно ограничены. [Отчёт/SHA](HEADLESS-SDK-SIGN-IN.md).
Real public authUrl binding проверен offline. SDK response — следующий этап.

## NID credential adoption continuation, 19 октября

replay-nid-credential-adoption.py исполняет OnResult continuation/ctor/manager/
GetObject с Save/clear/JSON/map captures. Четыре fixtures подтвердили
provider20 → SDK credential33 и два JSON fields; persistence не выполнялась.
[Отчёт/SHA/границы](HEADLESS-NID-CREDENTIAL.md). SDK SignIn/request остаётся следующим.

## SDK percent byte loop / callback query, 19 октября

replay-sdk-percent-decode.py сохраняет decoder/URI/getter/map fragments и
147 fixtures настоящего byte loop/strlen. UTF conversions — явные границы.
[Отчёт/SHA/ограничения](HEADLESS-SDK-PERCENT.md). Native duplicate/full URI
поведение ещё не исполнено; общий callback parser использует local policy.

## Native NID primitive replay, 19 октября

replay-nid-result-primitives.py сохраняет parser/channel/init bytes и CRT import
bindings. Native helpers + настоящий локальный CRT: 28 numeric, 45 channel,
6 integration fixtures; explicit remaining shims/captures.
[Отчёт/SHA/ограничения](HEADLESS-NID-PRIMITIVES.md). Никакого account/network I/O.

## OnResult native validation replay, 19 октября

replay-nid-result-validation.py: 22 synthetic fixtures, настоящие caller branch/
copy instructions; map/hash/parser/channel/SDK dependencies явно ограничены.
Сохранены missing/empty outcomes и раздельные settings arguments.
[Отчёт, SHA и границы](HEADLESS-NID-VALIDATION.md). Аккаунт/сеть не используются.

## Email result: web replay и compiled dispatcher, 19 октября

inspect-nid-auth-result.py проверяет сохранённый web snapshot и исполняет
выбранные helpers с synthetic state. build-headless-nid-result.py сохраняет
OnDeepLink/OnResult и 14 global initializer bindings из pinned EXE.
[Отчёты, SHA256 и ограничения](HEADLESS-NID-RESULT.md). Новых запросов нет.
Native token adoption и SDK session пока не доказаны.

## Публичный NID web snapshot и email contract, 19 октября

capture-netmarble-auth-web.py сохраняет HTML и объявленный module script;
inspect-nid-auth-web.py проверяет SHA и воспроизводит выбранные JS helpers.
build-headless-email-auth.py индексирует отдельные EmailAuth/NID SDK функции.
Тяжёлые assets и отчёты находятся вне Git; пути/SHA записаны в
[HEADLESS-NID-EMAIL.md](HEADLESS-NID-EMAIL.md). Login POST не выполнялся.
Web assets обновляются отдельно от EXE: новый snapshot требует сверки anchors.

## Public GMC2 success snapshot, 19 октября

Source serviceCode связан с ctor/caller. Один HTTPS GET без account/device
credentials: 200/13788 bytes, DECKEY HTTP header. Immutable response snapshot
вне Git; offline decode 93 ordinary+1 secret=94 string constants, auth URL keys.
[Source/profile/SHA/ограничения](HEADLESS-PUBLIC-GMC2.md).
Plaintext values/key не выводятся и не копируются в Git. Auth/session не выполнены.

## Уточнение SDK constants pipeline, 19 октября

Старые unescape evidence повторно использованы; составной runtime decoder
переключён с raw append capture на проверенный actual FString output.
Исторические отчёты сохранены, их границы явно исправлены.
[Интеграция/регрессии](HEADLESS-SDK-UNESCAPE.md).

## GMC2 XOR evidence, 19 октября

18 native fixtures полного XOR helper/actual append, source bytes/offsets/SHA,
raw uint16 inputs/outputs/guards. Общий primitive совпал. Это не весь response
и не найденный DECKEY. [Доказательства](HEADLESS-GMC2-XOR.md).

## GMC2 GET/header evidence, 19 октября

16 native header/method captures с source bytes/offsets/SHA, constructor name
prefix и build getter. Общий offline request plan совпал с captures.
[Источник/инструмент/границы](HEADLESS-GMC2-HEADERS.md).
Device/player getters synthetic, HTTP transport/auth не исполнялись.

## GMC2 URL assembly evidence, 19 октября

26 native fixtures: source offsets/bytes/SHA, getters, actual ASCII append,
явные allocation/copy/growth shims. Общий ASCII helper совпал по строкам.
[Инструмент/отчёт/границы](HEADLESS-GMC2-URL.md).
Active values/RequestGMC2 HTTP/response ещё не установлены.

## SDK bootstrap values, 19 октября

Native getters/initializers: SDK version5.2.11, BuildCode labels A/B/C,
256 входов byte проверены; source bytes/offsets/callsites сохранены.
[Отчёт/инструмент/ограничения](HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Game AppVersion/SDKZone — другие поля; active BuildCode не установлен.

## Публичная CDN-конфигурация и module descriptors, 19 октября

Отдельные immutable snapshots: реальный HTTPS CDN body (6000 bytes), разобранный
общим ядром, и четыре descriptor payload из base/patch. Zone=real/server REAL;
NnNetwork/NkPatchRuntime LoadingPhase=Default, descriptor слои совпали.
[CDN source/SHA/offline replay](HEADLESS-PUBLIC-CDN.md),
[module source/SHA/JSON pointers](HEADLESS-MODULE-DESCRIPTORS.md).
Active settings, module order и игровая сессия ещё не установлены.

Главная точка входа разработки: [README модуля](../../vampir/README.md).

Обновлено 19 октября 2026. Основная библиотека:
`F:/PhoneExit Resources/Vampir`. Данные клиента Windows — cooked-ресурсы,
а не исходный проект игры. Совпадение версии с Android не подтверждено.

## Startup callback конфигурации, 19 октября

Найден владелец FNnNetworkVar и immediate callback branch registration helper.
Восемь native fixtures подтверждают callback до registry insertion; есть
factory/vtable/source offsets и отдельная статическая patch init chain.
[Отчёт/инструмент/границы](HEADLESS-CONFIG-STARTUP.md).
Module/PAK/GConfig order и active INI ещё не доказаны.

## Game config основного архива и patch, 19 октября

Отдельный producer recover-base-game-config.py получил 12425 подтверждённых
путей основного ProjectRED-Windows.pak и два Game INI. Base 1.12.14/real/True
отличается от patch 0.1.1/dev/False; WindowsGame.ini совпал.
Оба snapshot сохранены отдельно. Порядок runtime-загрузки ещё не установлен.
[Source/SHA/сравнение/воспроизведение](HEADLESS-PAK-CONFIG-RECOVERY.md).

## Подтверждённый каталог pakchunk0 и Game config, 19 октября

Generated key callback и plaintext SHA1 main/full directories подтвердили
каталог 593 directories/7067 paths для archive SHA 7c1efc7b… . Это реальные
имена из PAK directory, не observed strings прежнего record scan. Отдельный
immutable snapshot содержит directory.json, DefaultGame.ini и WindowsGame.ini.
[Source/SHA/границы/исправление record hash basis](HEADLESS-PAK-CONFIG-RECOVERY.md).
Остальные архивы и прежние связи этим ещё не переиндексированы.

## Индексы обновлённых ресурсов, 19 октября

Построены свежие SHA-bound индексы всех 35 изменённых/новых архивов:
127 375 записей, ограниченный разбор без каталога PAK. Из pakchunk1 заново
извлечены 1565 CSV: 1267 точных совпадений со старым содержимым, 298 без
точного совпадения. Старые данные сохранены. [Результат, SHA и границы](CLIENT-RELEASE-INDEX.md).
U02 частичен; производные графы/карты ещё не обновлены, совместимость не доказана.

## Быстрый указатель

| Что нужно | Файл относительно библиотеки | Что подтверждено |
|---|---|---|
| Источники архивов и их изменения | `pc-pak-inventory.json`, `pak-extracted/<архив>/source.json` | Путь, размер, время изменения, выборочный отпечаток архива |
| Записи внутри PAK | `pak-extracted/<архив>/entries.json` | Номер записи, смещение, признаки формата и доступные внутренние пути |
| Все картинки и варианты | `archive-image-catalog.json` | Источник и хеш каждой экспортированной картинки |
| Предварительный выбор версии картинки | `archive-image-latest.json` | Выбор по наибольшему суффиксу `_sN`; сверка с телефоном обязательна |
| Карты | `map-image-catalog.json` | 1422 изображения; это не готовые маршруты |
| Атлас географии | `maps/atlas/index.json`, `maps/atlas/index.html`, `maps/atlas/worlds/` | 254 мира, 154 настройки, точки/NPC/квесты/порталы; [MAP-ATLAS.md](MAP-ATLAS.md). Nocturne Map10/11: native-проекция и 7 областей старого кадра; свежий Android/маршруты ещё не проверены |
| Скрины на большой карте | `maps/atlas/screenshot-study/index.json`, `coverage.jpg` | Один участок Krvna Nest: 463 детали, проверочный p95<1.3px; worldXY не доказаны |
| Rate callbacks и размещения добычи | `code-clues/loot-record-links.json`, `maps/loot/npc-locations.json` | 2 пустых callback, 4227 размещений 776NPC, точные фильтры Item/NPC+World; вероятность не доказана |
| Native-загрузка rates и обратные источники | `code-clues/loot-rate-evidence.json`, `maps/loot/item-origins.json` | Load3 таблиц/CRTatoi, 793Item/35211 цепочек; знаменатель шанса ещё не доказан |
| Предметы и добыча NPC | `maps/loot/index.json`, `maps/loot/index.html`, `item-icons-float/index.json` | 941NPC/793Item, 5827 предметов/3615 картинок. [NPC-LOOT.md](NPC-LOOT.md); rates сырые, не проценты |
| Общая карта Nocturne | `maps/nocturne-world.json`, `maps/nocturne-world.png` | 25 плиток, 10240×10240; происхождение плиток и проверка швов |
| Просмотр карт и интерфейса | `index.html`, локально http://127.0.0.1:17945/ | Поиск и галерея; сервер должен быть запущен |
| Деревья объектов интерфейса | `ui-layout-study/index.json`, указанные там JSON | 81 пакет WidgetBlueprint, включая WBP из TutorialUI; имена, типы и диапазоны сериализации |
| Открытые таблицы | `table-study/index.json`, `index-pakchunk1-Windows.json` | 125 CSV ProjectRED и 1565 CSV pakchunk1; SHA256, номера записей и смещения |
| Зацепки в собранном коде | `CODE-CLUES.md`, `code-clues/shipping-strings.json` | Загрузчики Quest/Tutorial CSV, поля задач и контролов, смещения строк в EXE |
| Зависимости и реальные строки квестов | `QUEST-DEPENDENCIES.md`, `quest-graph/index.json` | 1353 квеста, 5944 задачи; привязки TutorialStep к TutorialUI и WBP |
| Требования и награды | `REWARDS-AND-LAYOUT.md`, `quest-graph/rewards.json` | 1348 групп, 5759 записей наград; требования завершения квестов |
| Открытие контента и квестов | `CONTENTS-LOCKS.md`, `quest-graph/contents-locks.json` | 269 блокировок, 330 условий; числовая семантика ещё не восстановлена |
| Размеры и привязки из слотов | `REWARDS-AND-LAYOUT.md`, `ui-geometry/canvas-slots.json` | 2013 Canvas-слотов, 2 исключения; абсолютная геометрия ещё не подтверждена |
| Предварительные кандидаты квестовых ресурсов | `quest-data-candidates.json`, `quest-script-study/index.json` | Поисковые зацепки, а не доказательство наличия сценария |
| Кадры и координаты учебных действий | `phone-tests/index.json` | Копии диагностических кадров с SHA256; ручные и автономные действия различать |
| Исполняемый сценарий и шаблоны | Репозиторий: `phone-exit/bots/vampir/` | Фактическая логика бота; не восстановленный исходный код игры |

## Квесты и таблицы: найденные зацепки

Все номера ниже — поле `entry`, а не байтовое смещение. Точные смещения,
SHA256 распакованных CSV и отпечаток исходного PAK находятся в `table-study/index.json`.
Внутренние имена этих CSV неизвестны: зашифрованный индекс не расшифровывался.

- `ProjectRED-Windows-6080.csv`: Key/ValueType/Value. Настройки
  `Quest.StartQuestInfoId = 110110`, `Quest.LastQuestInfoId = 211910`,
  `Quest.GiveUpButtonUnlockQuestID = 110510`. Диапазон ID не доказывает,
  что все промежуточные числа являются заданиями или задают порядок прохождения.
- `ProjectRED-Windows-6078.csv`: пять строк описаний классов, поля
  `StartQuestId`, `HideGuideEffectQuestTaskId`.
- `ProjectRED-Windows-6099.csv`: английская локализация интерфейса, включая
  `MAINMENU_QUEST`, `QUEST_PROGRESS_VALUE_STATE_MINI`, `TUTORIAL_SKIP_POPUP_DESC`.
  Тексты интерфейса не задают последовательность действий квеста.
- `ProjectRED-Windows-6097.csv`: английская таблица заголовков.
- `ProjectRED-Windows-6106.csv`: английские сообщения ошибок.
- `ProjectRED-Windows-6201.csv`: 19 строк правил типов зон, поля
  `PossibleTutorialStart`, `OnEntryAutoCombat`, `EnableQuestType`,
  `LockOpenMap`, `WidgetInvisibleList`. Значения требуют отдельной интерпретации.

Данные заданий найдены в pakchunk1: Quest 1448, QuestTask 1454,
QuestTaskAction 1455, Tutorial 1551, TutorialStep 1555, TutorialUI 1556,
WorldSpot 1573. Схема и соединения: QUEST-DEPENDENCIES.md и quest-graph/index.json.
Английские имена квестов — запись 498, учебные подсказки — 543.
Текущий квест нельзя определять только по начальному ID из конфигурации:
исполнение графа и чтение стадии персонажа ещё не реализованы.

## Интерфейс: что читается, а что ещё нет

В `pakchunk500-Windows` найдены:

- entry 9164 — `WBP_TutorialUI`: `ButtonSkipRight`, `ButtonSkipLeft`,
  `CanvasPanelSkip`, `CanvasPanelWait`;
- entry 9152 — `WBP_TutorialFocusUI`;
- entry 9150 — `WBP_TutorialFocusFitEffectT`, `ButtonBlockTypeFit`;
- entry 9148 — `WBP_TutorialFocusDialogT`.

У JSON сохранены внутренние пути, ссылки на источник, имена экспортов,
размеры, диапазоны и SHA256. Поля layout сериализованы без проверенной схемы
unversioned properties: `geometry_schema_verified=false`. Имена кнопок помогают
найти ресурс, но пока не дают надёжных координат на разных экранах.
Рабочие нажатия определяются по кадру и шаблонам; координаты не переносить
из cooked-данных догадками.

## После обновления игры

Проверка магазинного сценария на кадрах: [SHOP-REPLAY.md](SHOP-REPLAY.md),
`phone-tests/shop-901030/bot-replay.json` (32 случая с хешами кода, шаблонов
и скриншотов). Прогон использует bot.py, а не подставленные found-флаги.
Кадра успешной покупки пока нет: результат остаётся неизвестным, повторы запрещены.

Пресеты масштаба и настройка: [UI-SCALE.md](UI-SCALE.md),
`ui-geometry/ui-scale-reference.json`: EOptionType::DisplayUIScale137 →
Option1429/record81 → OptionGroup32300 → SubTab32000 → MainTab30000;
константы 68/records329–353, подписи 488/record67. 25 коэффициентов в 5 профилях.
Default AOS=4, Win=2; активный масштаб телефона и DPI-кривая пока не установлены.
Ограниченный поиск конфигурации сохранён в `code-clues/ui-scale-config/index.json`.

Собственные размеры SizeBox: `code-clues/ui-properties.json` (16 свойств
из нативного массива EXE) → `ui-geometry/size-boxes.json` (2943 контейнера,
исключений 0 после разбора наследуемых полей) → `ui-catalog/<вариант>.json`, поля container_geometry
и size_constraints. Порядок извлечения и ограничения: [UI-CATALOG.md](UI-CATALOG.md).
Значение размера без bOverride не считать включённым ограничением.
ScaleBox: `ui-geometry/scale-boxes.json` (203 контейнера, исключений 0).
Нативные схемы общих свойств Widget и WidgetTransform также находятся в
`code-clues/ui-properties.json`; явные свойства подключены к контролам каталога.

Дополнительные производные отчёты (15 октября):

- `code-clues/native-enums.json`: 2020 групп, 11792 имени/числа с PE-смещениями;
  [NATIVE-SEMANTICS.md](NATIVE-SEMANTICS.md).
- `quest-graph/shop-tasks.json`: оба задания NpcShopBuy, категории, NPC,
  товары, цены, условия и неразрешённый ContentsLockKeyword=76.
- `ui-geometry/canvas-slots.json` и `panel-slots.json`: 4063 принятых слота;
  `topology.json`: порядок детей 1945 родителей из исходных массивов ссылок.
  [REWARDS-AND-LAYOUT.md](REWARDS-AND-LAYOUT.md) описывает ограничения схемы.

Эти отчёты расширяют первоначальный разбор имён экспортов выше, но не
подтверждают абсолютные координаты элементов на Android.

1. Сохранить прежнюю библиотеку; для нового снимка задать
   `PHONEEXIT_VAMPIR_RESOURCES` на новую папку.
2. Выполнить команды из README: инвентаризация → изображения → сборка карты →
   интерфейс → CSV → галерея. Сопоставить `source.json` старой и новой версии.
3. Сравнить внутренние пути и хеши содержимого. Номера записей и смещения
   могут измениться; не использовать их как постоянные идентификаторы.
4. Сверить шаблоны и карту с актуальным экраном Android. Обновить этот указатель
   и `bots/vampir.md`, указав фактические проверки и оставшиеся ограничения.

Полный SHA256 архива отличается от `sample_sha256`: последний вычислен только
по началу и концу архива. Ни один из них не заменяет проверку версии Android.

Nocturne XY→рельеф: `maps/atlas/projection.json`,
`code-clues/map-projection-evidence.json`, инструмент `build-map-projection.py`.
Происхождение/порядок/33 теста: [MAP-ATLAS.md](MAP-ATLAS.md).

Большая карта всех 36Nocturne-контекстов: `maps/atlas/nocturne.json`,
`nocturne-manifest.json`, главный `index.html`; прежний просмотр 254 миров —
`world.html`. Экспорт `nocturne-overview.png`10240×10635.
Инструменты `build-world-map.py`, `world-map*.js/html`, `render-world-map.py`.
Происхождение, 51 тест, исправление zoom и 25 плиток: [MAP-ATLAS.md](MAP-ATLAS.md).

Карточки NPC:`maps/atlas/monster-manifest.json`,`monsters/<ID>.json`,
`monster-verification.json`; сборщик `build-monster-details.py`.BattleCSV1545,
native-связь BattleGroupId, количество/условные цепочки: [NPC-LOOT.md](NPC-LOOT.md).
