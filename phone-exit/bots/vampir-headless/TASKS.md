# Самостоятельный Vampir — задачи

## H04-request-caller: найти owner и его policy

Выполнено: direct getter caller scan, actual caller 0x1468f1d70 и 32 native
cases до RequestA/send capture. Следом owner/vtable, actual virtual+a18,
lifecycle policy1 и связь с CharacterSelect_02. Response102/network/live session
остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-CALLER.md).

## H04-lifecycle: найти emitter и продолжение slot78

Выполнено: source-bound Ghidra экспорт lifecycle, 7 event cases и leaf callback.
Далее: emitter callbacks из slot08, продолжение 0x14561a8d0 из slot78,
доказанный caller slot90. Response102, network и live session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-LIFECYCLE.md).

## H04-world-label: source path подтверждён

Raw2→World.Id2→Lobby/CharacterSelect/CharacterSelect_02. Native field-store/
lookup/getter и base/current patch CSV parity проверены. Следом actual
cooked level/hooks завершения перехода и slot90/CharacterListRead dispatch.
Полный runtime loader/mount priority, response 102/socket/live session открыты.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-STATE-LABEL.md).

## H04-state-lookup: actual hash, реальные contents открыты

13 native cases lookup/hash/accessor→label caller. Дальше заполнение
registry storage+0x18 и actual record vtable/virtual20/source string key2.
Generic TLS/static registry exports не доказывают contents. Slot90 lifecycle,
response102/socket/full session остаются открытыми.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATE-LOOKUP.md).

## H04-selection-state: preparation/deferred boundary

10 native virtual40/SetState cases + 12 independent callback cases проверены.
Следом actual state-label lookup mapping и client/lifecycle hooks после
отложенного действия, доказанный slot90 dispatch. Полный scheduler/closure
lifetime, response102/network/fresh SDK/device inputs и live session открыты.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATE-TRANSITION.md).

## H04-selection-service: targets и select handoff подтверждены

Derived table 0x1499f11f0: slot90=requestA, slot50=CharacterSelect builder.
Далее slot40 SDK guard/base helper/virtual+c8/state-transition helper и
доказанный caller slot90. Отдельно packet109 writer/frame/response110.
Full owner ctor, свежие SDK/device inputs и live session ещё открыты.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-SERVICE.md).

## H04-waiting-end: один инициатор CharacterListRead подтверждён

ID 27/WaitingEndNotify handler 0x146768540 → predicate → requestB 0x145dbfe50
→ actual CharacterListRead constructor/send capture. 24 native cases.
Далее requestA 0x145dbd4b0 owner/slot (pointer 0x1499f1280), actual selection
virtual+0x40/+0x50 и response 102. Server notify timing и связь с обычным
Login success, frame/socket/session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## H04-character-list-boundary: reset и request разделены

8 native reset cases + 2 независимых CharacterList request entries.
После LoginResult подтверждён reset 0x1464846c0, а не direct character send.
Следующий участок: callers 0x145dbd4b0/0x145dbfe50, регистрация/условия и связь
с завершением Login; затем full ID 101 frame и reader/handler ID 102.
Живой transport/request lifecycle/fresh SDK/device inputs остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-BOUNDARY.md).

## H04-login-result-handler: covered native branches подтверждены

38 body→handler scenarios: state stores/early exit/error/SDK/server ID.
Следом actual virtual+0x28 после getter 0x146486a50 и доказанная цепочка
к CharacterListRead/выбору персонажа. Post-state 0x1467259c0 добавлен в Ghidra,
не считать его сетевой отправкой без продолжения. Request lifecycle/socket/
fresh SDK/device inputs и live session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-HANDLER.md).

## H04-login-result-reader: body подтверждён

21 full bodies, 332 short inputs, trailing policy. Ghidra расширена до
32 функций для nested readers и UTF-8. Общий LoginResultBody готов для
bounded offline decode. Далее actual handler 0x146765540/result gates,
Listener/Dispatch body linkage и следующие запросы персонажей. Request
lifecycle, fresh SDK/device/profile inputs и live session остаются открытыми.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).

## H04-login-send: handoff → queue подтверждён

34 native cases: 29 frames, 2 duplicate, 3 transport refusal. Проверены lookup,
timeout selection, getter/virtual send/writer/CRC/XOR/owning queue вместе.
Далее LoginResult reader/handler/result gates и стыковка с transport drain;
insert/notify/timeout lifecycle, fresh SDK/device/profile inputs остаются.
Live session/character selection ещё не подключены.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-SEND-PATH.md).

## H04-login-writer: body подтверждён

Ghidra → actual writer/UTF-8/archive IO: 25 payload vectors, 40 failures.
Общий LoginPayload готов для bounded offline encoding. +0x128 captured zero
в 16 preparation fixtures; семантика неизвестна. Следующий участок:
request handoff 0x144aa8020 → transport send, совместный prepare/writer/frame,
потом LoginResult. Real profile/device inputs и live session ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-WRITER.md).

## H04-tools: установка и границы совместимости

Правило выбора инструментов закреплено в AGENTS.md. CUE4Parse: три headers
проверены, четыре PAK без ключа индекса заблокированы; mappings/properties
не проверены. Dumper-7 собран x64; live SDK/mappings — отдельный будущий
эксперимент с согласованием. Продолжение Login: готовый Ghidra export,
затем native replay writer/handoff.
[Команды и ограничения](../resource-tools/vampir/ANALYSIS-TOOLS.md).

## H04-Ghidra: пакетный анализ подключён

22 функции успешно экспортированы и повторены из сохранённого проекта.
Далее Login writer и request handoff читать через общий псевдокод/call graph,
проверять целыми native scenarios. Межверсионное сопоставление ещё открыто.
[Установка, команды и границы](../resource-tools/vampir/HEADLESS-GHIDRA.md).

## H04-login-fields: constructor и SDK consumers проверены

Native Login prefix разделяет NetmarbleId/token/server fields и доходит
до request handoff. Далее writer/encoding и handoff0x144aa8020 → send,
device/profile input sources и полный SDK response→Login ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-FIELDS.md).

## H04-version-result: native переход к Login entry

VersionResult reader/handler/gate → 0x1467a9700 проверены. Далее actual
Login construction/SDK field sources/writer/send/LoginResult. Error helper
branches вне covered codes, live negotiation/transport ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-RESULT-HANDLER.md).

## H04-version-send: полный native путь до очереди

Wrapper/send-B/writer/frame/append проверены вместе на18 scenarios. Далее
VersionResult reader/registration/handler → Login; отдельные задачи actual
queue drain/socket и реальные weekly inputs. Server negotiation ещё нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-SEND-PATH.md).

## H04-version-writer: переносимое тело проверено

Actual writer/conversion/archive bytes совпали с VersionPayload на14 cases.
Далее frame/send0x1467aaa10 → VersionResult handler → Login; реальные
значения полей/weekly inputs и server negotiation ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-PACKET-WRITER.md).

## H04-connected-packet: сначала PktVersion

Game callback строит PktVersion/ID1 и вызывает send0x1467aaa10. Далее
send/writer/VersionResult → Login; реальные источники raw fields и weekly
version inputs ещё открыты. Live negotiation/session не доказаны.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECTED-VERSION-PACKET.md).

## H04-connected-delegate: игровой target связан

Native binding/bridge → game0x1467a9cd0 подтверждены. Далее тело получателя,
packet constructor/field sources и virtual send+0x38 → Login. Units storage
не refcount; AL1 bridge не server success. Live session остаётся открытой.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).

## H04-ready-notification: transport recipient исполнен

Completion code1 → socket listener → peer broadcast → OnTcpPeerConnected
и owner virtual+0x60 call site проверены. Далее actual owner P+0x308/+0x310
vtable/target → packet Login; endpoint/configuration/retry ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READY-NOTIFICATION.md).

## H04-socket-option: actual engine body проверен

Raw level/option translation → getsockopt и readiness gates исполнены.
Далее completion code1 recipients → peer transport notification → Login.
Live socket/scheduler/lifetime/session ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-ERROR-OPTION.md).

## H04-readiness-job: code/state gates проверены

Mode helper, одна worker iteration и completion mapping проверены.
Далее option selector1 → syscall/translation и code1 recipients →
transport notification → packet Login. Live readiness/threads/lifetime
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READINESS-JOB.md).

## H04-error-mapping: native таблица подтверждена

Mapper engine slot+0x68 и WSA inputs → wrapper acceptance проверены.
Далее helper 0x1445eab70 и actual job run/completion, readiness notification
и packet Login. Системный last-error source, active mode/network и
server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WINSOCK-ERROR-MAPPING.md).

## H04-connect-result: syscall boundary и bool semantics

Native endpoint connect lower/wrapper проверены. Дальше engine virtual
+0x68 error mapping, actual helper 0x1445eab70 и job/completion/readiness,
затем packet Login. Не считать wrapper acceptance готовой сессией;
реальные OS connect/wait и активный mode не проверены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-CONNECT-RESULT.md).

## H04-socket-create: recipient и creator проверены

Resolver recipient и source socket creator исполняются вместе.
Далее helper 0x1445eab70 и endpoint connect 0x1445e5c60 → 0x1445ecbb0,
реальные pending/error/readiness и callback packet Login. Socket syscall
и active network/session не проверены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVED-SOCKET-SETUP.md).

## H04-resolver-results: run/completion проверены

Job run/completion и адресные callback gates проверены на 8 fixtures.
Далее recipient action 0x141423088 → first socket/connect/readiness,
затем packet Login. Реальный DNS/vector parsing, scheduling/lifetime
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVER-JOB-RESULTS.md).

## H04-lower-connect: setup и resolver handoff проверены

Lower connect и lexical selector исполняются после endpoint construction.
Далее resolver job source vtable → run/result callback → socket readiness
и packet Login. Numeric parser, реальный DNS, duplicate/reset lifecycle
и active session ещё открыты; bool enqueue не заменяет readiness.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## H04-connect-target: host/game-port связь подтверждена

Основная пара +0x278/+0x288 и override +0x290/+0x2a0 связаны с
ConnectToServer. Далее lower connect 0x1445ea1b0 → socket/readiness
и callback packet Login. Второй word+0x28a, active endpoints/lifecycle
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).

## H04-server-target: source mapping проверен

BeginGame last ID/fallback/lookup/busy и target stores подтверждены.
Далее consumers transport+0x270/+0x278/+0x288/+0x28a → connection setup
и packet Login. Реальные server records/sentinel/busy lifecycle и
server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## H04-entry-gate: разделение title/SDK state

Title head/tail и отдельный BeginGame IsSignIn gate проверены.
Далее BeginGameImpl 0x146425730, server selection и packet Login.
UI middle/blacklist и активная session validation не закрыты; клиентские
флаги не заменяют доказательства серверного входа.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-STATE.md).

## H04-title-notify: переход найден

Условная цепочка manager-child → router → slot+0x08 →
OnSuccessNetmarbleSDKAuth подтверждена. Далее значимые переходы handler
0x14641d560 и существующая entry/packet Login цепочка. Активный NID
channel/policy, первый вход и полная session validation ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## H04-game-instance: PGS ветвь отделена

Game-instance virtual+0x10 оказался Google PGS SignIn с unsupported Windows
result, не game Login. Далее manager-child 0x14560f740 и реальные title
success notification/OnSuccessNetmarbleSDKAuth; затем packet Login.
Android parity, первый credential-вход и полная session validation открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-PGS-BRANCH.md).

## H04-game-success: broadcast и title handler проверены

Первый success action оказался общей рассылкой; title slot+0x30 обрабатывает
child pointer и не доказывает Login. Далее game-instance getter 0x1450b11b0
и virtual+0x10 в game callback, а также child action 0x14560f740.
Registration реальных subscribers и network/session readiness ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-SUCCESS-BROADCAST.md).

## H04-silent-game: цепочка callback проверена

Silent dispatcher → queued thunk → bridge → game callback проверены
вместе. Далее success action 0x143b8bf10 и ненулевой game instance → Login.
Silent response JSON/session contract и credential-first вход ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SILENT-GAME-DISPATCH.md).

## H04-channel-silent: handoff подтверждён

Переход ChannelManager → Auth silent и обязательный сохранённый player ID
проверены. Далее response callback Auth impl+0xa8 → Channel/game callback;
обычный credential-first вход, expiry/refresh и game Login остаются открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## H04-game-callback: следующая связь

Проверены AutoSignIn callback gates и отдельный SDK route owner+0x170.
Getter назван по diagnostic: GetChannelManager, target — SignInSilently.
Далее provider selection в 0x1444feac0, success manager action
и virtual callback → реальная credential/session цепочка → game Login.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-AUTO-SIGN-IN.md).

## H04-result-dispatch: native handoff проверен

16 сценариев связали SignIn binder, dispatcher, очередь и invoke bridge.
Task graph и реальный bound function пока fixtures. Следующий приоритет:
найти function/storage реального игрового callback, проследить до game Login;
затем expiry/refresh и real identity/confirmation.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-RESULT-DISPATCH.md).

## H04-response-completion: частично завершено

Проверены idpInfo, channel byte, native SetSignIn и вызов dispatcher.
Добавлен общий строгий parser без I/O. Следующий шаг: исполнение dispatcher
и привязки делегатов → игровой Login; затем expiry/refresh и реальное устройство.
Подтверждение входа по одному внутреннему флагу запрещено контрактом parser.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## H04-response-variant: conversion boundary reduced

10 native cases проверили converter/AsString/real TryGetString/CRT для
string и number-string fixtures. Три regression tests OK. Native JSON parser
и double/bool/другие variants открыты. Далее idpInfo/final callback/SetSignIn
и SDK token →game Login, затем полный runtime authorization boundary.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-VARIANT.md).

## H04-response-gates: native boundaries partial

18 native cases связали response raw predicates/body/status getters, JSON
object/errorCode gates и field traversal. _wtoi исполнился в actual Windows
CRT; JSON/variant — fixtures. Далее native numeric variant conversion,
error dispatch, idpInfo/final callback/IsSignIn/SDK →game session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-GATES.md).

## H04-SDK-response: field mapping partial

13 native cases и auth constructor подтвердили playerInfo/player keys,
SDK accessToken assignment и optional field preservation. Три regression
tests прошли. Далее network/JSON/errorCode validation до slice, idpInfo
и final callback/IsSignIn/expiry/SDK →game session. Runtime response parser
пока не подключён. [Source/SHA](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-RESPONSE.md).

## H04: следующий приоритет — SDK sign-in response

Migration wrappers проверены в 10 native cases; zero-tail guarantee отсутствует
в рассмотренном wrapper path. Реальный backend/полная миграция остаются открыты.
Это отдельная задача совместимости, не доказанная предпосылка нового входа.
Продолжать callback1444d85f0 leaf →1444cc1a0, response schema/errors →
SDK token/player/expiry →game Login, затем real identity/confirmation integration.
[Границы migration evidence](../resource-tools/vampir/HEADLESS-SDK-MIGRATION-ALLOCATION.md).

## H04-token-container и migration field

16 native container + 8 migration cases проверены. Decoder/JSON/split
primitives остаются fixtures; true caller result не доказывает auth.
ChannelKey source связан с migration branch. Далее allocator tail contract,
migration config/lifecycle, full token decode и SDK sign-in response/session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-TOKEN-PAYLOAD.md).

## H04-NID-suffix: transform и common helper

6 native suffix cases + independent AES/runtime comparison прошли.
Aligned printable ASCII derivation реализован в nid_storage_path, optional
crypto backend; Android пока не проверен. Следующее: source token/sub parsing,
migration branch/active path, SaveGame serialization и SDK auth response.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-NID-SUFFIX.md).

## H04-storage-auth-path: optional directory gate

8 native auth-context gate/Load join fixtures прошли; извлечение auth context
и suffix пока fixtures. SetupServiceSettingPath/parser сохранены статически.
Shared flag связан с Initialize/Save/post-restore sources. Далее suffix
transformations/reset lifecycle, active storage, SaveGame decode и SDK session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-AUTH-PATH.md).

## H04-load-device-fields: восстановление и filename

16 native Load field-copy/post-dispatch и 3 constructor/path fixtures прошли.
Разные SDK/NID поля и default ServiceSetting.bin подтверждены в указанном
объёме. Дальше optional directory, active filename overrides, file parsing/type
checks/Save read-back; реальные identity и device confirmation ещё открыты.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-LOAD-DEVICES.md).

## H04-NID-device: источник web/token ключа

Три native slices проверили deviceKey/device_key → NID getter. Registry v2
с отдельными NID key/source и миграцией v1 готов; основная локальная база
мигрирована с пустыми real values. Проверены native report и 5 registry tests.
Далее NID getter lifecycle, filename/Save/load и full web-context binding.
[Source/SHA](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md).

## H04-storage: каталог и NID identity

Native directory join проверен шестью fixtures, base getter explicit fixture.
Save/Load/Initialize и отдельный NID device key экспортированы статически.
Два regression tests прошли. Открыто: полный filename, Save/load field mapping,
NID getter caller → web deviceKey, active context и реальные keys.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-STORAGE.md).

## H04-device-setter: сравнение и запись

Native setter body/ASCII compare проверены в 56 fixtures, 12 интеграциях
с getter. Write failure не предотвращает изменение settings. Три regression
теста прошли. Дальше Save/load/path и active platform/SDKZone, реальная
identity основной почты, затем server challenge protocol.
[Source/SHA](../resource-tools/vampir/HEADLESS-DEVICE-SETTER.md).

## H04-device-lifecycle: getter branches

8 NM + 12 DeviceKey native fixtures подтвердили cache/source/save gate
и продолжение caller после ошибок write/Save. Три regression tests прошли.
Следующие зависимости: SetDeviceKey compare/write, active platform/environment,
Save/load, реальные identity и server challenge. Storage/parser остаются fixtures.
[Source/SHA/ограничения](../resource-tools/vampir/HEADLESS-DEVICE-LIFECYCLE.md).

## H04-device-source: storage и формат GUID

Найдены Windows StoredValue, NMDeviceKey/DeviceKey, platform-dependent branches
и CoCreateGuid. Native default formatter проверен тремя fixtures, два regression
теста прошли. Открыто: getter/cache/storage replay, platform/environment и
Save/load lifecycle, получение реальной identity и server challenge.
[Источники и границы](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).

## H04-device: постоянные привязки

Локальный SQLite-реестр реализован; основная тестовая почта зарегистрирована.
Три теста persistence/isolation/confirmation прошли. Открыто: source-bound
генерация и хранение обоих device keys, реальная identity, challenge protocol,
login runner gate, transfer/backup и Android adapter.
[Подробности](DEVICES.md).

19 октября: H04 SDK sign-in request preparation подтверждена: 4 native body
и 8 header/method fixtures. Общий sdk_sign_in offline plan добавлен; authUrl
из real public GMC2 связан только с synthetic context. Auth HTTP нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN.md).
Следующая зависимость: callback1444d85f0, network/SDK result schema, SDK access
token/playerId/expiry/errors → game Login. Active context/storage/refresh открыты.

19 октября: H04 OnResult continuation/GetObject проверены четырьмя fixtures.
Provider20 преобразуется в SDK credential33 с channelAccessToken. Native Save
return не проверяется; storage/clear/JSON/map insertion — explicit captures.
Общий nid_sdk_credential builder готов только в названном объёме.
[Source/SHA](../resource-tools/vampir/HEADLESS-NID-CREDENTIAL.md).
Следующая зависимость: FAuthImpl::SignIn 1444fb800, полный authUrl/v1/sign-in
request/header/device/client context и response → SDK token → game Login.
Auto caller после result/active auth attempt, persistence и refresh ещё открыты.

19 октября: H04 percent loop проверен 147 native fixtures, UTF conversions
остаются отдельной границей. Общий sdk_percent и callback parser используют
strict ASCII/route/duplicate policy; URL → provider credential без сети/storage.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-PERCENT.md).
Далее full query/map semantics и связь с активной попыткой входа, затем settings
setters/persistence и callback после 1450ef437 → SDK session → game Login.
Не считать локальный callback parser подтверждением подлинности токенов.

19 октября: H04 integer/channel dependencies проверены actual native helpers,
13 initializers/ASCII compare и локальным CRT. 28 numeric/45 channel/6 caller
fixtures; mailUserKey=20, native numeric parser permissive. Общий nid_result
принял только decoded dict, canonical0/presence/ASCII policy документирована.
[Источники](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).
Далее query parser/encoding и context binding, settings/persistence/callback
после 1450ef437 → SDK session → game Login. Android crypto/storage ещё открыты.

19 октября: H04 получил 22 native OnResult caller/copy fixtures. Подтверждены
caller gates и раздельные access/refresh/ID/country settings arguments; missing
и empty различаются. Parser/channel return fixtures не доказывают accepted
numeric syntax или email enum. Settings/callback ещё не исполнялись.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).
Следующая зависимость: parser 1415dea40/channel mapper 14452b060 и query parser,
затем setters/persistence и post-adoption call 1450ef437 → SDK/game session.

19 октября: H04 — email result path уточнён. Обычная web ветка проходит
profile processing → nmidprovider/result с accessToken. Отдельный signin/
authorization_code не подставлять вместо неё. 12 JS fixtures и native static
OnResult/14 initializer bindings сохранены; четыре targeted tests прошли.
[Источники](../resource-tools/vampir/HEADLESS-NID-RESULT.md).
Следующая зависимость: native OnResult query parser/resultCode validation,
token adoption/SendSignInCallback → SDK session → game Login.
По просьбе пользователя создан bot-test@vampir.top (100 МБ) в DirectAdmin;
доставка писем и регистрация Netmarble не проверены. Пароль не хранить в Git.

19 октября: H04 остаётся частичным. Найдены отдельные legacy EmailAuth/NID
SDK ветки и публичный NID web contract. Общий encrypted request plan готов
локально; POST, reCAPTCHA acquisition, response/callback не выполнялись.
[Источники](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Следующая зависимость: разобрать response → callback → authorization code,
сверить native обработку и context/provider selection. Затем token/session.
При обновлениях сверять web snapshot отдельно от EXE/PAK.

19 октября: public GMC2 получен и декодирован полностью в local response profile:
DECKEY HTTP header, 93 ordinary/1 secret/94 merged, auth endpoints доступны.
ServiceCode=netmarbles подтверждён ctor/caller. Build 0/A — явный constructor-
default probe, не доказанный active state. Далее email/password/browser code,
token response/expiry и SDK→game session. [Источник](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).

19 октября: исправлен existing decode_sdk_constants_string: reused unescape
→ actual XOR/append zero omission, без дублирования decoder. Два regression tests
и 18 новых native vectors через составной путь. DECKEY slot28/class method,
outer response и auth остаются следующими зависимостями.
[Источник](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).

19 октября: H04b native XOR helper/append подтверждены на 18 fixtures,
общий raw uint16 primitive добавлен. Далее encConstants source decode,
key/DECKEY, encSecretConstants и JSON/schema; byte XOR/UTF8 не подставлять.
[Источник](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).

19 октября: H04b RequestGMC2 headers/method arguments проверены на 16 native
fixtures с HTTP captures; общий immutable plan добавлен, без I/O/credentials
acquisition. Следом response decode/encConstants/DECKEY/auth URL values;
serviceCode/active device identity остаются отдельными зависимостями.
[Доказательства](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).

19 октября: H04b native URL assembly/getters/ASCII-view append подтверждены
26 fixtures; общий assemble_gmc2_config_url_ascii добавлен. Active inputs
и HTTP ещё не установлены. Следом RequestGMC2 headers/response decode/DECKEY.
[Source/SHA/ограничения](../resource-tools/vampir/HEADLESS-GMC2-URL.md).

19 октября: H04b bootstrap getters проверены native. Version=5.2.11,
BuildCode byte1→B/2→C/elseA (256 fixtures), общий selector добавлен.
[Источник](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Следующая зависимость — полный GMC2 URL builder/request и response decode;
active BuildCode не подменять game AppVersion или SDKZone.

19 октября: H04b получил реальный public CDN config по профилю base INI.
Общий decoder подтверждён: Zone real/mode2, index6/REAL с lobby details.
[Snapshot/offline verification](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md).
Далее SDK bootstrap/auth parameters/session response; active INI/native full
validation остаются открыты. Module descriptors base/patch совпали и имеют
Default phase; это не runtime order. [Источники](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).

Обновлено 19 октября 2026. Контекст/ограничения — [README.md](README.md).
История — [WORKLOG.md](WORKLOG.md); общий реестр — [FUNCTION-INDEX](../vampir/FUNCTION-INDEX.md).
Общие результаты и runtime package — [vampir-shared](../vampir-shared/README.md).
H03a codec находится в `vampir-shared/vampir_core`, без копии в сетевом боте.
Не создавать подагентов без прямой просьбы пользователя.

19 октября: H04b startup callback уточнён. FNnNetworkVar loader вызывается
сразу при registration, до registry insertion (8 native fixtures).
Найдены owner factory/vtable и отдельная patch init chain. Следующая зависимость:
module load → PAK mount → GConfig Game cache/overrides.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-CONFIG-STARTUP.md).

19 октября: H04b получил оба Game config слоя с проверенными хешами.
Base 1.12.14/real/True отличается от patch 0.1.1/dev/False.
Следующая незавершённая зависимость — порядок startup/mount/GConfig cache
и overrides; выбирать active settings по внешнему виду значений нельзя.
[Снимки и воспроизведение](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

Статусы: готово — только в названном объёме; частично — есть доказательство,
но критерий не достигнут; осталось — ещё не сделано. При продолжении выбирать
первую незавершённую зависимость, обновлять её и добавлять запись в журнал.

| ID | Задача / зависимости | Статус | Проверяемый результат |
|---|---|---|---|
| H00 | Зафиксировать требования, задачи, общий реестр | Готово | README/TASKS/WORKLOG, ссылки из главного README; ограничения и unknown явно записаны |
| H01 | Инвентаризировать уже найденные функции и сетевые строки | Готово в ограниченном объёме | Воспроизводимый SHA-bound отчёт: 27 строк/31 проверенная LEA; общий индекс, независимая проверка bytes |
| H02 | Packet name→vtable→ID/read/write; H01 | Готово для 10 выбранных типов | 10vtable/constructor/ID/IO targets, 5 result registrations, 10 native ID cases/4 audit tests; HEADLESS-PACKET-BINDINGS.md. Не wire-schema |
| H03 | Транспорт и wire encoding; H02 | Частично: H03a готов | Реальный Ping body IO/126 native scenarios; framing, transport и остальные поля ещё unknown |
| H03a | Ping/Result primitive IO и переносимый payload codec | Готово для исследованной ветки | `<QQ`/16 байт и `<IQ`/12 байт, native constructors/primitive/raw IO; только внешний memcpy shim; 5 tests/6 replays |
| H03b | Complete framing/send/receive; H03a | Частично | Найдены output roots144aa9da0/144aaccf0 и helper144aa6ca0; нужны доказанные размер/checksum/transform/context и complete-frame vectors |
| H03c | Остальной codec и bounded transport; H03b | Осталось | Primitive strings/arrays/limits/таймауты, send/receive контекст без смешивания IDs; offline vectors и локальный transport test |
| H03b.1 | CRC/XOR helpers и общий код | Готово в указанном объёме | CRC32+LE64 repeating XOR, 4send/receive roots, 252 native executions/5 tests; full frame ещё unknown |
| H03b.2 | Frame bounds/integrity/context и связь receive→Dispatch | Частично | Send-A Ping frame закрыт H03b.2a; receive/лимиты/key/callback targets остаются H03b.2b |
| H03b.2a | Цельная сборка исходящего Ping send-A | Готово в указанном объёме |20 native assembly cases/5 tests; length 24/CRC32/ID16/seq16/body/XOR, wrap; shared send_frame.py |
| H03b.2b | Приём/контексты/ключ; H03b.2a | Частично | Length probe 156 cases/wrapper 13 cases, static callback→Dispatch; смена ключа закрыта отдельно; transport/CRC/handler wrappers ещё неизвестны |
| H03b.2b-key | Notify→ack→peer key | Готово в указанном объёме | IDs11/12/raw64, registration, 20 native handler slices; send capture shim; server key generation/full Notify→wire неизвестны |
| H03b.2b-transport | Первый raw receive stage | Готово в ограниченном объёме | Native size 23/compressed flag/copy/decompress/compaction, 62 scenarios/5 tests; literal fixtures, не общий decoder |
| H03b.2b-block | Блочная распаковка и связь второго stage | Готово в указанном объёме | 166 valid / 86 invalid native cases; shared bounded block_decode.py/take_transport_frame; static slots38/40, не полный listener replay |
| H03b.2b-listener | Исполнить второй receive loop; H03b.2b-block | Готово в указанном объёме | 44 native cases/5 tests: probe/broadcast/receive-A/XOR/compact; snapshot lifecycle fixtures, final callback capture; общий take_receive_a_frame |
| H03b.2b-dispatch | Dispatch→reader→handler wrapper | Готово в указанном объёме |24 native cases/4 tests; receive-A→ID lookup→PingResult reader→OnHandler entry, TLS/current cleanup; registry fixtures/handler capture, не gameplay side effects |
| H03b.2b-receiveB | Keyed receive-B и дополнительные действия | Готово в указанном объёме |39 native cases/4 tests: XOR/key, ID table lookup/remove, empty notify, Dispatch; manager/registry fixtures/handler capture; session semantics и full integrity открыты |
| H03b.2b-sendB | Keyed send-B/queue ownership | Готово в указанном объёме |40 native cases/5 tests, Ping/KeyChanged/CRC/key/seq/wrap и synchronous copy, shared encoders/bounded queue; drain/socket и весь Notify→wire открыты |
| H03b.2b-drain | Queue→socket и partial send | Готово в указанном объёме |61 native cases/5 tests, ordinal send provenance, partial consume/errors; portable bounded pump/real IPv4 loopback; connect/auth/shutdown/scheduler ещё открыты |
| H04 | Авторизация почта/пароль→игровая сессия; H01 | Частично: H04a static SDK/token-form evidence | Прослеженный SDK/HTTP/session flow, параметры/сроки/ошибки, ручные challenge; секреты защищены, игра не нужна |
| H04a | SDK auth graph и token request forms | Готово в указанном объёме |24 symbols/34 LEA/24 roots, 143 constants, 512 native escaping calls/5 tests; offline code/refresh plans, не email/password login/config/response/game handoff |
| H04b | Источник SDK config GMC2 и параметры | Частично: real public response decoded | Source-bound build 0/A probe дал 200/errorCode=0/DECKEY HTTP header; 93 ordinary+1 secret=94 merged constants, auth URL fields и offline token binding. Active settings/native callback/email authorization остаются открыты; HEADLESS-PUBLIC-GMC2.md |
| H04b-settings | Class defaults и game overrides; H04b | Частично | 9 property descriptors, 4 constructor + 13 game native replays; market/game/client globals и environment→zone rule; actual singleton+48 load/call order неизвестны |
| H04b-CDN-source | Физический Game config и actual CDN values; H04b-settings | Частично | Generated key callback + точные directory SHA1; 7067 paths и два packed Game INI слоя восстановлены. Найдены defaults, active parameter/command-line/late overrides/scheme/CdnConfig ещё открыты; HEADLESS-PAK-CONFIG-RECOVERY.md |
| H04b-CDN-HTTP | Получение CDN config; H04b-settings | Частично: public HTTPS profile verified | Offline native URL/GET/response foundations плюс real 200/6000-byte public CDN snapshot; active settings/native TLS/lifecycle/прочие framing paths открыты; HEADLESS-PUBLIC-CDN.md |
| H04b-CDN-decode | Body → JSON → SDK environment; H04b-CDN-HTTP | Готово в ограниченном offline-профиле | Bounded Unicode, AES fallback с optional backend, строгий JSON dict и exact NetmarbleS/Zone → SDK selector; native crypto/parser core и Android не проверены; HEADLESS-CDN-JSON-FLOW.md |
| H04b-CDN-servers | Выбор server_list и raw lobby details; H04b-CDN-decode | Готово в ограниченном offline-профиле | 31 native replay (30 whole SetServerList), first ASCII-fold type match, четыре detail fields; общий изолированный raw plan, без endpoint validation/IO; HEADLESS-CDN-SERVER-LIST.md |
| H04b-CDN-accept | Полный ReadJson/применение/startup; H04b-CDN-decode | Частично | SetServerList проверен с JSON/FString shims; осталось проверить остальные поля ReadJson, актуальные settings/документ, полный порядок применения/ready/lifecycle и endpoint/auth handoff |
| H04b-secret | Декодирование secret constants; H04b | Готово в локальном Windows profile | Existing native primitives + real public PKCS8 RSA 3072/OAEP SHA256/list decoded; native PEM parser acceptance и Android ещё не проверены; HEADLESS-PUBLIC-GMC2.md |
| H04b-map | Merge строковых констант и auth URL getter; H04b-secret | Готово в данном response profile | Real 93 normal/1 secret ->94  string map, auth URL lookup и offline token binding; nonstring JSON отвергается local policy, full native callback/active values не доказаны |
| H04b-path | Полный адрес token request; H04a/H04b-map | Готово в указанном offline-объёме | 70 native path scenarios, bind_token_request с явной картой и сохранённым body; acquisition/HTTP/browser code/session handoff не реализованы |
| H05 | Один вход и модель персонажа; H02–H04 | Осталось | Выбрать правильный сервер/персонажа, получить ID/world/position/HP; живой тест без процесса игры |
| H06 | Общий runtime на Windows/Android; минимальный H03 | Осталось | Один сетевой/codec smoke на двух платформах, зависимости закреплены; UI/OS вне ядра |
| H07 | Боевой цикл на месте; H05 | Осталось | Доказать client/server обязанности автобоя, команды/результаты/кулдауны, stop; один аккаунт 30 мин без игры |
| H08 | Менеджер 1–20 аккаунтов; H05/H06 | Осталось | Изоляция, последовательное подключение, независимый stop/reconnect; 20 сессий, 2 часа, без смешивания состояния |
| H09 | Онлайн 2D-карта и панель; H05 | Осталось | Проверенная world→map привязка, живые слои/выбор аккаунта, старт/стоп, stale indicator; пустые неизвестные данные не выдаются за координаты |
| H10 | Движение и выбор точки на 2D-карте; H09 + H03 + подтверждённая навигация | Осталось | Проверить move schema, позиции/достижимость/остановку; выбор точки отправляет только доказанные команды |
| H11 | Безопасное восстановление; H05/H07 | Осталось | После разрыва сначала sync state, ограниченный backoff; смерть/challenge/защитное/unknown→pause; без повторения неизвестных действий |
| U01 | Manifest и снимки выпусков; H01 | Частично: immutable аудит 163 архивов; 34 changed/1 added; EXE SHA прежний | Source/build/SHA256 + зависимости генераторов, immutable snapshots, версия Windows/Android отдельно; неизвестная версия явно unknown |
| U02 | Инкрементальное извлечение и diff; U01/H02/H03 | Частично: свежие индексы 35 архивов и 1565 CSV pakchunk1; 298 без точного старого совпадения | Сравнить packets/IDs/schema, auth, таблицы, world/map; пересобрать затронутые наборы, сохранить происхождение/прошлый выпуск |
| U03 | Compatibility gate и обновление пакета; U02/H05/H07 | Осталось | Offline regression + ограниченный live canary, явный compatibility result, atomic switch, recovery; ошибочный/частичный update не заменяет проверенный |
| P01 | Компактные runtime-данные и bounded resources; H03/H09 | Частично: OutboundFrames имеет byte/frame limits; общий runtime ещё не готов | В сборке нет EXE/PAK/analysis library, данные региона по требованию, ограничены очереди/кеш/история; UI не дублирует полный мир на каждый tick |
| P02 | Профилирование и оптимизация; H08/P01 | Осталось | Размер сборки/данных, RAM/CPU/network для 1/10/20, двухчасовой soak без неограниченного роста; бюджеты принять по замерам, обещаний без измерений нет |
| A01 | Android-служба и оболочка; H06/H07 | Осталось | Тот же core, foreground/notification/Stop, экран выключен/network changes; масштаб на телефоне определить измерениями |

## Текущее продолжение

Full default GET header: 7 native blocks + 4 overrides; общий encoder и
Draft.header_bytes проверены offline. [HEADLESS-CDN-HEADERS](../resource-tools/vampir/HEADLESS-CDN-HEADERS.md).
Далее response/status/body limits/chunked/compression/JSON/callback order,
request queue/TLS и реальные Game config values/late overrides.

URI parser: 22 native URL→URI→GET-line cases; общий strict ASCII subset,
16 supported/6 rejected. [HEADLESS-CDN-URI](../resource-tools/vampir/HEADLESS-CDN-URI.md).
Draft URI/request_line готов в offline объёме; далее full headers/body,
TLS/response/status/limits/JSON/callback order и фактический Game config.

HTTP defaults: 16 native GET/1.0 request-line scenarios и frozen offline draft.
[HEADLESS-CDN-HTTP](../resource-tools/vampir/HEADLESS-CDN-HTTP.md).
Далее URI parsing/full headers/body/status/limits/TLS/late overrides/callback order;
actual Game config values остаются неизвестны, реальные requests не отправлены.

CDN preparation: 15 native AppVersion replacements + compiled Windows platform
chain + 7 return-tag branches проверены. [HEADLESS-CDN-PREPARATION](../resource-tools/vampir/HEADLESS-CDN-PREPARATION.md).
Общий offline URL из явных settings готов в указанном объёме; далее actual Game
config/late overrides, HTTP semantics и callback order. Не повторять version tail.

CDN URL tail: 16 native concat/growth сценариев и общий ASCII assembler готовы
в offline объёме. [HEADLESS-CDN-URL](../resource-tools/vampir/HEADLESS-CDN-URL.md).
Version preprocessing/platform getter закрыты следующим этапом выше; реальные
Game config/bases/prefix/late overrides остаются неизвестны, network_ready=false.

CDN selection: 16 native Find/branch cases и общий helper с явными bases.
[HEADLESS-CDN-SELECTION](../resource-tools/vampir/HEADLESS-CDN-SELECTION.md).
Loader file-global связан с Game; текущие physical config/URLs неизвестны.
Следом physical/cooked Game config и late parameter overrides, полный URL
builder; поиск 4 markers в decoded pak0 результата не дал (75 encrypted skipped).

H04b: найден CDN ReadJson → NetmarbleS.Zone → environment field+48,
7 native slices; [HEADLESS-CDN-CONFIG](../resource-tools/vampir/HEADLESS-CDN-CONFIG.md).
Далее actual NetworkSetting.CdnConfigUrl/QA/ConfigPrefix, источник настроек,
полный URL builder и callback order до GMC2. Active environment пока неизвестен.

H04b: constructor settings и game InitSetting исследованы, 4+13 native cases.
[HEADLESS-SDK-SETTINGS](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md).
Заполнение singleton14b575630+48 из CDN JSON прослежено следующим этапом выше;
порядок с GMC2 Start, active environment и поздние изменения globals/build открыты.

После подтверждённого пользователем обновления U02 частичен: новые индексы
34 изменённых и одного нового архива сохранены отдельно; 1565 CSV pakchunk1
извлечены и сравнены. Дальше обновлять затронутые зависимости/связи, не применять
прежние offsets к текущим архивам. См. [свежие результаты](../resource-tools/vampir/CLIENT-RELEASE-INDEX.md). [Аудит и происхождение](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md).
U01 частичен: нет полной SHA-проверки остальных архивов, game/Android version
неизвестны, compatibility gate ещё не готов. EXE-bound исследования сохранены.

H03b остаётся частичным: выбранные send/receive пути подтверждены offline,
но нет server-compatible connection/session. Не повторять закрытые исследования.
H04a закрыт в HEADLESS-AUTH.md: SDK auth graph/code-refresh forms.
H04b начат: GMC2 selector проверен на 256 mode values, активный mode неизвестен.
HEADLESS-SDK-CONFIG.md. Далее settings+0x49/getters 0x144524390/0x14452b820,
response/decode → authTokenUrl/authAccountUrl/authUrl/clientId/region, browser code
и token responses/expiry→SDK session→game Login. Также connection setup, receive accumulation,
readiness/таймауты и session lifecycle. Затем полный Notify→wire и live canary.

Закрытые bounded этапы: raw stage/block decoder, listener loop/receive-A,
Dispatch до PingResult OnHandler entry, receive-B/ID bookkeeping, send-B/copy,
queue drain→Winsock send. Для drain61 native cases; portable pump прошёл real
IPv4 loopback test. HEADLESS-SEND-DRAIN.md. Native fatal close/diagnostic,
nonempty notifications/concurrent lifetime и whole transport integrity ещё unknown.
Runtime OutboundFrames хранит partial head offset; socket_send не выполняет
connect/retry и требует от session owner readiness scheduling/error handling.

Уже подтверждено:

- Ping payload и исходящий send-A кадр: HEADLESS-PING-CODEC.md и HEADLESS-SEND-FRAME.md.
- CRC32/XOR: HEADLESS-FRAME-PRIMITIVES.md.
- Length probe 0x144aa9a90 и статическая связь B callback → Dispatch:
  HEADLESS-RECEIVE-ENVELOPE.md. Вход Dispatch имеет ID+3/body+5;
  исходящий send-A — ID+7/body+11. Эти слои нельзя отождествлять без tracing.
- Смена ключа: Notify handler 0x146765050 → ack ID12 → setter 0x144aab330.
  Ключ приходит в Notify ID11; send ack вызывается до записи peer+248.
  HEADLESS-KEY-CHANGE.md, headless-key-change.json. Первичная авторизация,
  генерация ключа сервером и доставка ack этим не доказаны.

Библиотека отчётов: F:/PhoneExit Resources/Vampir/code-clues/.
Исходные адреса относятся только к указанному в отчётах SHA EXE.
Login/LobbyLogin имеют одинаковые ID3/4 при разных схемах и контекстах.
H04 (SDK auth) остаётся отдельной зависимостью. U01 делать до приёма
следующего обновления игры; новые версии без проверки не считать совместимыми.

Критерий продукта: Windows без процесса игры, 10–20 аккаунтов, управление
через живую 2D-карту, проверенный фарм, замеренная нагрузка и воспроизводимые
обновления данных. Статические связи и offline replay этот критерий не закрывают.
