# Vampir — главный файл разработки

## Native connect result и wrapper acceptance, 19 октября

16 native сценариев проверили sockaddr IPv4/IPv6, connect call sites
и ветвь ожидания. Wrapper принимает raw engine codes 22/23/37 даже
после lower false; это не connected/session proof. Winsock/wait fixtures.
Далее error mapping и mode/job completion → readiness → Login.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-CONNECT-RESULT.md).

## Resolver result → socket creator, 19 октября

7 native integrations связали real resolver dispatch/peer recipient
и socket creator. Winsock ordinal 23 подтверждён как socket; аргументы
IPv4/IPv6 и отказы проверены. Syscall и endpoint connect остаются captures,
реального соединения и Login ещё нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVED-SOCKET-SETUP.md).

## Resolver run/completion проверены, 19 октября

8 native scenarios исполнили job run/completion с fixture Winsock responses.
Проверены family traversal, native IPv6-first swap и failure/empty callbacks.
Импорты getaddrinfo/inet_ntop source-bound; DNS и socket readiness ещё не исполнялись.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVER-JOB-RESULTS.md).

## Нижний connect → resolver handoff, 19 октября

12 native integrations связали lower connect, host/port copy, две
регистрации и lexical выбор numeric/hex либо задания имени. Job enqueue/
parser callbacks остаются captures; return true не доказывает готовый socket.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## Game connect: host/port consumers, 19 октября

13 native scenarios связали BeginGame fields с ConnectToServer и реальным
endpoint constructor. +0x278/+0x288 — основная host/game-port пара; есть
override +0x290/+0x2a0. Нижний connect capture; сети и Login ещё нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).

## BeginGame: сервер → transport target, 19 октября

11 native сценариев связали last server ID, fallback/lookup, busy gate
и четыре target setters транспорта. Коллизии/отказы/точные raw fields
проверены. Endpoint/protocol роли fields и реальное соединение ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## Title state и BeginGame SDK gate, 19 октября

10 native сценариев проверили отдельные head/tail slices title handler
и IsSignIn gate BeginGame. Title flag interface+0x230 и SDK+0x400 независимы
в этих slices. Средняя UI/policy часть пропущена явно; полного входа нет.
Далее BeginGameImpl/server selection → packet Login.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-STATE.md).

## Manager-child → title auth-success, 19 октября

Семь native сценариев связали manager-child/router с рассылкой slot+0x08
и OnSuccessNetmarbleSDKAuth 0x14641d560. Переход условный; idp/policy/channel
inputs явные fixtures. Тело title handler и packet Login ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## Game-instance success ветвь — Google PGS, 19 октября

Getter 0x1450b11b0 и virtual+0x10 названы по diagnostic/vtable:
FPGSIDProvider::GetOrCreate/SignIn. Windows body готовит отдельный unsupported
result. Четыре native интеграции исключили эту ветвь из прямого game Login.
Далее manager-child action и реальные title success notifications.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-PGS-BRANCH.md).

## Game success broadcast, 19 октября

12 native сценариев проверили рассылку живым подписчикам. Source-bound title
slot+0x30 вызывает дочерний virtual и очищает pointer; это ещё не packet Login.
Следующий участок — отдельная game-instance ветвь успешного callback.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-SUCCESS-BROADCAST.md).

## Auth silent → игровой callback, 19 октября

12 интеграционных native сценариев связали silent dispatcher, очередь,
реальный delegate bridge и игровой AutoSignIn callback. Передаётся исходный
response pair; error/expired owner не превращают AL=1 в успешную сессию.
HTTP response validation и переход от success actions к Login ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SILENT-GAME-DISPATCH.md).

## ChannelManager → Auth silent, 19 октября

12 native сценариев связали ChannelManager::SignInSilently с GetAuth и
FAuthImpl::SignInSilently. Сохранённый player ID и callback передаются дальше.
Пустой ID принимается верхней обёрткой, но отвергается Auth: первый вход
без сохранённого профиля этим не реализован.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## Игровой AutoSignIn callback, 19 октября

15 native сценариев проверили weak-owner gates и ветви raw result.
Найден отдельный SDK getter owner+0x170; его связь с auth+0x150 ещё открыта.
Дальнейший success callback и packet Login не исполнены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-AUTO-SIGN-IN.md).

## SDK result: очередь и callback, 19 октября

16 сценариев проверили dispatcher, перенос делегата и исходного response pair.
Native binder/virtual invoke подтверждены; обёртка возвращает true независимо
от fixture callback result. Реальный игровой получатель и Login ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-RESULT-DISPATCH.md).

## SDK sign-in completion и общий parser, 19 октября

16 native сценариев связали idpInfo, код провайдера, SetSignIn и место вызова
финального dispatcher. Внутренний флаг может быть true при неполных данных.
Общий offline parser требует свежие token/player ID и явный errorCode 0.
Dispatcher, игровой Login и живая авторизация остаются открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## Native response variant conversion, 19 октября

10 cases исполнили converter/AsString/actual virtual TryGetString и CRT.
String и number-string representations связаны с source factories/vtables.
JSON parser type selection и double/bool/прочие ветви ещё открыты.
Далее idpInfo и final callback/SetSignIn →SDK/game session.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-VARIANT.md).

## SDK response gates связаны с field traversal, 19 октября

18 native cases: actual raw predicates/body/status getters → JSON/object
gate → string errorCode/_wtoi → player fields. CRT импорт и DLL SHA проверены.
Variant/JSON conversions fixtures; numeric JSON errorCode и error dispatch
ещё открыты. Slice completion не равен login/session.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-GATES.md).

## SDK response player fields, 19 октября

13 native response-slice fixtures связали resultData.accessToken с SDK
module token, а playerInfo/player — с playerId/country/region/status.
Constructor keys исполнены, JSON/settings/storage — fixtures/captures.
Network/errorCode gates и полный callback/session ещё открыты.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-RESPONSE.md).

## Migration allocator wrappers: граница уточнена, 19 октября

10 native scenarios подтвердили: проверенные allocation wrappers не обнуляют
rounded tail. Реальный allocator backend остаётся fixture, zero padding
не доказан. Миграция старых сохранений остаётся отдельной открытой задачей.
Следующий приоритет первого входа: SDK sign-in response/session → game Login.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-MIGRATION-ALLOCATION.md).

## Token payload и migration path, 19 октября

16 native container fixtures подтвердили count/padding/object gates; split/
decode/JSON primitives fixtures, signature validation этим не доказана.
8 migration fixtures отделили channelKey path от sub suffix. Padding tail
зависит от непроверенного allocator, готовой модели для unaligned ещё нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-TOKEN-PAYLOAD.md).

## NID storage suffix восстановлен для aligned ASCII, 19 октября

6 native fixtures: sub low-byte minus1 → actual AES-NI → HEX.
Aligned outputs совпали с AES-256 ECB и общим nid_storage_path.
nmDeviceKey используется как 32 ASCII bytes с сохранением регистра.
Token/sub acquisition, migration/active path и real identity ещё открыты.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-NID-SUFFIX.md).

## Auth-specific storage path gate, 19 октября

8 native fixtures проверили Load path gate: auth type netmarble → extra
directory и общий post-restore flag. Native compare/join; auth context/base/
suffix fixtures. SetupServiceSettingPath и command-line parser только static.
Save/Initialize читают тот же flag; active suffix/lifecycle ещё не доказаны.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-AUTH-PATH.md).

## Load device fields и filename defaults, 19 октября

16 native fixtures подтвердили раздельное восстановление SDK/NID device keys
из Save object и post-restore dispatch. Три constructor/path fixtures дали
ServiceSetting.bin (+0x2f8), отдельно от ServiceSettings.bin (+0x2e8).
Active path/optional directory и реальные Save/Load операции ещё открыты.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-LOAD-DEVICES.md).

## NID context использует отдельный device key, 19 октября

Три native pair slices связали NID web deviceKey и OAuth device_key с
GetDeviceKeyForNetmarbleId, а SDK sign-in использует другой getter.
Registry schema v2 добавляет отдельные nid_device_key/source, миграция
сохраняет прежние данные. Реальные ключи пустые, HTTP не выполнялся.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md).

## SDK storage directory и отдельный NID key, 19 октября

6 native fixtures подтвердили каталог base persistent directory + NetmarbleSDK.
Base getter — fixture; active path/filename ещё неизвестны. Save/Load/Initialize
и отдельный DeviceKeyForNetmarbleId (+0x628) сохранены как static evidence.
Не смешивать этот ключ с двумя уже известными полями.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-STORAGE.md).

## Native SetDeviceKey и getter integration, 19 октября

56 setter fixtures и 12 getter/setter integrations подтвердили native
case-insensitive ASCII compare, force write и изменение settings даже после
write=false. Getter flag=false не запрещает запись внутри setter.
Platform/storage остаются fixtures; Save/path пока статические sources.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-DEVICE-SETTER.md).

## Device getter branches проверены, 19 октября

8 NM fixtures с повторным вызовом и 12 DeviceKey fixtures исполнили native
выбор cache/storage/settings/generation. Отказы write/Save не мешают caller
вернуть ключ; повторный NM вызов после write=false не повторяет запись.
Parser/storage/platform/setter/Save остаются явными fixtures/captures.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-DEVICE-LIFECYCLE.md).

## Device identity: storage и native формат GUID, 19 октября

Статически найдены отдельные постоянные nmDeviceKey и deviceKey, Windows
registry helpers и CoCreateGuid. Default formatter и hex writer исполнены
на трёх synthetic fixtures: 32 uppercase hex без дефисов. Реальные ключи
не читались; getter/platform/Save branches ещё требуют replay.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).

## Постоянная привязка почты к устройству, 19 октября

Добавлен общий локальный SQLite-реестр account → device profile → confirmation.
Основная тестовая почта зарегистрирована в игнорируемой базе; реальные deviceKey
и nmDeviceKey ещё не получены. Профили сохраняются между запусками/обновлениями.
[Схема, источники и дальнейшие задачи](../vampir-headless/DEVICES.md).

## SDK sign-in request plan: JSON и headers, 19 октября

Native caller подтвердил body nmDeviceKey/deviceKey/countryCode/os, optional
playerId и credential33. 4 body/8 header fixtures: POST JSON, gameCode/buildCode,
optional accessToken/authToken из отдельного SDK token context.
Общий sdk_sign_in формирует immutable plan по explicit inputs и authUrl из
SDK constants; real public config binding проверен offline, POST не отправлялся.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN.md).
Далее response callback 1444d85f0 → SDK token/player/expiry → game Login.

## Provider20 → SDK credential33, 19 октября

Native OnResult продолжен до регистрации credential: Save return не проверяется,
следом clear credentials и insert по SDK channel33. GetObject добавляет
channelAccessToken из provider access token и numeric channelCode33.
Общий nid_sdk_credential повторяет эти два поля без HTTP/storage/login success.
Provider email channel20 остаётся отдельным значением.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-CREDENTIAL.md).
Далее полный FAuthImpl SignIn request/response и SDK→game session.

## Callback URL: percent loop и строгая общая граница, 19 октября

147 native byte-loop fixtures: + остаётся плюсом, decode однократный;
malformed escapes/NUL обрабатываются permissive в native. Общий sdk_percent
использует строгий printable ASCII subset. parse_nid_email_callback проверяет
явно заданную game route и поля → redacted provider credential, без I/O.
Это local policy, не full native URI/map или доказательство действительности
токенов/активной попытки входа. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-PERCENT.md).
Далее full query/context, settings/persistence и SDK callback/session.

## Integer/channel helpers исполнены, общий result boundary добавлен, 19 октября

28 numeric/45 channel/6 caller fixtures исполнили native helpers и локальный CRT.
mailUserKey →20, ASCII case-insensitive. Native parser принимает 0abc как zero;
общий nid_result требует точный resultCode="0" по явной локальной политике.
Валидатор принимает decoded fields, проверяет presence и возвращает redacted
provider credential. Query/origin, storage, setters/callback/session ещё открыты.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).

## Native OnResult: проверки и аргументы принятия токенов, 19 октября

22 fixtures исполнили caller validation/adoption slice и FString copy.
Access/refresh/ID/country передаются раздельно; пустой refreshToken допустим,
отсутствующий ключ не равен пустому. Missing fields сохранили null-read outcome
в fixture map contract, без заявления о crash живой игры. Parser/channel/map/
settings остаются явными shims/captures.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).
Далее parser/channel/query semantics, setters/callback → SDK/game session.

## Почтовый вход передаёт отдельный NID result, 19 октября

Проверены выбранные JS helpers: четыре комбинации refresh policy и восемь
переходов authType/profile gate. Email branch передаёт accessToken через
nmidprovider/result после обработки профиля; authorization_code не подставлять.
В EXE найден OnResult и 14 связей globals → initializer literals. Это static
native evidence, принятие токенов SDK ещё не проверено.
[Источники и воспроизведение](../resource-tools/vampir/HEADLESS-NID-RESULT.md).
Далее native OnResult parsing/validation/token adoption → SDK/game session.

## Найден контракт входа NID по почте, 19 октября

Публичные HTML/JS по authWebViewUrl из GMC2 сохранены с SHA256 вне Git.
Подтверждены POST /api/signin/netmarble, RSA PKCS1v1.5 для email/password,
reCAPTCHA action members_signin и заголовки interceptor. Общий nid_email
готовит только локальный зашифрованный план запроса; login POST не выполнялся.
Legacy FEmailAuth и Netmarble ID разобраны отдельно, выбор провайдера игрой
ещё не доказан. [Источники, воспроизведение и границы](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Уточнение следующего этапа: email result → native OnResult → SDK/game session.

## Получена и разобрана реальная GMC2-конфигурация SDK, 19 октября

Source-bound public GET без account/device credentials вернул 200/errorCode=0.
DECKEY наблюдался в HTTP response headers; offline decoder получил 93 ordinary
и 1 secret constant, merged 94. Auth URL fields найдены, token-plan привязан
offline с искусственным code; auth HTTP не выполнялся. PKCS8 DER backend
поддержан наряду с PKCS1; encrypted outer NUL разрешён, plaintext policy прежняя.
[Source/profile/snapshot/границы](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).
Active BuildCode/native callback и email/password→session остаются открыты.

## Исправлен составной decoder SDK constants, 19 октября

Повторно использован ранее проверенный JSON-unescape. decode_sdk_constants_string
теперь вызывает actual-output XOR с пропуском нулей; прежний raw XOR helper
остаётся только отдельной capture-моделью. Два regression tests проверяют
zero outcome и все 18 новых native fixtures через составной путь.
[Источник и границы](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
DECKEY lookup/полный response/auth остаются открытыми.

## GMC2 XOR: подтверждён primitive расшифровки, 19 октября

Полный native DecryptXOR и FString append проверены на 18 fixtures.
XOR идёт по uint16 units повторяющимся key; нулевые результаты append
пропускает. Общий xor_gmc2_utf16_units возвращает raw units, без Unicode/JSON
или получения ключа. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).
Далее source decode/key/DECKEY/encSecretConstants и весь response contract.

## GMC2 GET: постоянные и условные headers, 19 октября

16 native fixtures подтвердили header preparation и GET method argument:
шесть постоянных headers, eTag при непустом значении и playerId/accessToken
по token gate. HTTP virtual methods — captures, device/player — return fixtures.
Общий immutable план скрывает URL/headers в repr и не выполняет сеть.
[Источник/ограничения](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).
Далее response decode/DECKEY/auth URLs; active settings/device identity открыты.

## GMC2 URL: native сборка и общий helper, 19 октября

26 native fixtures подтвердили base/group/SDK version/build/market сборку,
включая actual ASCII-view append и getters. Общий assemble_gmc2_config_url_ascii
сохраняет слэши/raw characters, не делает HTTP или выбор active settings.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-URL.md).
Далее RequestGMC2 headers/response decode и auth URL values.

## SDK bootstrap: версия и BuildCode, 19 октября

Native getters подтвердили SDK version 5.2.11 и BuildCode byte1→B/2→C/остальные→A.
Исполнены compiled initializers и 256 getter fixtures, общий select_sdk_build_code
добавлен в vampir_core. Это отдельные поля от game AppVersion и SDKZone.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Active BuildCode, полный GMC2 URL builder/response и авторизация ещё открыты.

## Получена публичная CDN-конфигурация, 19 октября

HTTPS GET по base INI профилю вернул 200/6000 байт. Общие декодеры разобрали
реальный документ: SDK Zone=real, server index=6/type=REAL, поля лобби заполнены.
Снимок с SHA/HTTP provenance сохранён, offline replay не требует сети.
[Инструмент, снимок и ограничения](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md).
Active INI/native acceptance не доказаны; подключений к лобби/аккаунтам нет.
Оба module descriptor совпали base/patch: NnNetwork и NkPatchRuntime имеют
фазу Default. [Источник/границы порядка](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).

**Начинать здесь при любом продолжении работы над ботом Vampir.**
Обновлено 19 октября 2026. Исполняемая точка входа — `bot.py`, документационная
точка входа — этот файл. Здесь хранится карта проекта, подробности — по ссылкам.

## NetworkSetting читается при регистрации callback, 19 октября

Прослежены factory/vtable владельца → FNnNetworkVar → callback → загрузчик
Game config. Восемь native slices подтвердили немедленный вызов callback
до вставки в реестр; тело загрузчика и вставка — capture shims.
[Источники, воспроизведение и ограничения](../resource-tools/vampir/HEADLESS-CONFIG-STARTUP.md).
Порядок относительно PAK mounting/GConfig cache ещё открыт; active слой не выбран.

## Основной Game config отличается от patch-слоя, 19 октября

Отдельно проверен ProjectRED-Windows.pak: подтверждены каталоги и 12425 имён,
извлечены DefaultGame.ini и WindowsGame.ini. Base NetworkSetting содержит
AppVersion 1.12.14, prefix real, CdnConfig=True; patch pakchunk0 — 0.1.1/dev/False.
Оба слоя сохранены с SHA и source offsets. Порядок загрузки и active settings
ещё не доказаны; версия INI не объявляется версией релиза.
[Инструмент, снимок и сравнение](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

## Восстановлены PAK-каталог и packed Game config, 19 октября

Generated key callback исполнен native; SHA1 расшифрованных main/full directory
совпали. Получены directory-backed имена 7067 файлов и DefaultGame.ini +
WindowsGame.ini в отдельном immutable снимке. Найдены NetworkSetting defaults:
CDN bases без scheme, AppVersion 0.1.1, prefix dev, CdnConfig=False.
Это packed layers, не доказанные active settings; overrides ещё открыты.
[Источник, SHA, исправление record hash semantics](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).
Ключ подтверждён хешами каталогов; сетевые запросы ещё не выполнялись.

## Предыдущий поиск актуального источника CDN, 19 октября

CDN-derived candidate не подтвердился для encrypted directory. У encrypted
records SHA1 относится к ciphertext: прежнее сравнение с plaintext не проверяет
ключ. 23 records пропущены по bounds, compressed payloads не проверялись. Восемь plain records прошли hash controls.
Три EncryptionKey name xrefs сохранены как clues без доказанной PAK-связи.
[Источник, воспроизведение и ограничения](../resource-tools/vampir/HEADLESS-CDN-SOURCE-PROBE.md).
Этот прежний probe не восстановил key/config; новый результат описан выше.

## Выбор сервера и поля лобби из CDN, 19 октября

Установлено назначение 145661a70: _SetServerList. select_server/type выбирает
первый ASCII-case-insensitive match в server_list. Читаются detail/lobbyAddress,
lobbyPort, patchURL, dataURL. 31 replay, включая целую функцию для 30 входов.
Общий select_cdn_server возвращает отдельный raw detail plan без globals;
missing fields — None, без наследования адресов другого аккаунта.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SERVER-LIST.md).
Реальные config values, пригодность endpoint и подключение ещё не проверены.

## JSON CDN и поле окружения SDK, 19 октября

12 native slices уточнили parser/object → fallback/ReadJson и обязательную
следующую validation. Общий decode_cdn_config_document разбирает plain либо
AES-encrypted JSON; read_cdn_sdk_environment читает NetmarbleS/Zone без default.
Проверена offline цепочка whole HTTP body → JSON → Zone → SDK mode.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-JSON-FLOW.md).
Полный ReadJson/secondary validation, actual settings/TLS ещё открыты.

## Запасная расшифровка CDN, 19 октября

Найдена fallback-ветка: IV16 + AES-256-CBC, key = SHA256 от compiled seed.
21 native orchestration replay проверяет аргументы, descriptor и error cleanup;
SHA/EVP primitives — явные backend shims, native crypto core не исполнялся.
Общий decrypt_cdn_fallback возвращает bounded raw bytes через optional crypto.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-FALLBACK.md).
JSON acceptance/реальный config/settings/TLS и HTTP compression ещё открыты.

## Декодирование тела CDN и BOM, 19 октября

31 native body replay и 9 status-gate slices подтвердили BOM-ветки и вход
в CDN body branch для 200–299. Найдено чтение UTF-16LE за длиной тела на
искусственных guard fixtures; общий код его не повторяет: строгий bounded
UTF-8/UTF-16LE decoder, корректные surrogate pairs, запрет NUL, лимит 2 МиБ.
[Источники, SHA и отличия](../resource-tools/vampir/HEADLESS-CDN-BODY.md).
Сжатие/chunked/EOF/полный JSON callback/settings/TLS ещё открыты.

## Content-Length и полнота тела CDN, 19 октября

30 native сценариев подтверждают lookup/atoi/unsigned receive comparison;
ещё один folded-field fixture остановлен по лимиту инструкций.
Общий take_cdn_length_response ждёт полное тело по одному Content-Length,
с локальными ограничениями 2 МиБ/status 200/без compression, range и chunked.
[Доказательства и границы](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-LENGTH.md).
Полный parser/receive loop, остальные framing/decode и JSON ещё не готовы.

## Начальный разбор ответа CDN, 19 октября

52 native сценария подтвердили CRLFCRLF boundary, статус из первых 12 байт
и число уже доступных байт тела. Общий cdn_response.py разбирает только head
со строгой локальной HTTP/1.x политикой и лимитами; полнота тела не заявляется.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-HEAD.md).
Повторный аудит установки совпал со снимком обновления: 34 изменённых архива,
один новый, EXE прежний. TLS/body/JSON/actual settings ещё открыты.

## Полный базовый CDN GET header, 19 октября

Native URI/context/header pipeline проверен на 7 default и 4 override сценариях.
Default: GET/1.0, Host с port, Aqua/1.0 и конечный CRLF; пустые body/query/cookie/
range, без Content-Length/Type/Connection. Общий encode_cdn_get_headers и
Draft.header_bytes совпали побайтно с native. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-HEADERS.md).
Transport/TLS/response и actual settings/late overrides пока открыты.

## URI parser и строка CDN запроса, 19 октября

22 native URL→URI→GET-line сценария подтвердили scheme/host/uint16 port/path.
Общий parse_cdn_uri_ascii поддерживает строгий ASCII subset; 16 совпадений,
6 native quirks отклоняются. Draft хранит parsed URI и даёт request_line bytes,
без полного HTTP. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-URI.md). Реальные settings/headers/TLS/
response всё ещё открыты; network_ready=false.

## HTTP defaults CDN и offline draft, 19 октября

16 native сценариев подтверждают constructor→method 1→GET request line HTTP/1.0,
с пустой query collection и явными parsed-path fixtures. Общий cdn_request.py
даёт immutable draft URL/GET/1.0 со строгой локальной проверкой HTTPS; HTTP нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-HTTP.md). Полные headers/body/TLS/response и реальные values
ещё не проверены; native default не выдаётся за готовый сетевой клиент.

## Подготовка CDN версии и Windows platform, 19 октября

15 native replays подтверждают AppVersion dot→underscore. Исполнена цепочка
compiled platform initializer→vtable getter→code 2→window; ещё 7 ветвей проверены
с return-value fixtures. Общий prepare_cdn_config_url_ascii собирает URL из
явных normal/qa/prefix/app_version/platform_code, без HTTP.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-PREPARATION.md). Actual config values и request semantics ещё открыты.

## Сборка CDN URL из фрагментов, 19 октября

16 native сценариев подтвердили завершающую сборку base+platform/prefix/version/
config.json, включая std::string growth/move. Общий assemble_cdn_config_url_ascii
принимает явные готовые ASCII-фрагменты, без HTTP и преобразования AppVersion.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-URL.md). Реальные базы, version preprocessing и platform getter
ещё требуют проверки; действующий адрес не заявляется.

## Выбор CDN по ConfigPrefix, 19 октября

16 native сценариев подтверждают поиск подстроки real без учёта ASCII-регистра:
она выбирает CdnConfigUrl, иначе CdnConfigUrlQA. Это отличается от точного
сравнения SDK Zone. Общий select_cdn_config_base требует явных prefix/normal/qa.
Config loader связан с логической конфигурацией Game; текущие URLs неизвестны.
[Доказательства и ограниченный поиск в pakchunk0](../resource-tools/vampir/HEADLESS-CDN-SELECTION.md).

## Источник окружения SDK, 19 октября

Прослежена загрузка CDN config: ReadJson читает NetmarbleS → Zone и пишет
поле, которое InitSetting использует для выбора SDKZone. 7 native slices
с capture shims подтверждают аргументы lookup/ветку missing/destination.
Начальное dev не выдаётся за активное окружение; CDN URLs берутся из
NetworkSetting, реальные значения и полный startup order ещё неизвестны.
[Доказательства и продолжение](../resource-tools/vampir/HEADLESS-CDN-CONFIG.md).

## SDK settings и game override, 19 октября

Подтверждены 9 полей NMSDKSettings и начальные значения (4 native replays).
Найдена игровая InitSetting: compiled globals market nmp/game thered/client ID,
13 native сценариев сравнения environment → production при real без учёта ASCII
регистра, иначе Dev. Общий select_game_sdk_zone требует явного environment.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md). Активный environment и его загрузка пока неизвестны.

## Индексы обновлённых ресурсов, 19 октября

Построены свежие SHA-bound индексы всех 35 изменённых/новых архивов:
127 375 записей, ограниченный разбор без каталога PAK. Из pakchunk1 заново
извлечены 1565 CSV: 1267 точных совпадений со старым содержимым, 298 без
точного совпадения. Старые данные сохранены. [Результат, SHA и границы](../resource-tools/vampir/CLIENT-RELEASE-INDEX.md).
U02 частичен; производные графы/карты ещё не обновлены, совместимость не доказана.

## Обновление клиента, 19 октября

После нового сообщения пользователя повторный аудит получил тот же неизменяемый
снимок: дополнительных отличий от уже учтённого обновления не обнаружено.
Полные SHA256 35 изменённых/новых архивов и EXE совпали; остальные 128 архивов
сравнены только выборочно. U02 и сверка производных карт/связей остаются открыты.

Аудит обнаружил 34 изменённых архива и один новый; полный SHA256 EXE прежний.
Старые индексы изменённых архивов устарели, их offsets применять нельзя.
Снимок сохранён отдельно; 128 совпадений выборочного отпечатка не доказывают
полную идентичность. [Манифест, инструмент и следующий этап](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md).
Совместимость с обновлёнными данными и сервером ещё не установлена.

## Текущее состояние самостоятельного клиента, 19 октября

Выбранные send/receive пути, CRC/XOR/распаковка, queue ownership/partial send
проверены native replay; portable pump прошёл local IPv4 TCP.
[Transport и границы](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
H04 начат: 24 SDK symbols/34 LEA/24 roots, 512 native escape calls, offline
code/refresh token request plans. [Авторизация](../resource-tools/vampir/HEADLESS-AUTH.md).
Источник конфигурации GMC2 найден: выбор адреса проверен на 256 значениях
режима; активный режим и параметры установленной игры ещё неизвестны.
[Доказательства](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Уточнены строка SDK `5.2.11`, начальные строки build `A/B/C` и отдельный
UTF-16 XOR GMC2: 42 native проверки, общий ограниченный модуль.
[Параметры и границы](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).
Перед XOR подтверждён разбор строковых escape GMC2: 43 корректных, 7 граничных
и 3 составных native сценария. Найдена статическая передача значения DECKEY;
точный метод его получения ещё исследуется.
[Ответ GMC2](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
19 октября: общий Base64-декодер секретной ветки проверен; 16 native сценариев
подтверждают аргументы OAEP. [Доказательства и границы](../resource-tools/vampir/HEADLESS-SDK-SECRET.md).
OAEP checker исполнен на 24 корректных и 69 ошибочных входах; общий декодер
одного secret chunk проверен на искусственных RSA-ключах Windows.
[Исполнение и ограничения Android](../resource-tools/vampir/HEADLESS-SDK-OAEP.md).
Список secret chunks собирается общим кодом в JSON; native orchestration
проверен на 9 основных и 4 граничных сценариях.
[Сборка списка и границы](../resource-tools/vampir/HEADLESS-SDK-SECRET-LIST.md).
Порядок normal→secret и замена совпавшего строкового ключа подтверждены;
SDK auth URL getter проверен на 24 native сценариях.
[Карта констант и auth lookup](../resource-tools/vampir/HEADLESS-SDK-MAP.md).
Правило path append проверено на 70 native сценариях; code/refresh plan
связывается с явно переданной конфигурацией без отправки HTTP.
[Полный адрес запроса и границы](../resource-tools/vampir/HEADLESS-SDK-PATH.md).
Полный вход по почте/паролю, SDK→game session, серверные endpoints и бой ещё
не реализованы. Все этапы/доказательства — в [TASKS](../vampir-headless/TASKS.md)
и [WORKLOG](../vampir-headless/WORKLOG.md); не повторять закрытые исследования.

## Общие находки и самостоятельный сетевой бот

18 октября: первый receive-stage `UxTcpPeer::_HandleRecvBuffer` подтверждён
62 native сценариями / 5 тестами: size 23, compression bit, copy/decompress,
compaction. Shared transport_header.py; receive_frame.py относится ко второму
слою, не raw stream. [Доказательства](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md).
Цельный listener pipeline и send queue ещё не готовы;
общий decoder с повторами добавлен следующим этапом выше.

18 октября: источник смены peer key подтверждён — PktKeyChangeNotify 11→
ackPktKeyChanged12→setter0x144aab330, send вызван ещё при старом ключе.
10 native roundtrips/16 shortcases/20 handler slices и 5 tests прошли.
[Доказательства](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md), общий key_change.py;
initialauth/receive integrity/transport ещё неполные.

18 октября, H03b.2b partial: incoming length probe 156 native cases/wrapper 13 cases,
static game callback→Dispatch подтверждён; общий receive_frame.py проверяет
полноту/локальные лимиты. [Доказательства](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md).
Приём CRC/keyflow/transport ещё неполные, сеть/игра не использовались.

18 октября, H03b.2a: цельный native send-A slice собрал Ping frames в 20 сценариях,
включая sequence wrap 65535→0. Shared `vampir_core/send_frame.py`, 5 tests прошли.
[Доказательства](../resource-tools/vampir/HEADLESS-SEND-FRAME.md), общий реестр
обновлён. Приём/context/key и подключение ещё не готовы.

Единый указатель общих компонентов: [vampir-shared/README.md](../vampir-shared/README.md).
Общий переносимый код: `vampir-shared/vampir_core/`; без копий на каждого бота.

Все направления используют [FUNCTION-INDEX.md](FUNCTION-INDEX.md) — общий
указатель найденных функций, адресов, источников/SHA и границ подтверждения.
Перед новым исследованием проверять его и подробный связанный отчёт; новые
подтверждённые находки добавлять туда независимо от направления работ.

18 октября 2026 открыто отдельное направление: [vampir-headless](../vampir-headless/README.md).
Цель — Windows без запуска игры, вход по почте/паролю, 10–20 аккаунтов,
лёгкая онлайн 2D-карта, переносимое ядро для Android и обновление данных вслед
за выпусками игры. [Задачи](../vampir-headless/TASKS.md),
[журнал](../vampir-headless/WORKLOG.md). Первый SHA-bound индекс:
27 сетевых строк/31 проверенная LEA, 1020 инструкций; wire/login/фарм ещё не готовы.
Экранный бот и исследование карты сохраняются отдельными направлениями.

18 октября, H02: для 10 выбранных сетевых типов подтверждены constructor/
vtable/ID/IO targets и 5 result registrations; 4 audit tests/10 native ID executions.
ID Login/LobbyLogin совпадают при разных схемах и регистрации; общий
FUNCTION-INDEX и [подробный отчёт](../resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md)
обновлены. Следом H03 primitive wire IO/framing/context, H04 SDK auth.
Самостоятельная сессия и бой по-прежнему не реализованы.

18 октября, H03a: реальными native primitive/raw IO подтверждены payloads
Ping 16 байт/Result 12 байт; 126 scenarios и 5 tests прошли, без primitive stubs
(внешний memcpy — bounded shim). Первое переносимое ядро `vampir_core/ping.py`
использует только stdlib. [Доказательства](../resource-tools/vampir/HEADLESS-PING-CODEC.md),
общий FUNCTION-INDEX и журнал обновлены. Framing/transport/auth ещё не готовы.

18 октября, H03b.1: CRC32 и повторяющийся XOR внешнего слоя подтверждены
252 native executions/5 tests и вынесены в общий `vampir_core/frame_primitives.py`.
Найдены два receive wrappers; XOR пропускает 3 байта. Frame/validation/key ещё
исследуются: [доказательства](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md).

**При продолжении читать [таблицу задач TASKS.md](TASKS.md):** выполненные работы,
частичные результаты, оставшиеся проверки и критерии завершения. После каждой
работы обновлять соответствующую строку; историю сохранять в журнале.

## Атлас карты, 17 октября 2026

18 октября: найден native initializer 14173c480, устанавливающий loading bit
archive+28&1 и actor-string gate archive+29&1.4 native flag cases подтвердили
сохранность прочих битов. Полный structured binding 14173eb10/adapter 141599f90
исполнен с bounded allocation, включая rebind; adapter возвращает embedded
archive. Связанный прогон init→package flags→version transfer→optional GUID→
actor tail заканчивается 443; native custom lookup вернул 8/170 без подмены.
Audit/97 recast tests прошли. Свойства до 375 ещё decoded descriptor-based,
не full native schema execution; active mesh/live routes не проверены.
Следом property schema/alignment и выбор активных тайлов. MAP-ATLAS.md.

18 октября: прослежены Linker summary→встроенный archive+240→прямой actor
serializer. Native setter/copy/getter вернули 170/8, missing key=-1:3 transfer
cases/15 lookups; 4 flag cases подтвердили package bits→archive bits02/40.
Constructor закрепляет vtable148a13918; прямой preload call передаёт этот
archive в 1452b8ff0 Nn actor. Audit и 97 recast tests прошли. Полная цепочка
всех wrappers/preload gates, loading/actor+29 flags и property serialization
ещё не исполнена; runtime mesh/движение не проверены. MAP-ATLAS.md.

18 октября: найдены native регистрации FortniteMain170 и UE5-PrivateFrosty8.
Nocturne и 34generated packages имеют zero serialized versions; native summary
gate выбирает общий registry snapshot, устанавливает scalar versions522/1013/0.
При registered170/8 actor tail заканчивается 443.2 registration/4 summary gate
replays и независимый audit прошли; 97 recast tests. Передачу этих versions/flags
из summary в фактический export archive ещё проследить; property boundary и
active mesh по-прежнему не объявлены доказанными. Источники/SHA — MAP-ATLAS.md.

Повтор codec с 170 завершён: 34 packages/19098 tiles/27249848buffer bytes,
независимая валидация прошла. Все buffers/records побайтно равны прогону 97;
геометрия и прежние reports97 сохранены. Новый output — hypothesis-170,
так как archive propagation/property boundary ещё требуют проверки.

18 октября: 68 bytes actor tail разобраны условно по native веткам: optional
GUID flag, строка NnRecastNavMesh-Default и две группы 4uint32 GUID.6 native
сценариев/audit/94 recast tests прошли. Важное ограничение: ключ custom version
тот же, что у tile threshold 97, но GUID pair читается лишь при version>=150.
При 97 tail заканчивается 411, при 150 —443. Версии/flags архива не извлечены;
offset 443 остаётся candidate. Полный UObject/schema/alignment и active area
remapping не исполнены. Следом восстановить источник archive versions/flags,
затем сверить tile decoder с ним. Источники/SHA — MAP-ATLAS.md.

18 октября: разобраны 8explicit actor properties до offset 375 (из 433unknown
value bytes осталось 68actor tail до candidate443). Native descriptor-derived
indices совпали: CellSize/resolution[3]/AgentRadius/NavDataConfig/SupportedAreas/
RootComponent5493→SceneComp этого actor. Serialized IDs MainRoad4/Forbidden3
не равны constructor 12/13; это saved export, не active map. CellSize*51 точно
даёт candidate width; float32 reciprocals resolutions совпали с quantization.
90 recast tests/audit прошли. Полный native schema builder/tail и runtime
selection ещё не проверены. Подробности/SHA — MAP-ATLAS.md.

18 октября: подтверждён shared serializer dispatch NnRecastNavMesh/Recast:
оба primary vtables d8→1452b91e0, e0→1452b8ff0; перед stream вызывается
14381b2b0→1417521e0. Закреплены 90 native descriptors NavigationData/Recast
с registry/getter/name provenance. Cooked header 8 fields/10 bytes известен,
433 bytes values до candidate offset 443 ещё не разобраны. 86 recast tests
прошли. Boundary и active selection остаются unknown. MAP-ATLAS.md.

18 октября: candidate grid params из Nocturne export 3919 сверены со всеми
18430 unique tiles: exact width 1000.0000133514404 даёт 0 boundary error/
0 minimum-cell mismatches; rounded1000 —13004 mismatches на minimum corners.
380 native pipelines при candidate origin/width/height/quantization повторены,
outputs/links не изменились. 83 recast tests прошли. Property boundary/active
runtime parameters пока не подтверждены; результат — consistency evidence.
Источники/SHA/границы — MAP-ATLAS.md.

18 октября: единый offline pipeline coordinate→projection→query→straight
исполнен в одной VM 380 сценариями/380 replays: 283 линии, 24 partial без линии,
73 projection-missing без линии. 122 линии проходят special points. 80 recast
tests прошли. Один baseline miss сохранён: ближайшая поверхность Y+70
при extent 50. Это анализ при explicit grid/filter/TLS, не восстановленный
gameplay wrapper и не движение бота. Подробности/SHA — MAP-ATLAS.md.

18 октября: full straight-path/funnel 145248b20 исполнен 472 cases/472 replays
для 236 коридоров: 66 internal/48 external/122 special. Независимый funnel совпал,
38 обычных путей имеют повороты; special endpoints/flags сохранены. 76 recast
tests прошли. TLS/static-init environment явно synthetic, epsilon из EXE.
Далее effective active mesh/filters/permissions и управление персонажем;
игровая проходимость не подтверждена. Источники/SHA — MAP-ATLAS.md.

18 октября: полный coordinate→tile hash→BV/filter→closest/detail-height→
nearest projection 1452451b0 выполнен 192 сценариями на 24 парах, независимо
сверен и повторён; 24 связки projection→polygon query также совпали. 72 recast
tests прошли. Grid origin 0/width 1000/hashmask 0 — явные synthetic inputs,
не runtime параметры. Line/funnel и живое движение ещё не выполнены.
Доказательства и границы — MAP-ATLAS.md.

18 октября: native construction→query проверены через границы тайлов и special
links: 218 cases/218 replays, 24 пары (4 стороны, полные/частичные интервалы),
61 special point в обе стороны; 1 из 62 пока без подходящей привязки. Независимый
audit сверил links, quantized intervals, достижимость и стоимость. 68 recast
tests прошли. Height 35/приоритеты/квантизация — явные offline scenarios;
custom-link runtime callbacks и cluster links отключены. Проекция/funnel,
active mesh/filters и движение персонажем ещё не проверены. MAP-ATLAS.md.

18 октября: впервые исполнен полный polygon query 1452457b0 на извлечённых
тайлах: 121 сценарий/121 replay, 33 тайла; internal links строятся native блоком
14523c6c1..14523c77a. Независимо проверены достижимость и стоимость цепочек,
флаги, лимиты узлов/стоимости; длина цепочки до 10 полигонов. 64 recast tests
прошли. Это single-tile
offline сценарии с явными фильтрами, без external/special links, проекции
точек и движения. Active mesh/CDO и реальные маршруты остаются непроверенными.
Инструменты, SHA и воспроизведение — MAP-ATLAS.md.

18 октября: исполнен полный native base initializer 1452b7120 с явными
SupportedArea/CDO inputs: 30 cases/30 audit replays, 34 anchors/28 fragments.
Стоимость 0,5 из CDO не получает clamp 1 из query override; entering также
передаётся напрямую. Отдельно проверена XY-ветвь выбора фильтра у caller
145688dd0→14569bcf0:13 cases/replays, порог squared9000000, ниже ShortPath,
на границе/выше Default; Z в этой ветви не участвует. 60 recast tests прошли.
Фактический поиск пути/active mesh/реальные маршруты ещё не проверены.
Источники, SHA и границы — MAP-ATLAS.md.

18 октября: подтверждён путь полей классов фильтров 780/788/790 через
class/CDO selector 1452818e0 к query helper145281400; vtable NnRecastNavMesh
slot3a0 вызывает три запроса, затем setter для base area 10–13 со значением 1.
Новый report 55 anchors/26 fragments, 16 native cases и независимых replay;
54 recast tests прошли. Найден base initializer 1452b7120 (slot8e0), его
создание impl и SupportedArea loop пока статическая проверка. Cached/active
значения и реальные маршруты всё ещё не подтверждены. MAP-ATLAS.md.

18 октября: в списке книг показан изучаемый навык (имя/иконка/переход),
фильтр kind=active/passive/unknown и поиск по имени/ID навыка. В meta.books
402 проверенных target из 403 книг: 113 active/289 passive/1 unknown;
при source=npcs — 7 active/105 passive. Генератор сохраняет provenance,
проверяет SHA входов и 149 файлов иконок. 12 целевых тестов/syntax/HTTP
прошли; все targets/картинки сверены с независимым skill index. Подробности
и границы — CATALOG-STRUCTURE.md. Новая визуальная проверка не выполнена.

18 октября: в книгах добавлен фильтр «Источник получения»: все книги,
в наградах монстров, без записей наград монстров. Использует прежние
item-origins/npc_id (NpcReward), параметр source в URL/возврате/догрузке.
112 из 403 книг имеют такие записи; это не подтверждение серверной выдачи.
6 тестов модели и JS syntax прошли. CATALOG-STRUCTURE.md.

18 октября: каталог книг (`maps/loot/books.html`) оформлен горизонтальными
карточками в стиле каталога навыков: иконка с клиентским фоном редкости,
название, редкость/ID, класс и компактный список монстров-источников.
Фильтры, сортировка по редкости, URL, ссылки карты и догрузка сохранены.
Только верстка списка; связи и данные предметов не менялись.

18 октября: у навыка без `ImgBg` каталог подбирает наиболее частую точную
текстуру ImgBg среди записей с тем же исходным `Skill.Rarity`; собственный фон
всегда имеет приоритет. Это визуальное сходство по просьбе пользователя, не
утверждение о клиентском назначении fallback. Подбор строится только для
рангов с хотя бы одним точным ресурсом ImgBg; наиболее частый источник
выбирается детерминированно. HTTP/deployed проверены.

18 октября: у навыков без `ImgBg` добавлена приглушённая цветная основа по
`Skill.Rarity` (1–5); найденная клиентская текстура остаётся поверх неё.
Обновлён CSS cache key. Проверены сборка каталога, HTTP и совпадение deployed.

18 октября: подложки навыков из точного поля клиента `Skill.ImgBg` применяются
в каталоге по всей площади иконки; отдельные CSS-цвета по `Skill.Rarity` остаются
только акцентом рамки. В skill index 288/3447 записей имеют единственный ресурс
ImgBg; неоднозначные не выбираются. Обновлён cache key страницы. Ресурсные пути,
SHA и происхождение остаются в skill-npcs.json. Syntax/HTTP/deployed сверены.

18 октября: в навыках сортировка по исходному Skill. Rarity0–5: default
сначала выше, внутри ранга имя/ID. Также ниже→выше и алфавит; unknown/
служебные коды в конце, sort сохраняется в URL.5 Node/syntax/HTTP прошли.

18 октября: 145 навыков с точной датированной заглушкой имени Registered
скрыты по умолчанию; отдельный relation=service для служебных записей.
Название со смыслом/отсутствие картинки не считаются заглушкой. NPC остаются
под отдельным фильтром, прямые URL сохранены. 4 Node/syntax/HTTP проверены.

18 октября: навыки с all_npc_ids видны в каталоге только при relation=npcs,
по просьбе пользователя; поиск/класс сами их не включают. Прямые карточки
и ссылки NPC сохранены. Новый skills-catalog-model.js в штатной сборке,
3 Node tests/syntax/HTTP/deployed прошли. CATALOG-STRUCTURE.md.

18 октября: список навыков оформлен горизонтальными карточками по примерам:
иконка 84px, имя/класс, тип и компактные счётчики связей. На узком экране 68px.
Новый build-skill-catalog-meta.py (вызов из build-catalog-pages.py) сохраняет
3446 строк SkillCSV1505/происхождение и явные [Active]/[Passive] из описаний
книг с проверенными targets: 97active/289passive/3060unknown. Skill. Type не
интерпретирован по аналогии с enum. Все SHA/3446 строк, 2 Node class tests,
syntax/HTTP/deployed проверены; visual QA остаётся. CATALOG-STRUCTURE.md.

18 октября: количество результата крафта поднято под названием в левую
часть заголовка; равный Min/Max показан одним числом. Пустой промежуток
из-за высоты валютного блока убран. Syntax/HTTP/deployed проверены.

18 октября: валютная стоимость крафта перенесена вправо в заголовок
рецепта по разметке пользователя; сетка содержит предметные материалы.
Разделение по подтверждённому CostType1; количества прежние. Syntax/
HTTP/deployed проверены; NPC-LOOT.md.

18 октября: материалы крафта разложены рядом адаптивной сеткой карточек
с иконкой/названием/количеством; на узком экране переносятся. Состав и
количества прежние. Syntax/HTTP/deployed проверены; NPC-LOOT.md.

18 октября: «Из чего крафтится» открыто сразу после наград монстров:
все рецепты/исходы, материалы с иконками/количеством/заточкой и валюта.
Условия и JSON закрыты. Для 13073000 проверен рецепт 3050006:5 предметных
материалов и Gold450000; успех/большой успех раздельно. Связи прежние,
syntax/HTTP/deployed проверены. NPC-LOOT.md.

18 октября: по явному уточнению блок «В наградах монстров» показывает
всех NPC сразу, включая список книг; лимиты 3/8 и «Ещё монстры» убраны.
JSON остаётся свёрнутым. Syntax/HTTP/deployed проверены; NPC-LOOT.md.

18 октября: карточка предмета уплотнена по скриншоту 13073000: награды
монстров в отдельном блоке сразу под характеристиками, сетка имён/уровней,
одна ссылка карты в заголовке; JSON/оговорки закрыты. Статы 30px вместо
42px+унаследованной высоты кнопки, меньше отступы панелей. 5 Node/syntax/
HTTP/deployed проверены; visual QA остаётся. NPC-LOOT.md.

18 октября: источники NPC теперь видны сразу у всех предметов, не только
книг: первые 8 записей, остальные под «Ещё монстры», JSON отдельно закрыт.
Пользователь подтвердил, что прежний список был доступен при раскрытии.
Для 13073000 проверены 13 цепочек/13NPC; новые игровые связи не добавлялись.
Syntax/5 Node tests/HTTP/deployed проверены; NPC-LOOT.md.

18 октября: исправлен переход предмет→источники: при личных NpcReward
используется world.html?item=ID (все миры), вместо только Nocturne.
В списке книг видны до 3NPC с уровнем/ссылкой, остальные раскрываются;
в карточке книги список перед характеристиками. Для 22023005 проверены
Arto400004/Eligo400006/Lussem400008, все 3 размещения в 20301. SHA источников,
5 Node tests/syntax/HTTP проверены; визуальная проверка остаётся. NPC-LOOT.md.

18 октября: страница monsters.html получила компактные иконки наград 72px
(56px на мобильном), hover/focus сведения и закрытый JSON. Опыт/валюты
показаны под основными параметрами раздельно по NPC/областям; заголовок
«Ур. N Имя». Для 400006 подтверждены 59 предметов/GehennaPoint220, других
валют/опыта в карточке нет. Syntax/HTTP/deployed и тесты каталога проверены;
визуальная проверка остаётся. Подробности — NPC-LOOT.md.

18 октября: заголовок карточки NPC теперь «Ур. N Название», значение из
существующего p.level; повтор уровня под заголовком убран. Syntax/HTTP
и совпадение развёрнутого JS проверены. MAP-ATLAS.md.

18 октября: JSON цепочек в подсказке предмета свёрнут по умолчанию,
раскрывается кликом «Исходные данные · JSON»; переход фокуса внутрь
подсказки сохраняет её. JS syntax/HTTP/deployed сверены. MAP-ATLAS.md.

18 октября: по уточнению пользователя награды снова видны сразу: компактная
сетка иконок/фонов редкости, hover/focus подсказки с количеством и цепочками.
Опыт/золото/алмазы возвращены под HP/атаку/защиту, с раздельными подписями
NPC/область; EventDiamond подписан «Ивент-алмазы». Условия/источники остаются
в подсказках и закрытом разделе. 30 Node tests/syntax/HTTP/SHA прошли;
визуальная проверка остаётся. MAP-ATLAS.md, «Иконки наград и валюты».

18 октября: карточка NPC на карте уплотнена по скриншоту пользователя.
Дроп NPC/награды области закрыты по умолчанию, заголовки показывают число
предметов; источники и ограничения собраны отдельно, условия размещения
сворачиваются. Разделение NpcReward/AreaReward и исходные данные сохранены.
30 Node tests/syntax/HTTP/SHA прошли; новая визуальная проверка не выполнена.
Подробности — MAP-ATLAS.md, раздел «Компактная карточка NPC».

18 октября: непроцентный formatter switch315…465 разобран и проверен 2307
native cases. 14 special rows: 315 вес×0.01,453suppression×0.001,454–465CC
по редкости×0.1, без суффикса%. IsPercentage имеет приоритет. Все 185routes:
76percent/14scaled/95unscaled. 16 tests/syntax/HTTP/SHA прошли; карточки
дополнены. build-stat-format-routes.py → build-catalog-pages.py. Это
отображение, не формулы боя/Stat→Stat. Источники и границы — ATTRIBUTES.md.

18 октября: восстановлена процентная display branch145dda3a0:
IsPercentage record+0x8c → int32→float32×0.01 → integer/%.2f →%.
10 anchors/11 fragments, 1665 native cases с явным fmodf shim; 15 tests/HTTP/SHA
прошли. 76 процентных карточек объясняют 100→1%, 150→1,50%. Это перевод
отображения, не формула шанса/урона; packet raw64bit не переинтерпретируется.
build-stat-format-evidence.py перед build-catalog-pages.py; ATTRIBUTES.md.

18 октября: native PktStat/Category/Extra/Detail schemas связаны vtables,
17 anchors/16 fragments. В формате есть key/value и category/value, значения
raw64bit; имена категорий/runtime consumer ещё не найдены. 1392 roundtrips+
8failure cases=2792 native calls с primitive IO stubs; 14 tests/HTTP/SHA прошли.
Карточка содержит source-fold без выдуманных категорий/значений. Новый шаг
build-stat-packet-evidence.py перед build-catalog-pages.py. Формулы Stat→Stat
этим не доказаны; полный порядок/источники/границы — ATTRIBUTES.md.

18 октября: контекст weight score уточнён: caller145db6fb0 сравнивает candidate
и peer предмет из слота Item. EquipmentType; signed greater, equal=false,
no-peer=true только после gates. 16 anchors/16 fragments, 320 native comparator
и 320UI selector cases со stub dependencies; 13 tests/HTTP/SHA прошли.
UIwidget+0xc68 имя ещё не установлено, общая мощь не доказана. Карточка
теперь «Вес параметра при сравнении предметов». Порядок:
build-attribute-score-context.py → build-catalog-pages.py. ATTRIBUTES.md.

18 октября: найдена native численная зацепка использования CombatPowerWeight:
загрузчик 145af0430 пишет word record+0x8a, потребитель 145d2da30 использует
3float32 multiply/floor/int32-add blocks. 861 cases/2583 native executions,
12 tests включая 18 replays/857JS-native comparisons прошли. В карточках
локальный калькулятор вклада, 171weight/14blank. Это не полная боевая мощь
и не Stat→Stat формула; контекст owner/caller остаётся. Новый порядок:
build-attribute-weight-evidence.py → build-catalog-pages.py; SHA/sources/
limitations — ATTRIBUTES.md. Native code/CSV проверяются перед сборкой.

18 октября: StatType185 строк сопоставлен с EStat: 181 конкретная привязка,
4sentinel Max207 (Synergy/CombatPower/PetAdventure); карточки различают их.
Точные enum strings повторно сверены с EXE. Граф 13 описательных связей:
добавлены противодействия CRIT chance/CRIT damage/PvP Drain. 9 tests,
syntax/HTTP/deployed/SHA прошли. Native string discovery воспроизводится
study-attribute-native.py; формулы/коэффициенты не найдены этим ограниченным
поиском, native расчёт не заявлен. Источники и границы — ATTRIBUTES.md.

18 октября: нажатие характеристики открывает ?stat=ID с деревом связей:
входящие/выходящие усиления и отдельные взаимодействия противника. 10 связей
(8modifier/2opposed) по точным CSV486 descriptions с provenance и fail-on-change,
formula=null, native/runtime не заявлены. attribute-relations.py вызывается
build-attributes.py; 8 tests/syntax/HTTP/data SHA прошли. Это первая часть
графа, native формулы остаются. Источники/границы — ATTRIBUTES.md.

18 октября: ID характеристики перенесён сразу после названия, отдельная нижняя строка убрана. Syntax/HTTP/deployed проверены; данные прежние. ATTRIBUTES.md.

18 октября: флаги характеристик компактно показаны возле имени: `%` для
IsPercentage=1, перечёркнутый глаз для InvisibleStat=1; title/aria-label.
Условия/данные прежние, syntax/HTTP/deployed сверены. ATTRIBUTES.md.

18 октября: характеристики уплотнены: название и две SVG-кнопки (коллекции/
источник) в строке, описание hover/focus, поля раскрываются кнопкой.
Данные/связи прежние, syntax/HTTP/deployed сверены. ATTRIBUTES.md.

18 октября: добавлена вкладка «Характеристики», maps/attributes/index.html.
185OperationType definitions, 4 клиентских вкладки и 49 без группы; поиск,
процентный фильтр, описания/исходные поля и ссылки на коллекции по bonus.
Native2diagnostics/enum strings/CSV SHA проверены; группировка 1427→1428→485,
локализация 486. build-catalog-pages.py вызывает build-attributes.py.
5 целевых tests/syntax/HTTP/deployed прошли, визуальная проверка остаётся;
значения аккаунта/формулы мощности не имитируются. Подробности/источники:
[ATTRIBUTES.md](../resource-tools/vampir/ATTRIBUTES.md).

18 октября: пользователь уточнил порядок коллекций — обычные, затем выше
качеством. Новый default sort=quality: Rarity0→5, затем 100/101/unknown,
внутри качества DisplayOrder; source/rank/name сохранены. Это редкость
коллекции, не рейтинг предметов и не подтверждённый native comparator.
8 Node tests/syntax/HTTP/deployed прошли; COLLECTIONS.md.

18 октября: порядок коллекций по умолчанию изменён на категории и числовой
CSV53.DisplayOrder; равные значения сохраняют последовательность CSV.
Редкость/алфавит доступны отдельными режимами с сохранением sort в URL.
Полный native-компаратор игры не заявляется: DisplayOrder имеет повторы,
runtime приоритеты неизвестны. 7 Node/syntax/HTTP/deployed проверки;
источники и ограничения — COLLECTIONS.md.

18 октября: по пользовательскому примеру коллекции оформлены широкими
строками: имя/бонусы слева, иконки с заточкой справа; hover/focus подсказки
предметов, адаптивный перенос. Прогресс аккаунта не имитируется, данные и
связи не менялись. Пересборка build-catalog-pages.py, syntax/HTTP/deployed
проверки; визуальная проверка остаётся незавершённой. COLLECTIONS.md.

18 октября: по просьбе пользователя навигационное исследование отложено,
добавлен раздел «Коллекции» в общем меню: maps/collections/index.html.
4079 групп/6766 требований/1010 предметов/73 типа бонусов; поиск, категория,
редкость, бонус, сортировка, догрузка 60, карточка ?collection=ID.
Состав показывает иконки/фон редкости, Count/EnchantLevel и полную карточку
предмета; описание бонуса — hover/focus. Native diagnostics4 связей сверены
с EXE, CSV SHA/строки и неизвестные runtime условия сохранены в manifest.
build-catalog-pages.py вызывает build-collections.py.10 целевых tests,
JS syntax/HTTP/deployed/icon проверки прошли; визуальная проверка остаётся
незавершённой после прежнего отказа browser URL policy. Источники и порядок:
[COLLECTIONS.md](../resource-tools/vampir/COLLECTIONS.md).

18 октября: native применение query-filter overrides проверено 33 cases/12 replays,
включая 7cooked variants. Travel override clamp>=1, entering>=0, excluded
пропускает прочие overrides записи; order сохранён. Карточка показывает
MainRoad0,5→1 при применении. 26 anchors/15 fragments/10leaves связывают handler/
vtables/setters и copy из owner+0x400; active filter selection ещё не определён.
recast-filter-apply-emulator.py/build-recast-filter-apply-evidence.py →
audit-recast-filter-apply.py → build-world-map.py.50 recast Python+8 Node,
all62scene/deployed audit прошли. Начальное состояние эмуляции — свежий native
constructor, реальные base arrays могут иметь другие SupportedArea/runtime
значения. Подробности/SHA — [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md).

18 октября: извлечены 7 пакетов/4Blueprint query filters Default/ShortPath/Combat/
ExcludeHiddenPath, 15explicit area records. Native48 anchors/23 fragments закрепляют
схемы, стоимость в constructor и IDs10Obstacle/11HiddenPath/12MainRoad/
13Forbidden/63Default. Дубли CDO совпадают. 14 исходных частей повторно извлечены,
25navigation Python+7 Node/scene/deployed audit прошли. В карточке перехода
«Фильтры из ресурсов клиента»: значения/override/excluded flags, без объявления
активного фильтра. build-navigation-filter-code.py → build-navigation-filter-resources.py →
decode-navigation-filter-resources.py → audit-navigation-filter-resources.py →
build-world-map.py. Связь выбранного Blueprint с owner+0x400/runtime и реальные
маршруты ещё не подтверждены; [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md).

18 октября: найдена native цепочка расчёта area priorities: два массива 64double →
сумма → native sort → ordinal ranks0..63 →64byte nav+0x94.22 anchors/14 fragments,
72 native cases/50heap fallbacks, независимый audit/12 replays прошли. Даже при
равных суммах ранги разные; подобранный 11→63→10 ещё не доказывает actual costs.
Новые recast-area-priority-emulator.py/build-recast-area-priority-evidence.py →
audit-recast-area-priority.py → build-world-map.py.46 recast Python+7 Node,
scene/deployed SHA проверены. Карточка содержит ссылку на источник priorities.
Active filter arrays/owner+0x400 binding остаются неизвестны; MAP-ATLAS.md.

18 октября: выполнены native start/end attachment и link creation на локальных
копиях тайлов. 7 наборов приоритетов/434 пары; при сценарии 11→63→10 обе связи 61
перехода точно воспроизводят baked vertices, 9432 не создаёт связей во всех 7.
Это подобранный исследовательский сценарий, не восстановленные runtime settings.
BV study: 8 режимов/1096 native queries. Новые инструменты recast-bv-nearest-emulator.py,
recast-attachment-emulator.py, build-recast-bv-nearest-study.py →
build-recast-attachment-study.py → audit-recast-attachment-study.py →
build-world-map.py → audit-recast-special-links.py. All434graph audit/28 native
replays, 42 recast+8world-map Python/7 Node и deployed data прошли. Карточка:
«Воспроизведение присоединения · предварительно». Runtime/active coverage,
clusters и реальные маршруты остаются; визуальная проверка не завершена.
Подробные источники/SHA/порядок — MAP-ATLAS.md.

Запуск локального сервера: дважды нажать `Start-Vampir-Map.cmd` в корне проекта.
Путь ресурсов, остановка и запуск из PowerShell — [MAP-SERVER.md](MAP-SERVER.md).
Скрипт `start-map-server.ps1` использует Python 3, слушает только 127.0.0.1:17946
и повторно использует уже работающий сервер; данные не пересобирает.

18 октября: отдельный предварительный слой «Особые переходы» показывает 62 записи,
выбор из списка и ссылки `?navLink=special-…`. Native42 anchors/10 fragments
закрепляют layout80 байт; исходные и baked endpoints хранятся отдельно.
39 пространственных совпадений с lift preview не считаются привязкой, все 62ID=0.
build-recast-special-code.py → decode-recast-special-links.py → build-world-map.py →
audit-recast-special-links.py.95 целевых tests и независимая сверка всех 62 записей,
SHA сцены/overlay/4deployedfiles прошли. Визуальная проверка этого этапа
не завершена: доступ браузерного инструмента отклонён URL policy.
Направление, runtime attachment/условия и проходимость ещё неизвестны.
Источники, SHA и порядок — MAP-ATLAS.md.

18 октября: флаги особых переходов проверены 27 native anchors/32 fragments,
11008 изолированных native cases (packing и 3query gates). У всех 62flag0xC0:
bit0x80 порождает metadata bit0x20 и обходит проверенное ограничение направления
в обоих направлениях. Карточка показывает этот ограниченный вывод и proof link;
полная проходимость/attachment/остальные фильтры не подтверждены. Новый порядок:
build-recast-special-direction-evidence.py → build-world-map.py → audit-recast-special-links.py.
35 recast Python+5overlay Node tests, all62 audit/scene/deployed SHA прошли.
Визуальная проверка остаётся незавершённой после отказа URL policy. MAP-ATLAS.md.

18 октября: native nearest-surface fallback проверен на 6synthetic cases и всех 62
переходах (136real queries). Для A61radius candidates/60baked matches, для B62/60;
3 перехода расходятся с baked, все связи остаются предварительными. В карточке
раскрытие «Предварительная проверка поверхности». Новый порядок:
build-recast-nearest-candidates.py → audit-recast-nearest-candidates.py →
build-world-map.py → audit-recast-special-links.py.38 recast Python+6overlay Node,
all136 audit/16 native replays/scene/deployed checks прошли. BV/preferred-priority
поиск, полный attachment и runtime остаются; подробности MAP-ATLAS.md.

18 октября: world/nav basis подтверждён 29 anchors/69 native cases, включая
signed zero: world→nav[-X, Z,-Y], inverse[-X,-Z, Y]. Новый отключённый по умолчанию
слой «Навигационная сетка · исследование» показывает 18430 ячеек/101090 полигонов
на карте, загружается лениво с SHA, все высоты вместе. На общем виде ячейки,
при zoom полигоны. build-recast-coordinate-evidence.py→build-world-map.py
(внутри build-recast-map-overlay.py).89 целевых tests, полный projection audit
и браузер 233%/14413%/1375% проверены. Special62 не рисуются; runtime/path остаются
непроверенными. MAP-ATLAS.md: источники/SHA/порядок/снимок.

18 октября: на всех 18430 уникальных тайлах выполнен native portal matcher:
106595 вызовов/125718 направленных переходов, все взаимны. Detail height helper
вызван 188 раз/triangle332. recast-portal-emulator.py исполняет клиентские
математические функции без OS, пропускает только cookie check. Порог 35 остаётся
явной гипотезой. build-recast-portal-evidence.py (10 случаев+real seam),
build-recast-external-graph.py --height 35, audit-recast-external-graph.py:
45Python tests/полный geometry audit/32 native replay прошли. Это candidate union,
не проверенный runtime graph/маршрут; источники/SHA/порядок — MAP-ATLAS.md.

18 октября: 57 native anchors/26 fragments закрепляют external-edge matcher,
detail-triangle height sampling и nav-parameter stream. Новый
build-recast-portal-code.py→decode-recast-nav-params.py находит в Nocturne
кандидат параметров (height 35); общий mesh имеет uint32 length, chunks uint64.
build-recast-grid-inventory.py: 18430 уникальных grid/layer из 19098,668 повторов
побайтно одинаковы, конфликтов 0.41 целевой Python test и независимая сверка
всех grid identities прошли. Это ещё не active mesh/cross-tile graph;
привязки properties/версий и полное соединение остаются. Подробности MAP-ATLAS.md.

18 октября: native geometry layout закреплён 47 anchors: 88 байт header,
24 байта/vertex (3double), 32 байта/polygon, индексы и internal neighbor-1.
build-recast-geometry-code.py→decode-recast-geometry.py разобрали 34 пакета:
214851 вершина/104726 полигонов/228354 направленных внутренних связей, все
общие рёбра взаимны. 34 целевых Python tests и полная сверка JSON с буферами.
Остаются 108758high-bit рёбер, специальные связи, версии/координаты/маршруты;
гипотезы исходных буферов сохранены. Подробности — MAP-ATLAS.md.

18 октября: extract-recast-tile-buffers.py восстановил кандидатные буферы всех
19098 тайлов/34 экспортов (27249848 байт) в изолированной Unicorn2.1.4 эмуляции.
При явных гипотезах offset 14/custom-version 97 все размеры совпали, каждый
экспорт прочитан до конца; отдельный validate-recast-tile-buffers.py проверил
все диапазоны/SHA.28 целевых Python tests. Это ещё не подтверждение версии
архива, полигонов или пути. Отчёт/порядок/ограничения — MAP-ATLAS.md.

18 октября: закреплена цепочка класса RecastNavMeshDataChunk→vtable→Serialize→
tile/cache codecs: 50 опорных инструкций и фрагменты EXE с SHA. Новый инструмент
build-recast-serialization-code.py проверяет 34 экспорта; в каждом один кандидат
заголовка version 26/offset 14, суммарный tile_count19098. Это ещё не декодер:
граница UObject properties и значение custom version не доказаны, полигоны/
маршруты не прочитаны. Размер восстановленного тайла нельзя использовать как
длину сериализованных байтов. Источники/порядок/проверки — MAP-ATLAS.md.

18 октября: найдена полезная нагрузка навигации в 34generated-пакетах Nocturne:
34RecastNavMeshDataChunk/17348530 байт, пары/диапазоны/цепочки владельцев проверены.
До этого search-navigation-chunk-headers.py проверил 147428UAsset headers в 106PAK.
build-navigation-generated-chunks.py сохраняет asset/body/exports и SHA.
37Python tests/все 34 пакета/214hits/SHA и браузерный статус проверены. Граф пока
не разобран, связь с 20WPRefNav entries и активная версия не подтверждены.
Сборка search-navigation-chunk-headers.py→build-navigation-generated-chunks.py→
build-world-map.py; подробности — MAP-ATLAS.md.

18 октября: подтверждена геометрия повёрнутых AreaBox — центр Min/Max,
положительный XY-поворот, float32-градусы. 11728 точек/1466 случаев совпали с
изолированной эмуляцией функции клиента. В Nocturne603 контура (322 повёрнутых),
175Area-точек/24074 записи; 2 обратных MinMax сохранены отдельно. Новые инструменты:
build-area-box-code.py→build-area-transform-evidence.py→build-world-map.py.
46 целевых тестов/SHA/полнота и браузер 945% проверены. Проходимость не доказана.
Подробности/кеш и --fresh — MAP-ATLAS.md.

18 октября: обратные ссылки материалов крафта —156 предметов/1369 рецептных
связей. Блок «Где используется в крафте» показывает количества/заточку,
результаты с картинками/редкостью и переход к раскрытому рецепту через recipe=ID.
Порции 40/автодогрузка.29Python+10 Node, 156 SHA/полнота связей/5deployedfiles и
браузерные Page11/Trinity265 (40→80) проверены. Новых native joins нет;
источники и порядок — NPC-LOOT.md/CATALOG-STRUCTURE.md.

18 октября: подтверждена связь ItemCraft. Id→ItemCraftMaterial. GroupId и
CostType=Item/CostParam→Item. Id. В рецептах 441 предмета показаны материалы,
картинки, количество и исходная заточка. 563 рецепта/1733 строки, 38 строк без рецепта
сохранены отдельно. Новый build-craft-material-binding.py запускать перед
build-npc-loot.py→build-world-map.py.64 native+17data anchors, 37 целевых тестов,
861 путь/403 книги и браузерные 21011003/11015007 проверены. Подробнее NPC-LOOT.md.

18 октября: в каталоге предметов добавлены фильтры EffectType, группы пассива
и ссылок на ограничения; 56 обычных Effect, 39 пассивных предметов, 42 со ссылками
LimitGroupId/ItemUseLimitId. Тип 20 не приравнивается к None. URL/возврат/
сортировка/догрузка сохранены.20Python+6 Node, SHA/развёрнутые ассеты и браузер
проверены. Новый native join не заявлен; подробности NPC-LOOT.md/CATALOG-STRUCTURE.md.

18 октября: обратные ссылки навыков расширены на все 5285NPC/миры:
1344 навыка с NPC, 9610 связей. В карточке список с уровнем/мирами/переходом
к NPC и догрузкой 60; кнопка карты считает отдельно Nocturne.20Python+34 Node,
3447skill SHA/полнота связей и браузер Sweep/50401 проверены.
Подробности и схема all_npc_ids/npc_ids — CATALOG-STRUCTURE.md, NPC-LOOT.md.

18 октября: портреты NPC добавлены в каталог, полную карточку и карту через
Npc. Img и точную NpcProfile. NpcInfoId→Npc. Id. Изображения есть у 86NPC
(55PNG), у 40 указанный ресурс не найден, у 5159 явная ссылка отсутствует.
Фильтр «Изображения» учитывает только найденные файлы. 53 целевых теста,
5285detail SHA/55PNG SHA и браузерный переход Larva карта→карточка проверены.
Происхождение/границы и порядок сборки — NPC-LOOT.md, CATALOG-STRUCTURE.md.

18 октября: меню «Монстры» открывает отдельный atlas/monsters.html
с поиском/уровнями/мирами/личными предметами и страницей ?npc=ID.
Все 5285NPC/61307 размещений собраны; 652NPC имеют личные предметы.
MonsterCard общий для карты и страницы, область не смешивается с личным
дропом.32Python+35 Node, 5285detail SHA и браузерные случаи проверены.
Порядок сборки/границы/источники — CATALOG-STRUCTURE.md и NPC-LOOT.md.

18 октября: книги и навыки получили фильтр/подпись класса из явных полей
Item. ClassInfoId и Skill. ClassType; неизвестное не считается All. 375 книг
с конкретным классом, 27 общих, 1unknown. Догрузка списков по прокрутке
добавляет 60 карточек; NPC показаны с уровнем, сортировкой/диапазоном.
24Python+32 Node и браузерные проверки прошли. build-catalog-classes.py
включён в build-catalog-pages.py; источники/границы — CATALOG-STRUCTURE.md.

18 октября: добавлены отдельные каталоги maps/atlas/skills.html и
maps/loot/items.html,books.html с поиском/фильтрами/полными карточками
и общим меню. Монстры пока используют прежний просмотр NPC/дропа.
SkillCard общий для карты и каталога, ItemDetails переиспользуется.
Сборка loot→world-map вызывает build-catalog-pages.py; 68 тестов моделей/
данных и проверка переходов в браузере пройдены. Порядок, URL и границы —
[CATALOG-STRUCTURE.md](../resource-tools/vampir/CATALOG-STRUCTURE.md).

18 октября: исследована структура отдельных каталогов: 67 типов Item
в 5827 записях, 17CSV проверены по SHA. Предложены Карта/Монстры/Предметы/
Навыки/Развитие/Задания; книги и 1585SkillCard различаются.
План/источники/ограничения — [CATALOG-STRUCTURE.md](../resource-tools/vampir/CATALOG-STRUCTURE.md),
воспроизведение study-catalog-categories.py. Новые страницы пока не реализованы.

18 октября: подписи областей размещаются с учётом полного фона, значков,
карточки выбора и краёв canvas. Четыре направления/смещения до 120px,
выбранная область первая, линии к отнесённым названиям. Все записи/поиск
сохранены, число показанных подписей видно в легенде. 30 Node tests/syntax
прошли; source/deployed JS совпали. В браузере проверены общий 94%
(59/172 названий) и 240% (49/120 в окне). Подробности — MAP-ATLAS.md.

18 октября: исправлена навигация карточек навыков после живой проверки браузера.
?skill=ID открывает карточку без фильтра NPC; явный фильтр сохраняется
в skillNpc=1. Добавлены возврат к карте, подсказка управления, компактный
список предметов, свёрнутые параметры и безопасное выделение SkillEffect.
Проверены Frenzy321001 и NPC-навык 50250 (3NPC/147 размещений), 17Python+27 Node
тестов прошли. Новых связей данных нет. Подробности — NPC-LOOT.md.

18 октября: карточки 19 пассивных навыков получили обратные ссылки на 39
предметов через ранее доказанную Item. PassiveSkillGroupId→SkillSet→Skill.
Показаны картинки/редкость/свойства/источники, сортировка редкость→имя→ID,
все исходные SkillSet rows сохранены. Activation остаётся false. 19 целевых
Python tests/syntax прошли; 3447detail SHA/полнота 39sources/deployed JS
проверены. Сборка build-world-map.py, подробности NPC-LOOT.md.

18 октября: карточки 1101 навыка получили уникальные иконки по точному
Skill. Img→texture basename из archive-image-latest.json.188 указанных Img
не найдены, 2157 пусты — картинка не выдумана. ImgBg применяется только при
уникальном совпадении; все 4 image-поля сохранены с provenance.298PNG SHA
и 3447 detail SHA проверены, 28Python+27 Node прошли. build-world-map.py
пересобран; порядок/источники/границы — NPC-LOOT.md. Browser visual check
не выполнен после ранее полученного URL policy отказа.

18 октября: проверены native MpMin/MpMax level getters (90 anchors/4literals/2slots).
Сравнение уровня показывает исходные MP и их источник, без формулы роста.
Все 7 ChangeMpMin/Max пусты; база сохраняется. build-skill-level-mp-code.py
запускать перед build-world-map.py.25Python+27 Node прошли. Сервер повторно
запущен на 127.0.0.1:17946; запросы atlas/skill JSON возвращают 200.
Подробности — NPC-LOOT.md. Визуальная проверка не заявлена.

18 октября: сравнение 7 SkillLevel-навыков дополнено Resource и StackCount
по проверенным getter ветвям. 6 непустых ChangeResource, 1 ChangeStackCount;
предыдущее сообщение о 5 ресурсах было неточным, actual CSV даёт 6.
build-skill-level-extra-code.py проверяет 30 instruction/4 literal/2slot anchors;
запускать перед build-world-map.py.23Python+25 Node прошли, 84deployed cases
совпали с Python. Actual runtime и смысл StackCount как зарядов не заявлены.
Документация/SHA/следующие поля MP — NPC-LOOT.md.

18 октября: 7 навыков получили сравнение перезарядки по выбранному уровню
на основе SkillLevel1511 и native skill-level-code.json. Первая включённая
строка заменяет Min/MaxCoolTime; 0/empty возвращает base, значения не складываются.
Другие Change-поля видны только исходными.20Python+23 Node прошли; 84 сравнения
deployed JS с проверенной Python-моделью совпали, 3447 detail SHA сверены.
build-world-map.py пересобран, источник/порядок/границы — NPC-LOOT.md.

18 октября: карточки навыков дополнены свёрнутым блоком «Класс и ограничения
применения»: исходные ClassType/UnusableRoomType/UsableWorldId, флаги боя,
контроля/автоиспользования и SkillLevelUpCostGroupId.1192 ClassType не пусты,
41 room-list, 2 world-list; группа цены повышения пуста у всех 3446.
Требования первого изучения/сочетание ограничений не выдуманы. Источник Skill
CSV1505 проверен по SHA, все 3447 detail SHA/исходные поля/deployed JS сверены,
JS syntax прошёл. build-world-map.py пересобран. Подробности — NPC-LOOT.md.

18 октября: ?skill=<ID> теперь открывает отдельную карточку навыка,
а также сохраняет фильтр NPC.3446 Skill definitions +1missing target201006;
403 книги связаны обратно с target ID, с картинками/редкостью/ссылками на
предмет и карту источников. Поиск включает все Skill, не только NPC Nocturne.
Общий renderSkillDetail используется и внутри NPC.25Python+21 Node прошли;
SHA3447 карточек/403 книги/изображения/source-deployed HTML-JS проверены.
Сборка build-world-map.py вызывает обновлённый build-monster-details.py;
перед ней нужен актуальный loot/item-details. Подробности — NPC-LOOT.md.
Визуальная проверка не выполнена после отказа browser URL policy.

18 октября: у 56 предметов EffectType=Effect появился свёрнутый блок
«Связь-кандидат» с совпавшей записью Effect, параметрами/операциями.
Связь EffectParams→Effect. Id и применение пока НЕ доказаны; false flags
и неизвестные единицы сохранены. Используется skill-effect-links.item_candidate,
сборка build-npc-loot.py→build-world-map.py.38Python+4 Node прошли;
56 candidates/source-deployed JS/atlas manifest проверены. Отвергнутые native
ветки и дальнейший поиск записаны в NPC-LOOT.md. Визуальная проверка недоступна.

18 октября: книги навыков связаны с Skill по проверенному native пути
SkillAcquire/EffectParams→_wtoi→Skill lookup в UI «уже изучен».403 target ID
подтверждены, 402 записи Skill найдены и получили ссылку/название; книга 22001005
указывает на отсутствующий Skill 201006. Успешное изучение не заявлено.
build-item-skill-binding.py: 38 native/12 data anchors и named import; запускать
перед build-npc-loot.py→build-world-map.py.30Python+4 Node прошли, manifest/JS
проверены. Подробности и ограничения — NPC-LOOT.md; browser check не выполнялся.

18 октября: обратные списки коробок сортируются по убыванию редкости,
внутри редкости — по видимому названию (Intl. Collator ru, numeric, base),
при совпадении — по ID. Сортировка всего списка выполняется перед порциями 40.
Проверен actual JS comparator на всех 1396 списках, syntax/deployed JS совпадают;
loot/atlas пересобраны. Новых связей данных нет.

18 октября: обратный список «В каких коробках указан предмет» получил
кликабельные 44px картинки с фоном редкости перед названием. 623 коробки
имеют уникальную картинку, 1 — два показанных кандидата, 20 — явный placeholder.
Все 625 файлов проверены, source/deployed JS/CSS совпадают, JS syntax прошёл.
Сортировка/порции 40/позиция блока внизу сохранены. Loot/atlas пересобраны.
Визуальная проверка не заявляется после отказа browser URL policy.

18 октября: подтверждена связь ItemBox. RewardGroupType→ERewardGroup через
loader+28→OnItemBoxUpdated→reflected enum property. Имена режимов теперь
показаны у всех 644 коробок; runtime выдачи и проценты не заявлены.
build-item-box-mode-binding.py проверяет 25 native/22 data anchors; запускать
после build-reward-group-semantics.py перед build-npc-loot.py→build-world-map.py.
28Python+4 Node прошли; SHA644 файлов/report/manifest и совпадение JS проверены.
Точная цепочка/источники/ограничения — NPC-LOOT.md. Browser check остаётся
недоступной по ранее полученному отказу URL policy.

18 октября: в наградах коробок показаны имена режимов каждой Reward-строки
и вложенной цепочки: Fixed/ClassFixed/Random/ClassRandom/RandomEach/Select/
ClassSelect. Новый build-reward-group-semantics.py проверяет 72 native anchors
и связь Reward. RewardGroup с ERewardGroup; запускать перед build-npc-loot.py.
ItemBox. RewardGroupType этим не разрешён, проценты остаются неизвестными.
27Python+4 Node прошли, SHA отчёта/644 коробок и deployed JS проверены;
карта/loot пересобраны. Browser URL policy по-прежнему не позволяет подтвердить
визуальный результат. Подробности и источники — NPC-LOOT.md.

18 октября: по запросу пользователя блок «В каких коробках указан предмет»
перенесён в конец карточки, после характеристик, пассивов, ограничений и
общих свойств. build-npc-loot.py/build-world-map.py пересобраны; JS syntax,
порядок секций и совпадение опубликованного локального JS проверены.
Локальный сервер слушает 127.0.0.1:17946. Визуальная проверка отклонена
политикой browser tool при получении вкладки; вид карточки не подтверждён.

18 октября: карточки предметов дополнены содержимым 644 коробок/10568 путей
наград и обратными источниками для 1396 предметов, включая 133 книги навыков.
ItemBox. ItemId/RewardGroupId/KeyItemInfoId/InstallGadgetInfoId проверены по
нативным reference diagnostics. Количество/Rate/цепочки сохраняются раздельно,
проценты и режим выбора не угаданы. Картинки/редкость/ссылки берутся из каталога.
`item-box-links.py` вызывается build-item-details.py→build-npc-loot.py;
после loot пересобрана большая карта.27Python+4 Node/JS syntax/SHA644 файлов прошли.
Браузер отключён в Work, новая карточка визуально не проверена. Примеры
?item=110000007 (коробка),?item=21001000 (книга с источником-коробкой).
Схема/источники/ограничения — NPC-LOOT.md. Эффекты/пассивы/runtime остаются частичными.

18 октября: `build-object-template-copy-code.py` закрепил 43 anchors завершающей
инициализации: выбор template/CDO, отдельное копирование subobjects,
raw-copy через VCRUNTIME140.dll!memcpy и альтернативный property callback.
Scene vtable+58 пустой,+50 ведёт к ActorComponent post-init и дальнейшим
вызовам. Отчёт `lift-blueprints/object-template-copy-code.json`; реальная
сборка прошла. Итоговый RelativeRotation ещё не доказан: runtime FProperty
и source CDO не подменяются compile-time descriptor. Слой остаётся 57 связей.
Источники/SHA/границы в MAP-ATLAS.md. Далее actual template values/callbacks.

18 октября: `build-object-zero-init-code.py` проверил 24 anchors цепочки
default-subobject→construct→allocate, импорт VCRUNTIME140.dll!memset и ветку
обнуления перед constructor. Reuse может обойти memset, после constructor
есть initializer finalization. Поэтому 6 omitted rotations не заменены 0;
слой остаётся 57 условных связей.59Python прошли. Отчёт
`lift-blueprints/object-zero-init-code.json`; источники/SHA в MAP-ATLAS.md.
Далее base callbacks/finalization1417c61a0. UI и граф не менялись.

18 октября: предварительный слой расширен до 57 связей из 63 размещений:
14 полностью явных, 43 с отдельно отмеченными native initial values.
`build-lift-initial-values.py` проверяет 26 anchors, 3 CDO/template цепочки,
native scale1×1×1 и единственный исходный PointLinks[(0,-50,0),(0,50,0)],
Direction0. Явные scale/empty arrays имеют приоритет; 6 omitted rotations
не заполнены. В карточках 1818/1821 показаны происхождение и условность расчёта.
55Python+21 Node/JS syntax/браузер прошли; снимок lift-inherited-checked.png.
Порядок: build-lift-initial-values.py после archetypes/point-links, затем
build-world-map.py. Итоговый frame/attachments/runtime по-прежнему не доказаны,
проходимость не назначена. Подробности/SHA в MAP-ATLAS.md.

18 октября: на карте появился выключенный по умолчанию слой «Лифты ·
предварительные расчёты»: 63 исходных размещения, 14 расчётных связей по полностью
явным location/rotation/scale/PointLinks, 49 без полного набора параметров.
Карточки показывают A/B/Z/разницу высот/направление и ограничения расчёта;
ссылка `?lift=1836`, выбор/нажатие/масштаб проверены в браузере, ошибок console нет.
Это условный расчёт без parent transform/смещения уровня/runtime, не навигационный
граф; world_transform_verified=false, walkable=null. Omitted defaults не заполнены.
Новый `build-lift-map-preview.py` вызывается из build-world-map.py после
rotation-evidence; отчёт maps/atlas/lift-preview.json.52Python+21 Node прошли.
Источники/SHA/порядок/снимок — MAP-ATLAS.md. Далее разрешение inherited defaults
и frame/attachment/активации; проходимость остаётся неподтверждённой.

18 октября: `lift-transform-math.py` реализует проверенные pitch/yaw/roll→XYZW
и scale→rotate→translate. `build-lift-rotation-evidence.py` сравнил формулу
с изолированной эмуляцией кода клиента: 195 вращений (включая 57 из размещений),
195 преобразований bounds; ошибки≤5.56e-16/1.17e-10. Начальные bounds клиента
[(0,0,-10),(0,0, 10)] учтены по константам EXE.49 целевых Python-тестов прошли.
Отчёт `lift-blueprints/rotation-evidence.json`, Unicorn2.1.4 закреплён с SHA
в requirements-native.txt. Это проверка математики на синтетических transforms;
effective CDO/attachments и реальные world endpoints ещё не разрешены.
Источники/SHA/границы в MAP-ATLAS.md.

18 октября: `build-component-transform-code.py` проверил 4 именованные native
привязки K2_GetComponentLocation/Rotation/Scale/ToWorld и 32 anchors обновления.
Блок SceneComponent+1d0 — мировое преобразование 96 bytes; позиция+1f0, масштаб+210.
Прослежена запись кэша в 143af8c00 и ветка без AttachParent. Отчёт
`lift-blueprints/component-transform-code.json`; реальная сборка прошла.
Формула вращения/точек, итоговые CDO defaults и runtime проходимость ещё не
доказаны. Источники и ограничения — MAP-ATLAS.md. UI этим шагом не менялся.

18 октября: `build-lift-archetypes.py` разрешил прямые template/outer ссылки
SceneComponent всех 63 лифтов через 6 Blueprint-шаблонов до native
Default__NnLift. Scene. Используется полный путь из таблицы, а не имя размещения:
3 экземпляра со старыми именами фактически имеют класс Type01. В 6 шаблонах нет
явных свойств Scene; нативные defaults/post-construction ещё не подставляются.
Отчёт `lift-blueprints/archetypes.json`; 42 целевых Python-проверки прошли.
Сборка после `build-lift-blueprints.py`/`build-lift-placements.py`.
Далее native CDO/настройки после создания и потребитель transform; мировые
переходы ещё не выведены. Подробности/SHA в MAP-ATLAS.md.
`build-lift-bounds-code.py` дополнительно закрепил 18 native anchors потребителя:
обе точки участвуют в min/max bounds, затем читается RootComponent+0x1d0.
Формула мировых endpoints и цикл обновления этих данных пока не подтверждены.

18 октября: `build-lift-point-links.py` разобрал 62 явных массива PointLinks
и подтвердил Actor. RootComponent = SceneRoot у всех 63 лифтов. Все 62 записи
имеют Direction=BothWays; это направление данных, доступность перехода не доказана.
Отчёт `lift-blueprints/point-links.json`, 38 целевых Python-проверок прошли.
Запускать после `build-lift-instance-settings.py`. `build-scene-native-defaults.py`
отдельно закрепляет начальные AttachParent=null и RelativeScale3D=1×1×1 по EXE;
они не подставляются экземплярам до проверки архетипов. Источники и SHA —
[MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md). Далее наследуемые значения,
attachment/runtime состояния и перевод точек; готовые маршруты ещё не заявлены.

18 октября: подтверждены явные SceneRoot/SmartLinkComp ссылки всех 63 экземпляров.
Новый build-lift-instance-settings.py читает native prefix с учётом собственных
полей Blueprint (2/1/0), 22 поля SplineActionParams проверены по EXE.
62 экземпляра с явными параметрами движения, 8 с bAutoActivation=false; omitted
не заменён default, единицы Duration/runtime ещё неизвестны. Отчёт
lift-blueprints/instance-settings.json, 34 Python-проверки прошли.
После build-lift-blueprints.py/build-lift-placements.py запускать
build-lift-instance-settings.py. Далее PointLinks/ActorRoot/attachment/активация;
мировые маршруты не подтверждены. Подробности в MAP-ATLAS.md.

18 октября:build-lift-blueprints.py подтвердил штатную цепочку создания Scene→
SceneRoot→Actor. RootComponent в конструкторе NnLift (7nativeanchors/2 descriptors).
Проверены 3 Blueprint пакета: BP_Lift_C→NnLift, Test/Type01→BP_Lift_C по SuperIndex/import.
Отчёт maps/navigation-study/lift-blueprints/index.json, 30Python проверок прошли.
Штатный корень доказан; переопределения экземпляров/архетипы/мировые точки ещё не разобраны.
Команда build-lift-blueprints.py; источники/SHA/границы — последний раздел MAP-ATLAS.md.

18 октября:build-lift-placements.py связал 63 parent лифтов с единственным
SceneComponent, проверил 13 native descriptors/pointers и порядок свойств.
Явные значения: 63location/57rotation/14scale/7absolute-locationtrue.
Omitted/default не подставлены; RootComponent/attachment/worldtransform ещё не доказаны.
Результат level/lift-placements.json с SHA/exports, 27Python проверок прошли.
Сборка build-navigation-level.py→build-lift-placements.py; дальше архетипы/корневая
привязка/условия лифта. Подробности 18 октября в MAP-ATLAS.md. Проходимость не подтверждена.

Навигационные связи: все 63 NnNavLinkCustomComponent уровня принадлежат
BP_Lift* (10+10test+43Type01). build-navigation-links.py подтверждает native
property-array и цепочку constructors, разбирает явные ID/relative endpoints:
49 стартов/40 концов/27 пар. 6 экспортов с неизвестными 14/22 сохранены частично;
8-byte suffix остальных 57 не получил придуманной семантики. Отчёт
maps/navigation-study/level/link-properties.json.23Python проверки прошли.
Это не пешие маршруты: parent transforms/направление/состояния/payload полигонов
остаются. Команды/доказательства/ограничения — последний раздел MAP-ATLAS.md.

Продолжение payload:search-navigation-payloads.py проверил 21494 записи/7PAK,
нашёл 22 RecastNavMesh-кандидата. build-navigation-level.py подтвердил пару
Nocturne header 1141/body1140 и 34206 exports, извлёк 49NavMeshBoundsVolume,
63NnNavLinkCustomComponent, NavSystem/Recast/RefLoader. 115 точных exports с SHA
в maps/navigation-study/level/. Полигоны/доступность связей ещё не разобраны.
inspect-ui.exports допускает явный max_exports=40000 для этого уровня,
default10000 сохранён.19Python тестов прошли. Команды/SHA/границы в MAP-ATLAS.md.

Продолжение: export-table проверка подтвердила header 886/body887 Nocturne_WPRefNav,
разобраны 20 записей ChunkRef/AssetFilePath/Bounds с полным учётом байтов и 6 native
property descriptors. Новый decode-navigation-header.py; report package/decoded_header
в navigation-study/index.json. Геометрия прохода/связность ещё не извлечены.
Сервер 17946 запущен, браузер снова доступен: карта/status20/alert/console проверены.
16Python+21 Node/SHA прошли. Сборка build-navigation-sources.py → build-world-map.py;
подробные SHA/смещения/границы — последний раздел MAP-ATLAS.md.

Продолжение навигации: build-navigation-sources.py закрепляет 15 native anchors,
пути RED/NavMesh/*_Nav.bin и RefNavMesh/*_WPRefNav, загрузчик и IsPathConnected.
В индексах 15 записей с RefNavMesh (14 заголовков+1 импорт уровня). Извлечён заголовок
Nocturne и соседняя запись-кандидат с 20 ExternalActors; пара/геометрия ещё не доказаны.
Отчёт maps/navigation-study/index.json; map-readiness проверяет его источники/SHA,
на карте ссылка и статус.13Python+21 Node/SHA прошли; браузер сейчас отключён.
Сборка build-navigation-sources.py → build-world-map.py. Маршруты и pivot AreaBox
по-прежнему неизвестны; подробности/offset/SHA в MAP-ATLAS.md.

По запросу «эффекты/ограничения + границы/маршруты»: подтверждён нативный
словарь 19 Item. EffectType, подписи выведены для 1774 предметов. 20 остаётся
fallback, EffectParams/runtime ещё не доказаны. Пассивы/ограничения не объявлены
завершёнными. Источники — новый раздел типов в NPC-LOOT.md.
Для карты build-area-box-code.py закрепил 15 anchors загрузки/Yaw, pivot неизвестен.
map-readiness.py: 1460 контуров, 5160 пар проверки маршрутов, 80 отсутствующих миров;
в извлечённой библиотеке 0 *_Nav.bin. На карте раскрываемый статус 322/1732 Nocturne.
Проходимость не подтверждена. 92 теста/базовая браузерная проверка прошли.
Сборка новых данных: build-item-effect-semantics.py → build-npc-loot.py →
build-area-box-code.py → build-world-map.py. Подробности/SHA в MAP-ATLAS.md.

Книги дополнены крафтом: 57 книг/107 путей результата по проверенным нативным
ссылкам ItemCraft→Reward. Карточка показывает рецепт, исход и количество;
в каталоге добавлен фильтр «Книги с рецептами крафта». Материалы, проценты,
доступность на сервере и EffectType4→Skill остаются неподтверждёнными.
89 тестов/SHA/браузер прошли. Сборка прежняя; источники — раздел крафта в NPC-LOOT.md.

Добавлен каталог книг навыков ?category=books: 403 книги по нативному Type31,
фильтр 112 книг с цепочками наград NPC, свойства и ссылки на источники карты.
402 EffectParams совпадают с Skill. Id; это явно помеченный кандидат, обработчик
изучения ещё не доказан. Книги и SkillCard разделены. 87 тестов прошли.
Сборка build-npc-loot.py; источники/SHA/ограничения — раздел книг в NPC-LOOT.md.

Поиск по навыку теперь показывает список уникальных NPC, а не повторяющиеся
размещения одного монстра. Группировка по точному npc_id после всех фильтров,
указаны число записей и миры. Нажатие открывает карточку и вписывает группу
размещений; переключатель «Каждое размещение отдельно» возвращает исходные точки.
Для 50250 видны 3 NPC: 30/30/87 размещений, всего 147.21 Node-проверка и браузер
прошли; источники/связи остаются прежними. Подробности — NPC-LOOT.md.

Добавлен обратный поиск «NPC с навыком»: карточка навыка→кнопка→все размещения,
поиск названия/ID в боковой панели, ссылка ?skill=ID и снятие фильтра.
`build-monster-details.py` строит maps/atlas/skill-npcs.json по подтверждённой
цепочке Npc→Battle→SkillIdList, manifest хранит SHA.395 навыков/2632 связей
Skill↔NPC; 50250→3NPC/147 размещений. 85 тестов/1785 SHA/браузер прошли.
SkillOperation. Param1→Effect остаётся кандидатом: имеющиеся native-проверки
подтверждают только SkillId→Skill, новой проверки параметра не найдено.
Источники/ограничения — раздел обратного поиска навыков в NPC-LOOT.md.

Время эффектов: `build-effect-time-code.py` подтверждает раздельные поля и
пути чтения Min/MaxDuration/Period: первичная загрузка strtoul→zero-extend32→64,
ModifyValue _atoi64→64. В текущих 2027 строках нет значений вне uint32;
Min/Max достигают 2500000000.413 Duration лежат вне Min/Max, приоритет полей
не доказан. В карте/предметах добавлены DurationGrowthRate и пояснение при
различии полей. Единицы остаются неизвестными; кандидат Skill→Effect не повышен.
23 anchors/2941 инструкция, 1785 SHA/75 кандидатов, 83 теста и браузер Frenzy
проверены. Источник/порядок сборки — раздел времени Effect в NPC-LOOT.md.

Проверка TotalTime закреплена в `build-skill-total-time-code.py` /
`code-clues/skill-total-time-code.json`: поле Skill+0xc8/getter slot0xb0
подтверждены, единица и runtime-потребитель остаются неизвестными.
Исправлена преждевременная подпись «Длительность»: теперь «TotalTime · исходное
значение» с пояснением при наведении. 5 anchors/2159 инструкций сверены с EXE,
отчёт воспроизводится; карточка 100171031 и console проверены браузером.
Подробности и отвергнутые связи — раздел TotalTime в NPC-LOOT.md.

Названия навыков дополнены полной корейской таблицей CSV1020: английское имя
приоритетно, иначе исходное KO; базовые атаки переведены на русский с явной
пометкой/оригиналом. 289 из 395 навыков имеют подпись, 106 остаются с ID.
У 100171031 теперь «Базовая атака 01/02». Sources/SHA/CSV record и происхождение
перевода сохранены; отчёт maps/atlas/skill-names-verification.json строится
build-monster-details.py.59Python тестов/1785 SHA и браузерная карточка прошли.
TotalTime по-прежнему не переведён: virtual slot0xb0 другого класса не доказательство
времени Skill. Подробности — новый раздел названий в NPC-LOOT.md.

Единицы базовой перезарядки подтверждены: `build-skill-tick-code.py` замыкает
UGameEngine::Tick/DeltaSeconds→диспетчер→счётчик cooldown. MinCoolTime/MaxCoolTime
хранятся в миллисекундах; карточки NPC теперь показывают их в секундах.
Это уточняет прежние записи об неизвестной единице именно этих двух полей.
Остальные длительности, итоговая перезарядка с runtime-модификаторами и сервер
не подтверждены. 33 anchors/1371 инструкция, 1785 файлов/SHA, 2632 вхождения
навыков, 81 тест и браузерная карточка 100171031 проверены. Сервер 17946 запущен.
Источник/порядок сборки/контракт UE5.5 —
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#перезарядка-в-секундах-граница-deltaseconds-17-октября).

Продолжение по уровневым заменам: `build-skill-level-code.py` подтверждает
SkillLevel1511→Skill getters, включительные MinLevel/MaxLevel и возврат к базе
при пустом/нулевом ChangeMinCoolTime/ChangeMaxCoolTime. Отчёт
`code-clues/skill-level-code.json`: 7 строк, 33 anchors, 4 теста граничных случаев.
Среди 395 навыков 1785 NPC текущего атласа затронутых нет. Поэтому карточки
монстров не изменены; единицы времени/runtime-поправки остаются открытыми.
Источники и следующий шаг — раздел SkillLevel в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#skilllevel-замены-перезарядки-по-уровню-17-октября).

Продолжение по времени навыков: `build-skill-time-code.py` закрепляет найденную
цепочку перезарядки до `WBP_SkillSummaryInfoT.TextSkillCoolTime`: вычисление,
float32 ×0,001, поправки персонажа, деление на число зарядов и формат `%.1f`.
Отчёт `code-clues/skill-time-code.json`: 32 native anchors, 2 константы,
leaf-переходы/vtable, SHA EXE и ресурс окна. Это доказательство масштаба
конкретного вычисленного значения; секунды для всех CSV-полей ещё не доказаны.
UI/данные карты не переводились в новые единицы. Границы и следующий шаг —
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#перезарядка-цепочка-вывода-в-клиенте-17-октября).

По новому запросу продолжена V13: [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md).
Собран единый атлас 254 миров, 154 настроек карт, 588 точек, 501 области,
61307 записей размещения NPC; связаны квестовые цели и порталы с исходными
стоимостью/условиями. 1422 PNG и 17 CSV проверены по SHA256. Просмотрщик:
`F:/PhoneExit Resources/Vampir/maps/atlas/index.html` через локальный HTTP.
Есть поиск, Nocturne, исходные текстуры и отдельные координатные слои;
запросы данных бота — `query-map-atlas.py`. Подробные источники/команды по ссылке.
9 тестов прошли; Android/навигация ещё не подтверждены, `navigation_ready=false`.
Локальный управляющий API17842 недоступен; текущую доступность Pixel 5 этим
не установили. Игровых нажатий, выпуска и установки новой версии не было.

### Скрин → большая карта и добыча NPC

Старый World Map сопоставлен с полной Nocturne10240×10240:463 согласованных
детали, 95% проверочных ошибок меньше 1.3px атласа. В просмотрщике добавлены
покрытие, совмещённый фрагмент и сравнение с ресурсом. Связь действует для
изображений этого снимка; worldXY/проходимость ещё не доказаны. Порядок в
[MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md).

Собран [NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md): 941 NPC с наградами,
793 разных предмета в прямых NPC-группах, 5827 предметов общего справочника,
3615 путей изображений, 41 дополнительно декодированный FloatRGBA-ресурс.
Для 790 NPC-предметов иконка однозначна, для 2 показаны несколько путей, для 1
не найдена. RewardRate/Rate сохранены, проценты не подтверждены.
Локальный просмотр maps/loot/index.html, запросы query-npc-loot.py.
5 тестов совмещения+6 тестов иконок прошли; прежние 9 тестов атласа повторно
прошли. Это данные/просмотрщики, без выпуска новой версии и действий на телефоне.

Продолжение 17.10: проверены native-загрузчики AreaReward/NpcReward/Reward и
PE-import **atoi**: rates загружаются как 32-битные поля, проценты этим не доказаны.
[Подробности](../resource-tools/vampir/NPC-LOOT.md#продолжение-загрузка-rates-и-обратный-поиск-17-октября).
Добавлен обратный индекс 793 предметов/35211 цепочек и раздел «Где указан»
в карточках. Все цепочки сверены, 9 тестов npc_loot прошли. Обновлённый UI визуально
не проверен: local browser use отключён в Work settings. Старый preview сохранён.

Следующее продолжение 17.10: для NpcReward/Reward прослежено создание записей
и vtable rate-callback: оба пустые ret0 (24 опорных инструкции/12 фрагментов).
Нормализации в них нет; внешний розыгрыш всё ещё не доказан. Добавлены 4227
исходных размещений 776NPC, раздел мест NPC в каталоге и CLI--item/--npc+--world.
Проверены 10 тестов npc_loot+5loot_locations, все 4227 строк по полям, реальный
Item 12013000/World10017→33NPC/39 размещений, JSsyntax. Новый UI визуально
не проверен. Подробности/команды в[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md).

Визуальная проверка 17.10 по запросу пользователя выполнена после включения
браузера: HTTP сервер 17946 перезапущен(был остановлен), атлас Nocturne/покрытие,
Item 12013000→175NPC/244 цепочки→NPC 200052→размещение World10017 и раздел rates
отображаются, ошибок страницы нет. Свежий preview-checked.png в maps/loot.
Это уточняет прежние записи «UI не проверен»; Android/шансы ещё не проверены.

### Nocturne: координаты и добыча на рельефе, 17.10

Продолжение V13: восстановлена статическая цепочка полей Map → масштаб → XY
значка. Для Map10/11 (36 миров/17488 исходных NPC-записей) формула Nocturne
проверена без подгонки по 7 областям значков одного старого кадра Krvna Nest.
`maps/atlas/projection.json`, native SHA/offset и воспроизводимый инструмент —
[MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md#мир-xy--nocturne-и-источники-предмета-17-октября).
В просмотрщике карта с точками, весь атлас, фильтр по предмету, ссылки из добычи
на конкретное размещение. Item 12013000→175 NPC/8 миров; World10017→39 записей/
3 координаты. Браузерная проверка и 33 целевых теста прошли. Свежий Android,
проходимость и навигация не проверены; `navigation_ready=false`. Проценты добычи
не установлены. Модуль/версия/APK не менялись.

### Большая карта всех контекстов, 17.10

Главный atlas/index.html теперь показывает всю Nocturne со всеми 36 мирами:
24071 отметка (17488NPC, 669 объектов с 40 порталами, 207 точек, 172 подписи областей,
5535 квестовых целей), 177 названий областей из CSV385. NPC→предметы/иконки,
портал→стоимость/прибытие, точка→квесты; общий поиск, фильтр предмета, контексты.
Прежние 254 мира сохранены в world.html. Источники: nocturne.json/manifest,
[MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md#единая-большая-nocturne-17-октября--все-контексты-и-связи).
Экспорт всей карты: nocturne-overview.png10240×10635. По замечанию пользователя
исправлена геометрия плиток при увеличении: atlas_rect — границы, не размеры.
Все 25 плиток попиксельно сверены, увеличение проверено на Krvna Nest. Прошли 51
тест и браузерная проверка. 322 повёрнутых/2 некорректных AreaBox и 5 областей
без позиции сохранены явно, без догадок. Свежий Android/маршруты/проценты всё
ещё не подтверждены. Новых игровых действий, версии и APK не было.

<a id="карточка-монстра-и-дроп1710"></a>

### Карточка монстра и дроп, 17.10

Выбор NPC на карте: дроп/иконки/количество/условные цепочки, HP/атака/защита,
опыт/золото/другие строки наград, размещения/радиусы/условия видимости.
`build-monster-details.py`: 1785 карточек, BattleGroupId→BattleCSV1545 подтверждён
native-диагностикой; 2NPC сохраняют несколько вариантов. 23329 цепочек проверены,
56 тестов. NPC 200052: HP24318, атака 1537,29 предметов, опыт 12040, Gold158–192.
Шансы и гарантированность наград не установлены. Предыдущая расширенная карточка
проверена браузером, финальная компактная —ещё нет: браузер отключён в Work settings.
Подробности:[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#карточка-выбранного-монстра-17-октября).

<a id="пустой-дроп-обычных-монстров1710"></a>

### Пустой дроп обычных монстров, 17.10

По скрину NPC 100201042: прямых NpcReward нет, но AreaInfoId100201040 совпадает
с AreaReward. GroupId, найдены 34 предмета/Exp27577/Gold165–202. Добавлен отдельный
раздел«Награды области» со статусом кандидата, не доказанного дропа за убийство.
Все 1785 карточек сверены, 57 тестов. Браузер отключён, визуальная проверка остаётся.
Подробности:[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md).

<a id="раздельные-источники-наград1710"></a>

### Раздельные источники наград, 17.10

Проверены 323AreaReward-группы→Area. Id и 941NpcReward-группа→Npc. Id;
пересечений нет, правило применения за убийство ещё не доказано. Карточки и фильтр
разделены на«Личные записи NPC»и«Записи области»; последние показывают области,
не объявляют обычных NPC подтверждёнными источниками. area-rewards.json,
reward-scope-audit.json; 58 тестов, 1785 SHA карточек. Браузер отключён.

## Текущее состояние и следующий шаг

На Pixel 5 · JP установлена **1.0.22**, настройки редакции 4 применены.
Новый персонаж Zizak дошёл до уровня 6, задания 14. Покупка для Guide прошла:
75 Gold, одна бутылка. Бот на паузе из-за распознавания золотого фона завершённого
Guide; повторной покупки не было. Учёт персонажей разделён контекстом в данных.
Подробности: [PURCHASE-CONTEXT.md](PURCHASE-CONTEXT.md).

Кандидат **1.0.23**: варианты завершённого Guide и общий исполнитель действий
[QUEST-AUTOMATION.md](QUEST-AUTOMATION.md). 24 учебных правила и получение награды
используют общую проверку геометрии, ожидание, ограничение попыток и резерв до IPC.
Полный прогон прошёл: 239 тестов за 129,366 секунды. Живая проверка выполняется.
1.0.23 собрана, подписана и опубликована; установить пока не удалось: после
восстановления локального gateway Pixel отображается offline. Последнее состояние
телефона — пауза на 1.0.22 после покупки. Следующий шаг — проверить сборку на сохранённом reserved, затем продолжить
квесты. Полного универсального распознавания любых окон пока нет.

### История проверок

Кандидат **1.0.20** — [PASSIVE-HUD.md](PASSIVE-HUD.md): короткое наблюдение
уже подтверждённого автоквеста без нажатий. Свежие HUD+auto_on, нет учебного SKIP/
известных попапов; полный поиск каждые 12 сек. Неизвестный маркер может ожидать полного
поиска, немедленная реакция на любой новый попап не обещается. Desktop короткий путь
845–878 ms/36 match вместо 2559–3096 ms/68 match. Полный путь ещё медленный.


На Pixel 5 установлена **1.0.19**, редакция 3 применена. Бот продолжает работать:
Zizak **5-го уровня**, KrynaNest. После общего обработчика сумки свежий кадр показывает
HUD без инвентаря, quest_auto_running, errornull. Подробности [BAG-EXIT.md](BAG-EXIT.md).
Прошли 2 новых кадровых теста+5 роутера+25 квестовых регрессий. Полный обычный HUD поиск
пока 6833 ms; оптимизация повторных учебных шагов не равна быстрому HUD циклу.

Сцена с SKIP закончилась сама; общий skip без подтверждения типа экрана включать нельзя.
Для CutsceneUI/MediaUI найдены ButtonSkip и геометрия, но это недостаточно для
отличения от SKIP обучения. Отдельная задача V61, источники сохранены.

На Pixel 5 установлена **1.0.18**, редакция 3 применена. Свежий кадр после
исправления: Zizak **3-го уровня**, задание 6 «To a safe location / Talk to Damir».
После завершения 4002 бот продолжил цепочку без ручных игровых нажатий.
 Бот прошёл Adrenaline
по рамке (1.0.17), затем сам выполнил завершающий Tooltip4002018 и вернулся
к заданию 3 «Talk to the Elottarvizian». Ошибка цели устранена. Последний статус
running, error=null; действие quest_skip_scene1048 ms. 24 учебных привязки.
Проверки: полный прогон 1.0.17 —215 тестов; затем 2 новых кадровых теста Buff
и 46 регрессионных(квесты/каталог/связи)прошли. Не называть это полным 217-прогоном.
Источники и ограничения: [ADRENALINE-FRAME.md](ADRENALINE-FRAME.md).
Кадры/статусы zizak-level1-2026-10-16; следующий короткий прогон
zizak-after-drain-2026-10-16. Покупки остаются выключены.

Новый прогон 16 октября: Zizak1→2 уровня на Pixel 5. Общая 1.0.15 сама прошла
начальный диалог, задание 1, сюжетную сцену и обучение Drain до Adrenaline в задании 3.
Покупки выключены. Имя ПК — только метаданные. Кадры в zizak-level1-2026-10-16.
Drain на одном кадре score0.816 не прошёл порог, но позже прежняя 1.0.15 распознала и
продолжила. Установленная 1.0.16 добавляет точные варианты текста 75/100/125%, без снижения
порога/смены исходного действия 4002004;4 варианта кадра прошли. Полная ранняя цепь
ещё не проверена; последний кадр Adrenaline. Верификация при повторе—вручную.

На Pixel 5 установлена **1.0.16**, 213 тестов прошли. [ENHANCE-EXIT.md](ENHANCE-EXIT.md)
описывает быстрый маршрут окна Enhance. Поиск на Android 935 ms(полный tick 1543 ms
при capture 602 ms). Затем игра разорвала сессию KICKOUT_FOR_INSPECT, бот подтвердил
сообщение и встал на паузу; титул подтверждён кадром. Успешный возврат к HUD после
стрелки не подтверждён. Пользователь сообщил, что ожидается повторное подтверждение
телефона. Верификацию не автоматизировать, не считать одноразовой; повторный автоматический вход
не включать. Следующая живая проверка после ручного подтверждения пользователем.

На Pixel 5 установлена **1.0.14**, 208 тестов прошли. [RECOGNITION.md](RECOGNITION.md)
описывает первый общий механизм: приоритет ожидаемого/предыдущего шага по данным
клиента, кеш только внутри кадра, поздняя проверка HUD. Все кандидаты остаются для
запасного поиска; универсального классификатора любых окон ещё нет. Desktop повтор
известных шагов 504–539 ms; первое/неизвестное состояние на Pixel 5 пока 5915–9495 ms.
Не выдавать это за целевой цикл 1 сек во всех состояниях.

23 учебных привязки.1.0.13 сама открыла сумку, следующие выбор/описание/свиток
проверены диагностическими одиночными tap.1.0.14 сама выполнила финальный 4007012:
потрачено 2500Gold, броня+1, обучение завершилось. После него окно Enhance осталось
открытым, бот поставлен на паузу; следующий шаг — общий выход по связям UI,
затем продолжить квест. Доказательства tutorial4007-2026-10-16/result-plus1.jpg
и result-status.json библиотеки. Полный автоматический проход всех четырёх
новых шагов на Android не проверен, только 16 масштабных кадровых случаев.

История: на Pixel 5 · JP была установлена **1.0.12**, применена редакция 3. После ручной
верификации устройства бот прошёл титул и GameStart выбранного персонажа,
загрузил мир, закрыл Guide-награду и продолжил задание 18 Leave Shadow Grove.
Прогон остановлен на новом обучении 4007; доказательства в библиотеке
phone-tests/quest-run-2026-10-16/. Полный проход поздних заданий не подтверждён.

Один универсальный entry.py для всех персонажей: общий титул и выбранный
персонаж, без профиля/фильтра имени или сервера. CharacterSelectUI.ButtonStart,
контроль 124, Slot48, связи и кадр в character-entry-reference.json. Сервер/аккаунт/
персонаж бот не переключает. На ПК имя изменено на наблюдаемое OrfPro(UgPhone),
это метаданные телефона, а не отдельный модуль. 202 теста и кадровые варианты
входа 75/100/125%+сдвиг прошли. Сборка/подпись/SHA проверены, пакет опубликован.

Квесты включены; покупки временно отключены quest_shop_enabled=false до
разделения учёта разных персонажей. Старый журнал не удалён. Обработчики
KICKOUT_FOR_INSPECT и idle подтверждены на телефоне в 1.0.9/1.0.10.

Источники текущего состояния игры и границы доступа: [LIVE-STATE.md](LIVE-STATE.md).

**Приоритет: первоначальный прогон квестового сценария**, а не полный разбор клиента.
Порядок и границы: [FIRST-RUN.md](FIRST-RUN.md), задачи V38–V41.
Сначала собрать и проверить имеющиеся обработчики, затем пройти текущий участок
на Pixel 5. Если встретилось непонятное окно или действие — сохранить кадр,
статус и последний подтверждённый этап, найти связь в существующем индексе;
углублять исследование клиента только для этого препятствия.

Последнее исследование V37: [MESSAGE-NAMED-SLOT.md](../resource-tools/vampir/MESSAGE-NAMED-SLOT.md).
Схема наследования свойства 59, анимация и dispatcher отложены до практической
необходимости. Неподтверждённые связи не становятся правилами клика.

На Google Pixel 5 · JP установлен Vampir **1.0.14**, Phone Exit 0.8.13,
Android-пакет игры `com.netmarble.thered`. OCR/ML Kit не использовать.
Игровые действия выполняются на телефоне, ПК управляет профилями и пакетами.

**Правило пользователя: сначала искать в данных клиента и их связях, затем
реализовывать и сверять с экраном.** Полный порядок закреплён в корневом AGENTS.md.
Для попапов начинать с UI-CATALOG.md и ui-catalog/index.json.

Подписанный пакет **1.0.8 опубликован в приватном каталоге и установлен**
на Pixel 5 · JP 16 октября 2026. SHA256 удалённого ZIP проверен.
Профиль первого запуска получен и применён, редакция 2. Живой запуск распознал
`Connection terminated for safe gameplay` и перешёл в паузу:
`waiting_connection_terminated_inspect`, `source_text:KICKOUT_FOR_INSPECT`, error=null.
Пользователь подтвердил, что окно пока остаётся. Нажатий подтверждения и повторного
входа не выполняли. Короткий квестовый прогон V39 ожидает возврата в игровой мир;
это проверка обработчика сообщения, не прохождение квестов.
Доказательства: библиотека `phone-tests/first-run-2026-10-16/`.
Магазинный Guide901030 и журнал покупки входят в пакет; полный цикл покупки
на Android ещё не проверен. Ранее работали по сохранённым кадрам; текущий запрос
пользователя разрешил эту живую проверку.
Исправлены независимая проверка цифр суммы и синхронизация каталога
журнала. Полный offline-прогон bot.py: 32 сценария, включая 75/100/125%,
смещение, неверные/пропавшие значения и перезапуск после подтверждения.
Это не живая покупка и не подтверждение завершения квеста; см. SHOP-REPLAY.md.
Журнал хранится в `files/bots/vampir/vampir-purchases.json` вне версий пакета;
неизвестный результат блокирует повтор покупки даже после перезапуска/обновления.
Автоматической смены персонажа/сброса журнала пока нет: повтор того же задания
на другом персонаже этого телефона требует отдельного подтверждённого учёта.

Полная найденная цепочка данных включена в `quest-runtime.json`: 1353 квеста,
5944 задачи, 3892 записи действий игры, 139 учебных шагов, 94 UI-ключа.
**Полная цепочка данных не означает готовое прохождение всех квестов.**
Визуально поддержаны 18 учебных действий, пропуск подтверждённого диалога,
получение Guide-наград и несколько проверенных окон. Серверные действия из
таблиц бот не исполняет. На неизвестном экране ввод приостанавливается.

Последние подтверждения: персонаж дошёл до уровня 6, квеста 14; обучение
Bloodshape связано с Quest 110530 → Task 110530005 → Tutorial 4009.
1.0.5 сама выполнила Equip; 1.0.6 добавила выход из оставшегося окна.
1.0.7 установлена и запущена с обработкой Guide-наград; итог этого запуска
перед новым действием проверить по свежему статусу/кадру, не по старому тексту.
Последний целевой прогон `test_vampir*.py`: 180 тестов прошли
(включая PE, UI, пресеты масштаба и покупки).

Вход также исследуется по макетам: [ENTRY-FLOW.md](../resource-tools/vampir/ENTRY-FLOW.md),
`ui-geometry/entry-reference.json` в библиотеке — 10 окон / 20 вариантов.
Найдены отдельные ButtonStart титульной панели и выбора персонажа, выбор сервера,
состояния загрузки и ручной авторизации. `launch_buttons` пока пуст:
автоматический проход входа не включён без привязки к экрану/персонажу.
Ссылка TitleUI → TitlePanelUI подтверждена явным полем UserWidget в двух архивах.
Общий decoder проверил 958 отложенных панелей, нашёл 957 явных путей;
runtime-видимость и необработанные свойства из этих ссылок не выводятся.
Первые нативные ветви входа: [NATIVE-ENTRY.md](../resource-tools/vampir/NATIVE-ENTRY.md),
`code-clues/entry-code.json` — проверенные ссылки и инструкции с unwind-цепочками.
Внутренний Sequence не отождествлять с ELobbyState; GUI-переходы ещё не доказаны.
Кнопки титульной панели связаны с нативными полями и сравнениями:
[ENTRY-BUTTONS.md](../resource-tools/vampir/ENTRY-BUTTONS.md), 11 контролов / 12 сравнений.
Видимость элементов и полный путь события этим ещё не подтверждены.
Индекс ссылок кода на окна: [NATIVE-UI-LINKS.md](../resource-tools/vampir/NATIVE-UI-LINKS.md).
Поиск `query-native-ui.py WBP_Имя` возвращает источники и проверенные инструкции
без нового сканирования; перед выдачей сверяются хеши источников.
Получение и показ входных окон разделены в [ENTRY-WINDOWS.md](../resource-tools/vampir/ENTRY-WINDOWS.md).
Возвращённый объект окна и проверка bInitialized не означают его видимость
или готовность персонажа; семантика проверок UI-менеджера ещё уточняется.
Уточнение: проверка перед презентацией сама обрабатывает список окон и вызывает
методы найденного окна. Это не чистый IsVisible; см. [UI-MANAGER.md](../resource-tools/vampir/UI-MANAGER.md).

Каталог runtime referenceRevision=4 дополнен группами наград и ContentsLock,
двумя магазинными задачами и нативными именами типов. Перед покупкой shop.py
проверяет соответствие задаче, предмету/цене/количеству и SHA источников.
Семантика неизвестных условий блокировок не исполняется.

ContentsLock соединён с квестами и наградами: 269 блокировок, 330 условий,
109 ссылок квестов, отсутствующих блокировок/групп нет. Типы проверок,
сравнения и логика групп пока не восстановлены; evaluator не включён.
Барьер 110540 требует Guide 901030 Importance of Supplies с магазинной задачей,
а не только выдачи предыдущих наград. См. CONTENTS-LOCKS.md ниже.

Числовые типы задач, действий и наград теперь подтверждены массивами enum в EXE:
задача 901030010 — NpcShopBuy. Найдены категория 3, вкладка 5 и восемь товаров
с ценами и условиями. Обработчик одной покупки подготовлен в локальной 1.0.8;
живой результат ещё не подтверждён. Разобрано 4063 слота UI, порядок детей найден
для 1945 родителей на первом этапе. После расширения на весь найденный UI:
71985 слотов, 35632 родителя, 1764 уникальных ресурсных пути; 363 пути попапов.
Абсолютные координаты и runtime-видимость не доказаны. См. UI-CATALOG.md.

Следующая работа: локальная сборка → первый ограниченный прогон → фиксация
конкретной остановки. Полный evaluator ContentsLock и геометрия всех окон
не являются условием первого прогона. Правило поиска в источниках перед
изменением каждого обработчика сохраняется.

## Где код и за что он отвечает

| Файл | Назначение |
|---|---|
| [bot.py](bot.py) | Вход движка: foreground, запуск игры, захват, загрузка каталога, нормализация масштаба |
| [messages.py](messages.py), [IDLE-CONFIRM.md](IDLE-CONFIRM.md) | Явные ключи сообщений, однократное подтверждение и проверка результата |
| [entry.py](entry.py), [TITLE-ENTRY.md](TITLE-ENTRY.md) | Универсальный вход с текущим выбором аккаунта/сервера игры; Android-переход ещё не подтверждён |
| [quests.py](quests.py) | Распознавание этапов, ввод, ожидание результата, допустимая вариация кликов и задержек |
| [shop.py](shop.py), [shop-reference.json](shop-reference.json) | Покупка для конкретного Guide, сохранение неизвестного результата без повторного списания |
| [SHOP-REPLAY.md](../resource-tools/vampir/SHOP-REPLAY.md) | Прогон настоящего bot.py на кадрах, исходные/отрицательные случаи и границы проверки |
| [ui-window-reference.json](ui-window-reference.json) | Текстовые ключи, источники и отдельно помеченные кандидаты ресурсов окон |
| [vision.json](vision.json) | Шаблоны, области поиска, привязки к TutorialStep, известные окна |
| `templates/` | Снимки только проверенных элементов; не массовый экспорт всех ресурсов |
| [quest-runtime.json](quest-runtime.json) | Генерируемая полная цепочка; не редактировать вручную |
| [tutorial-reference.json](tutorial-reference.json) | Генерируемые привязки 18 действий к CSV с SHA256 и смещениями |
| [manifest.json](manifest.json) | Версия модуля, совместимость движка/настроек, разрешённый пакет |
| [defaults.json](defaults.json), [settings.schema.json](settings.schema.json) | Независимые настройки Vampir; без профилей других игр |
| [../test_vampir.py](../test_vampir.py) | Запуск, загрузка, распознавание готовности, смена разрешения |
| [../test_vampir_quests.py](../test_vampir_quests.py) | Последовательности, задержки, лаги, границы кликов, награды и защита от слепого ввода |
| [../test_vampir_source_links.py](../test_vampir_source_links.py) | Целостность ContentsLock, групп условий, сохранение флагов и отсутствие выдуманной семантики |

## Где источники и все связи

Библиотека на диске: **`F:/PhoneExit Resources/Vampir`**.
Установка клиента для исследования:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
Это собранный Unreal-клиент/cooked-ресурсы, не исходный проект разработчика.
Версия данных Windows пока не доказана равной версии Android.

| Что требуется | Читать в репозитории | Данные относительно библиотеки на F: |
|---|---|---|
| Быстро найти любой ресурс | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md) | `RESOURCE-INDEX.md` |
| Как повторить извлечение | [README инструментов](../resource-tools/vampir/README.md) | `RESOURCE-PROVENANCE.md` |
| Ссылки в собранном EXE | [CODE-CLUES.md](../resource-tools/vampir/CODE-CLUES.md) | `code-clues/shipping-strings.json` |
| Числовые типы, товары и условия покупки | [NATIVE-SEMANTICS.md](../resource-tools/vampir/NATIVE-SEMANTICS.md) | `code-clues/native-enums.json`, `quest-graph/shop-tasks.json` |
| Объявленные связи таблиц | [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md) | `code-clues/table-dependencies.json`, `quest-dependencies.md` |
| Квест → задача → обучение → контрол | [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md) | `quest-graph/index.json`, `early-quests.json` |
| Требования и награды | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `quest-graph/rewards.json` |
| ContentsLock и ранний барьер квеста | [CONTENTS-LOCKS.md](../resource-tools/vampir/CONTENTS-LOCKS.md) | `quest-graph/contents-locks.json`, `early-unlock-chain.json` |
| Геометрия Canvas-слотов | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `ui-geometry/canvas-slots.json` |
| Панели и порядок дочерних элементов | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `ui-geometry/panel-slots.json`, `topology.json` |
| Все найденные окна, попапы и контролы | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `ui-catalog/index.json`, JSON вариантов окон |
| Размеры самих SizeBox и флаги применения | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `code-clues/ui-properties.json`, `ui-geometry/size-boxes.json` |
| Наследуемые свойства и ScaleBox | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `ui-geometry/scale-boxes.json`, `container_geometry.decoded.inherited_properties` в каталоге |
| Пресеты UI Scale, default и поиск DPI | [UI-SCALE.md](../resource-tools/vampir/UI-SCALE.md) | `ui-geometry/ui-scale-reference.json`, `code-clues/ui-scale-config/index.json` |
| Имена и дерево экспортов UI | [inspect-ui.py](../resource-tools/vampir/inspect-ui.py) | `ui-layout-study/index.json` и JSON каждого пакета |
| Полные CSV и происхождение | [extract-tables.py](../resource-tools/vampir/extract-tables.py) | `table-study/index-pakchunk1-Windows.json` и `index.json` |
| Карты и картинки | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md) | `archive-image-latest.json`, `map-image-catalog.json`, `maps/` |
| Что исполняется, а что пока справочник | [RUNTIME-CHAIN.md](../resource-tools/vampir/RUNTIME-CHAIN.md) | `RUNTIME-CHAIN.md` |
| История и живые проверки | [../vampir.md](../vampir.md) | `PROJECT-STATE.md`, `phone-tests/` |

Главные записи `pakchunk1-Windows`: Quest 1448, QuestTask 1454,
QuestTaskAction 1455, **Reward 1475**, Tutorial 1551, TutorialStep 1555,
TutorialUI 1556, WorldSpot 1573. Английские тексты: Quest 498,
QuestTask 502, TutorialStep 543. Это номера записей, не смещения в байтах.
После обновления игры номера могут измениться: использовать хеши/схему.

## Порядок изменения сценария

1. Найти строку задания/обучения и её зависимости в графе. Сохранить ID,
   условия, источник и хеш. Для наград проверить и требования квеста, и Reward.
2. По TutorialUI найти WBPName → WidgetName → ControlName/ControlIndex/TargetId.
   По экспортам/слотам проверить геометрию; неизвестные родительские размеры,
   DPI, анимацию или видимость не подменять предполагаемыми координатами.
3. Снять свежий кадр, проверить подсказку и цель, добавить контролируемый обработчик.
   Предыдущий ID или координаты не являются разрешением следующего клика.
4. Связать действие с исходной строкой через build-tutorial-bindings.py.
   Сохранять ограничения, флаги и минимальные ожидания. Проверить случай задержки,
   временной потери цели, повторного кадра и смены размера экрана.
5. Запустить проверки. Увеличить версию; опубликованную версию не перезаписывать.
   Собрать подписанный пакет, затем установить/проверить на выбранном телефоне.
   Новые зависимости движка требуют APK. Секреты не писать в команды документации.
6. Обновить этот файл при изменении состояния/путей и подробный журнал результатов.
   Отдельно указать ручные действия, автоматические действия и непроверенные случаи.

## Основные команды из корня репозитория

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-native-enums.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-quest-graph.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-reward-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-canvas-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-panel-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-topology.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-ui-properties.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-size-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-scale-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-catalog.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-templates.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-binding.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-window-bindings.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-deferred-panels.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-entry-reference.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-scale-reference.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ui-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-shop.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-runtime-chain.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-tutorial-bindings.py
python -m unittest discover -s phone-exit/bots -p 'test_*.py'
powershell -NoProfile -File phone-exit/pc/build-bot-package.ps1 -Bot vampir
```

Генераторы используют библиотеку на F:, проверяют исходные хеши и не должны
молча менять данные игры. Для новой версии клиента сначала выполнить процедуру
из README инструментов. Массовые PNG/PAK остаются вне пакета и репозитория;
в модуль включается только необходимый производный справочник цепочки.

Обычный переход через easing: [UI-TRANSITION.md](../resource-tools/vampir/UI-TRANSITION.md).
Связаны настройка callback, tick и его завершение; полная отмена/reset
и соответствие Android ещё не доказаны.

Класс перехода связан с WBP_FaderUI через superclass imports и native vtable:
[FADER-CLASS.md](../resource-tools/vampir/FADER-CLASS.md). Одноимённый ImageFader
в WBP_MediaUI относится к другому native-классу.

ContentsLockCondition: [CONDITION-TYPES.md](../resource-tools/vampir/CONDITION-TYPES.md).
Native-конвертер подтвердил 11 имён типов и связь со 330 CSV-условиями;
Type1=CompletedQuest. Runtime evaluator ещё не включён.

Подтверждённые имена 11 типов включены в quest-runtime.json referenceRevision3;
330 условий сохраняют исходные значения, неизвестные сравнения и AND/OR
не исполняются. Изменение источников блокирует сборку каталога до пересверки.

17.10, проверка разделения наград: прослежены отдельные native-менеджеры
AreaReward/NpcReward и 3 связи с клиентскими UI списков предметов карты/наград
монстров подземелья. Инструмент `build-reward-scope-code.py`, 15 проверенных
вызовов/88 фрагментов; SHA/адреса/ограничения в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#проверка-потребителей-areareward-и-npcreward-17-октября-2026).
Применение к убийству и проценты пока не доказаны. Браузер снова доступен:
NPC 100201012/34 предмета области и фильтр 43 областей проверены, сервер 17946
восстановлен. 58 тестов прошли; игровых действий не было.

17.10: в карты/каталог добавлены Item. Rarity, восемь оригинальных фонов и подпись
редкости; сортировка от Mythic к Common, специальные категории отдельно в конце.
Источники/ограничения и порядок сборки — [NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#редкость-оригинальный-фон-и-сортировка-предметов-17-октября-2026).
Проверены 5827 значений/8 SHA текстур; Max102 у 3 записей не превращён в редкость.
Общий maps/item-rarity.js создаётся build-npc-loot.py до build-world-map.py.
59 тестов прошли. Фоны проверены браузером; runtime-привязка игрового виджета
по-прежнему не доказана.

17.10: добавлена полная страница предмета ?item=ID: параметры/уровни заточки,
отдельное благословение, все поля Item, описания и источники. build-npc-loot.py
теперь автоматически запускает build-item-details.py и копирует item-details.js;
848+84 группы с SHA загружаются отдельно. Источники/ограничения в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#полная-карточка-предмета-и-параметры-заточки-17-октября-2026).
Проверены 932 файла/62583 строки, Item 11014006 +0/+15 браузером, 59 тестов.
Пассивные навыки/эффекты/ограничения с неразобранной семантикой остаются как ID,
не выданы за полностью вычисленные характеристики конкретного экземпляра.

17.10: карточка предмета оформлена компактными панелями, полные свойства свернуты;
описания параметров теперь в подсказках по наведению/фокусу/нажатию.
item-details.css входит в build-npc-loot.py. Проверены браузером Item 12014006 +15,
подсказка/Tab/Escape, значения сохранены, JSsyntax и console без ошибок.
Подробности и снимок — [NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#оформление-карточки-и-подсказки-параметров-17-октября-2026).

17.10: заточка показана как база(+прибавка), итог в подсказке. item-stat-model.js
копируется build-npc-loot.py; строгое сравнение с+0, благословение отдельно,
неоднозначность не превращается в выдуманную разницу. 63 теста прошли;
браузер подтвердил 224(+107)=331 для шлема 12014006+15. См.NPC-LOOT.md.

17.10: расшифрован блок боевых параметров NPC, добавлены Skill 1505/
SkillName_en525/SkillOperation1512 и native enum названия типов действий.
Все 1785 карточек/SHA и 3039 строк операций проверены, 63 теста прошли;
браузер подтвердил 100181082 и навыки 50160/50161. Новые цепочки, источники,
native diagnostic161193986 и неизвестная семантика описаны в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#боевые-параметры-и-навыки-npc-17-октября-2026).
Время/дистанции/формула урона не домыслены; AttributeMax не выдан за элемент.

17.10: native-проверкой подтверждён выбор списка дропа в окне клиента:
NpcSpawn. AreaInfoId!=0→AreaReward, иначе NpcReward по NpcInfoId. Это ветвление UI,
не сложение и не доказанный серверный roll. Новый build-drop-selection-code.py:
26 anchors/36 фрагментов, указатели/leaf-getters/SHA; подробная цепочка в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#выбор-области-или-npc-в-окне-дропа--native-проверка-17-октября-2026).
build-monster-details.py проверяет отчёт и помечает связь в карточках;
1785 SHA/17488 размещений проверены, 64 теста прошли. Для Glade Vagrant100181102
подтверждён клиентский список области 100181100→29 предметов. Серверная выдача,
проценты и модификаторы остаются непроверенными.

17.10: проверена ссылка NPC 300041/spawn 10014140: нет NpcReward и AreaInfoId,
найдены явные QuestTask. Param.npcInfoIdList связи с Quest130420/130430.
Карточка корректно показывает отсутствие клиентских строк. Источники в NPC-LOOT.md;
серверное отсутствие дропа из этого не следует.

17.10: добавлен фильтр «Только NPC с личным дропом» и ссылка-пример 200052/
spawn 100177067 (29 предметов). Nocturne: 554 размещения/470 NPC с личными
предметными строками против 17488 всех размещений. URL npcLoot=1, подписи
NpcReward в списке. Новый тест фильтра, 18 Node-тестов карты прошли.
Подробности в NPC-LOOT.md. Исходные награды не менялись.

17.10: проверено изображение NPC 100181052: Img/NpcButtonImg пустые; похожий
портрет CharcoalNymphBoss не связан с ним явно. В Nocturne8NPC имеют прямые
Img→PNG связи. Подробности NPC-LOOT.md/monster-image-check.json; UI не менялся.

17.10: build-skill-semantics.py восстановил 40 имён Skill. FireCondition по
явным парам указателей native-парсера; 43 — его fallback, Always=0.
Имена покрывают 830/3446 Skill-строк; у всех 2632 вхождений навыков в карточках
Nocturne значение 43, поэтому оно явно оставлено нерасшифрованным. Карточки
показывают статус и исходные параметры условия. Сборка: сначала новый native
инструмент, затем build-world-map.py; SHA/offset/bytes и связи описаны в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#skillfirecondition-словарь-парсера-и-границы-времени-17-октября-2026).
1785 SHA/66 тестов проверены; визуальная проверка заблокирована настройкой Work.
Runtime-предикаты, единицы времени, формула урона и оставшиеся эффекты предметов
ещё требуют исследования; целочисленная загрузка времени не доказывает миллисекунды.

17.10: Skill. TargetType и SkillOperation. TargetType связаны с одним native-
словарём 15 целей; TargetConditionType — с отдельным словарём 15 условий выбора.
Новый build-skill-target-semantics.py запускать после build-skill-semantics.py,
затем build-world-map.py. Карточки показывают русскую подпись/ключ/код:
Enemy4, Self1 и прочие; значения парсера 15/17 остаются явно неизвестными.
Все 1785 SHA/3039 действий проверены; 67 тестов прошли. Источники и цепочки в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#цели-skill-и-skilloperation-17-октября-2026).
Точные runtime-фильтры целей, время, формула урона и эффекты предметов остаются;
визуальный просмотр всё ещё недоступен из-за настройки Work.

17.10: в карточках 39 предметов добавлены пассивные навыки: 19 групп SkillSet,
19 навыков/описаний и 35 действий. Item. PassiveSkillGroupId→SkillSet. GroupId→
SkillInfoId→Skill. Id подтверждены native diagnostics160988706/161195010.
Сборка build-npc-loot.py вызывает расширенный build-item-details.py; JSON с SHA
в item-details/passive/, новые связи и источники — в
[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#пассивные-навыки-предметов-17-октября-2026).
69 тестов/все 39 ссылок прошли. Проценты/длительности в описании — текст клиента,
не вычисленная формула; активация/сервер не проверены. EffectType/EffectParams,
вложенные эффекты и ограничения остаются. Браузер теперь доступен, но открытие
вкладки отклонено политикой безопасности URL; новый блок визуально не проверен.

17.10, повторная проверка по запросу пользователя: сервер 17946 запущен на
127.0.0.1 из F:/PhoneExit Resources/Vampir. Браузерная проверка теперь прошла:
Magistrate's Sword11013010 +0/+15 (прибавки+93/+45), иконка/редкость/благословение;
Demon King's Sword11015000→Frenzy и описание видны, ошибок console нет.
Это уточняет прежний статус «визуально не проверен». Снимки server-check-item.png
и passive-checked.png в maps/loot; сервер оставлен работающим.

17.10: добавлен блок ограничений предмета: 14 ссылок на ItemLimit и 28 на
ItemUseLimit, 0 потерянных. Native-парсеры подтвердили DisableEnchant0 /
DisableRefinement1 / DisableDisassembly2 и UseOnly0 / UseExcept1;
сочетание списков миров/типов и runtime-применение пока неизвестны.
Новый build-item-limit-semantics.py запускать перед build-npc-loot.py.
Источники/47 anchors/связи в[NPC-LOOT.md](../resource-tools/vampir/NPC-LOOT.md#ограничения-предметов-itemlimit-и-itemuselimit-17-октября-2026).
71 тест/браузерные примеры 11014106 и 94100191 прошли, снимок item-limits-checked.png.
По навыкам работа частичная: вложенные эффекты/точные предикаты, код 43, урон
и единицы числового времени ещё не восстановлены; это следующий приоритет.

17.10: подключены определения Effect92/EffectOperation93 и доказана их связь
по EffectInfoId (native diagnostic160717314). Переход SkillOperation. Param1→Effect
ещё не доказан: 75 вхождений/37 разных NPC-кандидатов и 19 пассивных кандидатов
сохранены отдельно со статусом false и явной подписью в свёрнутом UI.
skill-effect-links.py + общий skill-effects.js/css; сборка прежняя.
[Источники/границы исследования](../resource-tools/vampir/NPC-LOOT.md#определения-эффектов-и-неподтверждённые-ссылки-из-навыков-17-октября-2026).
74 теста/1785 SHA прошли, Impact/оглушение 101 визуально проверены.
Вложенные эффекты навыков **не считаются завершёнными** до доказательства Param1;
урон, время и runtime-условия также остаются.

17.10: Effect. ActionType→native parser→56 имён подтверждены; 408 определений
с именем/1619 с fallback56. None=0, Stun=6;56 не интерпретируется как None.
build-effect-action-semantics.py запускать до сборщиков loot/monster/world.
UI показывает действие/ActionParam/исходные поля истечения. Источники и
[границы](../resource-tools/vampir/NPC-LOOT.md#effectactiontype-56-названий-действий-17-октября-2026).
75 тестов/1785 SHA/2027 определений проверены, Impact визуально проверен.
SkillOperation. Param1→Effect всё ещё кандидат; время/урон/предикаты не закрыты.

17.10: восстановлены словари OverlayType(5 имён) и BuffType(3), выведены в
определениях эффектов. OverlayType 2008/2027 известны, 19fallback; BuffType 9
известны/2018fallback. Новый build-effect-rule-semantics.py перед сборщиками
loot/monster/world. [Связи/источники/границы](../resource-tools/vampir/NPC-LOOT.md#режимы-наложения-и-подтипы-эффекта-17-октября-2026).
Проверены 9 исходных ключей истечения Skill/Die без выполнения цепочек.
76 тестов/1785 SHA/2027 определений/визуальная проверка прошли.
Правила накопления/обновления длительности/истечения, Param1→Effect,
время/урон/runtime-условия ещё не считаются восстановленными.
