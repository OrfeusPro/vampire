# Самостоятельный Vampir — задачи

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
