# Vampir — самостоятельный сетевой бот

## Общий валидатор результата почтового входа, 19 октября

Native parser/channel проверены: 28 numeric/45 channel/6 caller fixtures.
Общий nid_result проверяет уже decoded fields, email channel20 и canonical0,
возвращает redacted provider credential без I/O. Local policy строже native.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).
До готового входа остаются query/context, storage, setters/callback и session.

## Проверки OnResult подтверждены с явными dependencies, 19 октября

22 native fixtures проверили caller gates и подготовку раздельных token/ID/
country settings calls. Пустой refreshToken проходит; отсутствие поля — отдельный
fixture outcome. Integer/channel returns и map/settings заменены shims/captures.
[Источник и ограничения](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).
Реальной SDK/game session нет. Далее parser/channel/query/setters/callback.

## Уточнён путь результата почтового входа, 19 октября

Email web flow передаёт nmidprovider/result с accessToken, а не доказанный
здесь authorization code. Перед result требуется обработка профиля.
12 JS fixtures и static native OnResult/dispatcher bindings сохранены.
[Доказательства](../resource-tools/vampir/HEADLESS-NID-RESULT.md).
Далее проверить native query validation/token adoption; реального входа нет.

## Локальный план входа NID по почте, 19 октября

Из сохранённых публичных HTML/JS подтверждены endpoint, поля и RSA encoding.
Общий nid_email формирует зашифрованный запрос с явными context/reCAPTCHA token;
HTTP и получение captcha не реализованы. Ответ входа и callback ещё не разобраны.
[Источники, SHA и воспроизведение](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Авторизации аккаунта, выбора персонажа и боя пока нет.

## Реальная SDK-конфигурация получена, 19 октября

Public GMC2 profile дал 200/errorCode0 и DECKEY HTTP response header.
Общий offline decoder: 93 ordinary+1 secret=94 constants, auth URL fields найдены.
Token plan связан с real config offline, только synthetic code/device/client inputs.
[Source/SHA/snapshot/границы](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).
Авторизация/персонаж/бой не выполнялись. Дальше email/password/browser flow.

## Составной SDK constants decoder исправлен, 19 октября

Existing unescape → actual XOR output теперь использует единый primitive
с пропуском нулевых units. 18 native fixtures сверены через composed path;
старые raw-capture результаты сохранены как история.
[Ограничения](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
Полный DECKEY lookup/response/auth ещё не готов.

## Подтверждён XOR primitive GMC2, 19 октября

Native helper/append: uint16 XOR по повторяющемуся key, zero outcomes
пропускаются. 18 fixtures и общий gmc2_decode.xor_gmc2_utf16_units совпали.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).
Ответ GMC2 целиком/DECKEY/auth/session ещё не разобраны.

## Подтверждены аргументы GET и headers GMC2, 19 октября

16 native fixtures проверили шесть постоянных headers, eTag/token gates
и GET method. Общий gmc2_request.plan_gmc2_get_request хранит immutable
headers, скрывает значения в repr, не получает/не передаёт credentials.
[Источник и границы](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).
HTTP object methods — captures; device/player fixtures, вход ещё не готов.

## Подтверждена сборка URL GMC2, 19 октября

Native assembly slice/getters/ASCII-view append проверены на 26 fixtures;
общий assemble_gmc2_config_url_ascii в sdk_config.py совпал со строками.
Нет нормализации слэшей/escaping; inputs явные, HTTP/URI trust отдельно.
[Доказательства](../resource-tools/vampir/HEADLESS-GMC2-URL.md).
Далее RequestGMC2 headers/response/DECKEY и auth endpoints.

## Уточнены параметры SDK bootstrap, 19 октября

SDK getter version=5.2.11, BuildCode byte1→B/2→C/остальные→A.
256 native getter fixtures и compiled initializers проверены; общий
select_sdk_build_code находится в vampir_core.sdk_config.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Активный BuildCode и полный GMC2 request/response ещё открыты.

## Реальный публичный CDN config и два слоя INI, 19 октября

Base Game config содержит 1.12.14/real/CdnConfig=True, patch — 0.1.1/dev/False;
active слой и startup precedence ещё не доказаны. По base профилю выполнен
public HTTPS GET: 200/6000 байт; общий decoder получил Zone real/mode2 и
server index6/REAL с lobby details. Body/source/headers сохранены, offline
verification не обращается к сети. [Доказательства](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md).
ProjectRED.uproject/NkPatch.uplugin совпали base/patch; обе runtime декларации
имеют LoadingPhase=Default, порядок не установлен.
[Module descriptors](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).
Подключения к лобби/авторизации не выполнялись; далее SDK bootstrap/auth/session.

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

## Обновление установленного клиента, 19 октября

34 архива изменились, один добавлен; EXE сохранил SHA256. Старые индексы
изменённых архивов устарели. Новый манифест сохранён отдельно, старые данные
не заменены. [Результат и порядок обновления](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md).
Совместимость с обновлением пока не установлена.

## Текущее состояние самостоятельного клиента, 18 октября

Выбранные send/receive пути, CRC/XOR/распаковка, queue ownership/partial send
проверены native replay; portable pump прошёл local IPv4 TCP.
[Transport и границы](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
H04 начат: 24 SDK symbols/34 LEA/24 roots, 512 native escape calls, offline
code/refresh token request plans. [Авторизация](../resource-tools/vampir/HEADLESS-AUTH.md).
GMC2 config: 7 связанных функций и 256 native проверок выбора адреса.
Активный режим/параметры ещё не установлены.
[Источник и границы](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Параметры SDK и UTF-16 XOR конфигурации сохранены в общем ядре;
42 native проверки. [Доказательства](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).
Строковый unescape перед XOR и три составных искусственных JSON проверены
отдельно; [ответ GMC2 и передача ключа](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
19 октября: [Base64 и параметры RSA секретной ветки](../resource-tools/vampir/HEADLESS-SDK-SECRET.md);
настоящая конфигурация пока не получена.
Дополнение: [OAEP checker и декодер одного элемента](../resource-tools/vampir/HEADLESS-SDK-OAEP.md)
проверены на искусственных ключах; полная конфигурация и Android ещё открыты.
Общий [декодер списка secret constants](../resource-tools/vampir/HEADLESS-SDK-SECRET-LIST.md)
возвращает JSON только после успешной обработки всех элементов.
Общие [merge строковых констант и auth URL lookup](../resource-tools/vampir/HEADLESS-SDK-MAP.md)
подтверждают secret priority и ASCII case matching; весь GMC2 callback ещё открыт.
Общий [bind_token_request и native path append](../resource-tools/vampir/HEADLESS-SDK-PATH.md)
дают полный offline-план из явной карты; реальных серверных данных ещё нет.
Полный вход по почте/паролю, SDK→game session, серверные endpoints и бой ещё
не реализованы. Все этапы/доказательства — в [TASKS](../vampir-headless/TASKS.md)
и [WORKLOG](../vampir-headless/WORKLOG.md); не повторять закрытые исследования.

Обновлено 18 октября 2026. **Сетевой клиент ещё не реализован.**
Главный общий вход проекта — [Vampir README](../vampir/README.md).
Найденные функции всех направлений — [общий FUNCTION-INDEX](../vampir/FUNCTION-INDEX.md).
Общий исполняемый код и данные — [vampir-shared](../vampir-shared/README.md).
Сетевой бот использует общий `vampir_core`, своей копии протокольного ядра нет.
Продолжение работ — [TASKS.md](TASKS.md), история — [WORKLOG.md](WORKLOG.md).

## Требования пользователя

- Работа на Windows без запущенной игры, включая вход по почте/паролю.
- 10–20 отдельных аккаунтов одновременно; у каждого свой персонаж/состояние.
- Сначала определить персонажа/место и фармить там; затем расширять сценарии.
- Лёгкая 2D-карта и онлайн-положение/цели/статусы; управление через карту.
  Нажатие точки не отправляет движение, пока координаты и команды не проверены.
- Небольшие размер сборки, память, CPU и трафик. Без рендера Unreal, кадров и OCR.
- Общее переносимое ядро для Windows и будущего Android. Предварительная основа:
  Python/asyncio, уже применяемый Chaquopy для Android. Окончательная пригодность
  зависимостей подтверждается ранним smoke-test на двух платформах.
- Учитывать примерно еженедельные обновления игры: извлечение данных,
  сравнение версий и проверка совместимости являются частью продукта.

## Границы и архитектура

Это отдельное направление, не изменение экранного `vampir/bot.py`.
Существующие исследования карты продолжаются независимо; подтверждённые
результаты используются через общий указатель. Полная карта не блокирует вход.

Ядро отделено от UI/ОС: протокол и сессии → актуальная модель мира → сценарии →
команды. Одна независимая async-сессия на аккаунт; отдельный процесс на аккаунт
не является требованием. Платформенные адаптеры: секреты (DPAPI/Keystore),
подтверждения входа, жизненный цикл/Android foreground notification/Stop.
Команды оболочки: connect/select_character/start_farm/stop_farm/disconnect;
будущее move_to включается только после отдельной проверки. Это план интерфейса,
не уже существующее API. После reconnect сначала получить authoritative state.

Визуализация: 2D-подложка/векторы выбранной области + живые слои персонажей,
целей и состояния. Использовать имеющиеся карты/преобразования только с их
подтверждёнными ограничениями. Сетевой обмен независим от частоты UI: выбранный
персонаж до 5 обновлений UI/с, общий список до 1/с, скрытая карта не перерисовывается.
Не загружать все миры/NPC/иконки сразу. Полная исследовательская библиотека,
EXE, PAK, Capstone/Unicorn и дампы не входят в runtime-сборку. Данные выдаются
компактными проверенными пакетами; debug packet capture выключен по умолчанию,
очереди/история/кеши ограничиваются. Секреты и содержимое авторизации не логировать.

Смерть, защитное сообщение, неизвестная версия/состояние и дополнительная
проверка входа приостанавливают действия соответствующего аккаунта. Фарм,
покупки и переходы не имитировать заглушками. Покупки/торговля/воскрешение/квесты
не входят в первый боевой цикл. Аккаунты не опрашивать до реализации протокола.

## Обновления игры

Не предполагать, что каждое обновление меняет протокол или только таблицы.
Хранить immutable снимки по build/SHA, version manifest и зависимости каждого
производного набора. Путь источника, версия (либо явно unknown), полные SHA256,
record/export/offset и версия инструмента обязательны. Перед переключением
проверять сериализацию, ID, вход, состояние и бой по реально затронутым связям.
Не смешивать карту и протокол разных неподтверждённых версий. Частичное извлечение
не заменяет последнюю проверенную сборку. Смена файлов — атомарная после проверок;
откат сохраняет старые данные, но не разрешает старый протокол на новом сервере.

Серверную совместимость нельзя вывести только из локального SHA. При unknown
response/version mismatch остановить команды и показать причину. Пока нет
доказанного межверсионного контракта, новая версия считается непроверенной.
Ручная команда проверки установленной игры — первый этап; расписание или
автоматическое скачивание/публикация пользователем пока не запрошены.

## Уже есть и где продолжать

Источники: `F:/PhoneExit Resources/Vampir`, установленный Windows EXE.
Полный baseline SHA и точные адреса — в общем FUNCTION-INDEX.
Есть каталог ресурсов, отдельные packet/handler/vtable связи, структуры статов,
подтверждённые ветви UI-входа; готового wire codec/login/бойца нет.

Первый инструмент нового направления:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-network-index.py
```

Выход: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Проверяет SHA EXE, точные строки и LEA на границах инструкций, хранит provenance.
Не запускает игру, не читает память процесса и не отправляет запросы.
Текущий результат: 27 symbols / 31 xrefs / 27 roots / 32 fragments / 1020 instructions,
missing=0, rejected=0, network_ready=false.

Проверка отчёта независимо от генератора:

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_index.py -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_native_entry.py -v
```

18 октября: 3 проверки отчёта и 7 проверок PE/unwind-инструментария прошли.
Проверки повторно декодируют xrefs из оригинальных байтов и сверяют SHA
фрагментов/строк. Отсутствие локальных данных означает skip, не подтверждение.

**H02 выполнен для 10 выбранных типов**: функции→vtable→constructor/ID и
reader/writer targets; пять result registrations. Полный отчёт и таблицы:
[HEADLESS-PACKET-BINDINGS.md](../resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md).
ID Login/LobbyLogin совпадают, их схемы/регистрация различны; учитывать контекст.
Четыре независимых проверки, включая 10 native ID getter scenarios, прошли.
Wire encoding и сеть этим не проверены.

**H03a выполнен**: реальные native primitive/raw IO подтвердили Ping body16 байт
и Result 12 байт, 126 native scenarios/5 tests; codec в `vampir-shared/vampir_core/ping.py`, только
стандартная библиотека Python. [Доказательства и ограничения](../resource-tools/vampir/HEADLESS-PING-CODEC.md).
Это тела сообщений, не complete frames и не рабочее подключение.

Следующий конкретный шаг **H03b**: framing/send/receive/выбор dispatcher;
output roots144aa9da0/144aaccf0 и helpers1445f1230/144aa6ca0 ещё разобрать.
**H04**: SDK auth почта/пароль→сессия.

H03b.1: CRC32/XOR helpers подтверждены 252 native executions/5 tests;
общий `vampir-shared/vampir_core/frame_primitives.py`.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md).
Следом H03b.2: полный frame, receive validation, key/context/callbacks.

H03b.2a: native цельный send-A slice подтвердил 27 байтовый Ping frame и sequence
wrap (20 scenarios/5 tests). Общий `vampir_core/send_frame.py` умеет его собрать.
[HEADLESS-SEND-FRAME.md](../resource-tools/vampir/HEADLESS-SEND-FRAME.md).
Продолжение — receive validation/context/key H03b.2b; сетевого подключения нет.

H03b.2b partial: length probe 156 native cases и wrapper 13 cases; статически связаны
game peer callback и Dispatch. Общий receive_frame.py проверяет полноту/лимиты,
не CRC/packet fields. [Доказательства](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md).
Следом transport caller, integrity/keyflow и полный входной layout.

Смена peer key теперь связана с PktKeyChangeNotify(ID11): ackPktKeyChanged(ID12)
передаётся в send до setter, оба payload8 байт. 20 native flow cases/5 tests;
общий key_change.py. [Доказательства](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md).
Первичная авторизация, полный receive layout и send queue остаются unknown.

Первый raw receive stage подтверждён 62 native сценариями / 5 тестами:
size 23/compressed flag, копирование/распаковка и compaction. Общий transport_header.py
распознаёт признак сжатия, извлекает несжатые кадры; общий decompressor ещё не готов.
[Доказательства](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md).
Далее listener loop/второй framing и send queue; сетевого подключения нет.
Действующие данные не перезаписывать
прогонами новых гипотез; новый результат ссылать в общем индексе и журнале.
