# Vampir — общие компоненты и результаты

## GMC2 XOR primitive, 19 октября

Общий vampir_core.gmc2_decode.xor_gmc2_utf16_units: raw LE uint16 XOR,
повтор key без storage NUL, пропуск zero output units как в native append.
18 native fixtures совпали; empty key/type/size отклоняются. Нет Base64/JSON,
key acquisition или I/O. [Источник](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).

## Offline GMC2 GET plan, 19 октября

Общий vampir_core.gmc2_request.plan_gmc2_get_request: explicit URL/service/
game/build/device, optional eTag/player/token; frozen tuple headers/repr redaction.
16 native captures совпали. Нет I/O/device creation/credential acquisition.
[Source и локальная input policy](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).

## GMC2 URL assembly, 19 октября

vampir_core.sdk_config.assemble_gmc2_config_url_ascii собирает только строку
из явных base/group/sdk_version/build_code/market. 26 native fixtures совпали.
Не нормализует слэши/не экранирует/не выполняет HTTP; printable ASCII subset,
4096 chars fragment/result. [Доказательства](../resource-tools/vampir/HEADLESS-GMC2-URL.md).

## SDK BuildCode selector, 19 октября

Общий vampir_core.sdk_config.select_sdk_build_code принимает явный byte int:
1→B, 2→C, остальные→A; bool/вне диапазона отклоняются. Все 256 значений
совпали с native getter на compiled initializer defaults. Активный BuildCode
не угадывается по Zone/версии. [Доказательства](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).

Обновлено 19 октября 2026. Главный вход — [Vampir README](../vampir/README.md).
Общие результаты предназначены для экранного бота, сетевого бота, 2D-карты
и будущей Android-оболочки. Здесь единый указатель, без копирования доказательств.

| Что нужно | Единственный источник |
|---|---|
| Функции, адреса и степень подтверждения | [FUNCTION-INDEX](../vampir/FUNCTION-INDEX.md) |
| Ресурсы, таблицы, карты и происхождение | [RESOURCE-INDEX](../resource-tools/vampir/RESOURCE-INDEX.md) |
| Извлечение данных и доказательства | [resource-tools/vampir](../resource-tools/vampir/README.md) |
| Общий переносимый исполняемый код | `vampir-shared/vampir_core/` |
| Тяжёлые данные и машинные отчёты | `F:/PhoneExit Resources/Vampir/` |
| Задачи/история сетевого бота | [TASKS](../vampir-headless/TASKS.md), [WORKLOG](../vampir-headless/WORKLOG.md) |
| Экранный бот и карта | [Vampir TASKS](../vampir/TASKS.md), [MAP-ATLAS](../resource-tools/vampir/MAP-ATLAS.md) |

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

## SDK settings и game override, 19 октября

Подтверждены 9 полей NMSDKSettings и начальные значения (4 native replays).
Найдена игровая InitSetting: compiled globals market nmp/game thered/client ID,
13 native сценариев сравнения environment → production при real без учёта ASCII
регистра, иначе Dev. Общий select_game_sdk_zone требует явного environment.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md). Активный environment и его загрузка пока неизвестны.

## Общий код

`sdk_constants.py:xor_sdk_utf16le` — отдельный XOR 16-битных единиц GMC2,
с ограничением входа/ключа и сохранением нулей/суррогатов. 42 native проверки
и пять тестов: [доказательства](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).
Модуль также разбирает содержимое JSON-строки перед XOR, отклоняет неверные
escape и сохраняет UTF-16 единицы. 43 корректных и 7 граничных native входов,
три составных примера: [ответ GMC2](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
Получение ключа, извлечение полей ответа и проверка схемы ещё не реализованы.
`decode_sdk_base64` в том же модуле декодирует один ciphertext, до 2048 символов,
с каноническим padding или без него. 26 корректных native входов и 8 граничных;
[RSA-параметры и ограничения](../resource-tools/vampir/HEADLESS-SDK-SECRET.md).
`sdk_secret.py:decrypt_sdk_secret_chunk` расшифровывает один secret chunk
с явным телом RSA-ключа; optional cryptography backend загружается при вызове.
Windows проверен на искусственных ключах, native OAEP — 24 корректных / 69
ошибочных входов. [Доказательства и лимиты](../resource-tools/vampir/HEADLESS-SDK-OAEP.md).
`decode_sdk_secret_constants` собирает список расшифрованных элементов в JSON,
проверяет типы/UTF-8/повторные ключи и отклоняет весь результат при ошибке.
9 основных / 4 граничных native сценария orchestration, шесть тестов:
[список и границы](../resource-tools/vampir/HEADLESS-SDK-SECRET-LIST.md).
`sdk_config.py` объединяет уже строковые normal/secret карты с приоритетом
secret и читает значение по native HTTP(S) prefix check. 24 lookup / 3 replacement /
5 hash native сценариев: [доказательства](../resource-tools/vampir/HEADLESS-SDK-MAP.md).
Stringify прочих JSON-типов, весь callback → SDK map и Android ещё открыты.
`append_sdk_path` повторяет native path concatenation (70 сценариев),
`auth_request.py:bind_token_request` связывает code/refresh form с явным
authTokenUrl. URL/body скрыты в repr; нет HTTP или автоматического выбора адреса.
[Правила и локальные ограничения](../resource-tools/vampir/HEADLESS-SDK-PATH.md).

`auth_request.py` создаёт offline TokenRequestPlan для code/refresh grants,
explicit authTokenUrl config key/relative v2/access-token, bounded printable ASCII.
24 SDK roots/512 native byte primitive calls: [доказательства](../resource-tools/vampir/HEADLESS-AUTH.md).
Нет получения/отправки credentials, browser login, HTTP или game session.
Источник конфигурации исследуется отдельно: [GMC2](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Адреса и активный режим не зашиты в runtime по наличию строки в EXE.

`socket_send.py:drain_outbound` — bounded send на уже подключённом nonblocking
socket; `OutboundFrames.peek_frame/consume_sent` сохраняют partial tail.
61 native cases/5 tests и real local IPv4 TCP: [доказательства](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
Connect/auth/readiness scheduler и session lifecycle пока не реализованы.

`send_frame.py` содержит send-B encoders Ping/KeyChanged с explicit key/sequence.
`outbound.py:OutboundFrames` ограничивает bytes/frames, хранит immutable ciphertext,
ставит key ack под старым ключом до переключения следующего кадра.
40 native cases/5 tests: [доказательства и локальная error policy](../resource-tools/vampir/HEADLESS-SEND-B.md).
Это не socket transport; один session owner, без thread safety/авторизации.

`receive_frame.py:take_receive_b_frame` / `receive_packet.py:decode_game_ping_result_b`
используют явный unsigned64 peer key, не выполняют session bookkeeping.
39 native cases: [доказательства](../resource-tools/vampir/HEADLESS-RECEIVE-B.md).
Input immutable, body policy exact, raw transport layer обрабатывается отдельно.

`receive_packet.py:decode_game_ping_result` — один receive-A game PingResult ID17,
body12, явный frame limit. Exact body policy строже native trailing tolerance.
24 native Dispatch scenarios: [доказательства](../resource-tools/vampir/HEADLESS-DISPATCH.md).
Без игровых OnHandler side effects и без универсальной registry для lobby/game.

`receive_frame.py:take_receive_a_frame` — один полный receive-A кадр:
length probe + fallback XOR, header сохраняется, вход не меняется.
44 native loop cases и 5 tests: [доказательства](../resource-tools/vampir/HEADLESS-LISTENER-LOOP.md).
Не raw transport, не CRC/packet schema; управление сессией ещё не реализовано.

`vampir_core/transport_header.py` — первый уровень приёма: size 23, признак
сжатия и извлечение кадра с явными input/output limits. [Доказательства](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md).
`block_decode.py` распаковывает literals/matches с ограниченным output;
166 valid / 86 invalid native проверок: [доказательства](../resource-tools/vampir/HEADLESS-BLOCK-DECODE.md).
`take_transport_frame` поддерживает обе ветки skip=3. `receive_frame.py` относится
к следующему уровню; применять его прямо к raw stream нельзя.

`vampir_core/key_change.py` — общие IDs11/12 и raw64codec уведомления/подтверждения
смены ключа, repr скрывает значение. [Доказательства и порядок вызовов](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md).
Управление сессией и отправка подтверждения пока не реализованы.

`vampir_core/receive_frame.py` — проверка полноты входящего кадра с явным
лимитом и защитой от недопустимой длины; [источники и отличия от клиента](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md).
Это ещё не packet decoder или CRC validation.

`vampir_core/send_frame.py` — сборка полного исходящего Ping кадра send-A;
[доказательства](../resource-tools/vampir/HEADLESS-SEND-FRAME.md).
Приёмный decoder и подключение пока не реализованы.

`vampir_core/frame_primitives.py` — подтверждённые CRC32 и XOR helpers;
это не полный frame encoder. [Доказательства](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md).

Первый модуль — `vampir_core/ping.py`, payload encode/decode для Ping/Result.
Только стандартная библиотека Python; импорт `vampir_core.ping` одинаков для
всех потребителей. Package root — `vampir-shared`; тесты подключают его через
sys.path. Упаковка Windows/Android ещё не реализована. В сетевом боте второй
копии нет. Сам модуль не подключается к серверу и не запускает игру.

Доказательство/версия: [HEADLESS-PING-CODEC.md](../resource-tools/vampir/HEADLESS-PING-CODEC.md).
Название `headless-*` у старого отчёта означает происхождение исследования,
а не принадлежность результата только сетевому боту. Не переименовывать
provenance-файлы без необходимости: на них завязаны хеши и проверки.

Новые подтверждённые протокольные структуры, модели состояния, преобразования
координат и общие алгоритмы размещать здесь по мере появления потребителей.
UI, ключи аккаунтов, DPAPI/Keystore, foreground service и сценарии оболочки
остаются у потребителей. EXE/PAK/эмулятор не включать в runtime.
Совместимость нового выпуска игры проверяется отдельно; импорт модуля её не доказывает.

## Продолжение работы

Перед исследованием читать главный README и общий FUNCTION-INDEX. Новые связи
с версией/SHA, инструментом и ограничениями добавлять в общий реестр, подробное
доказательство хранить в resource-tools/общей библиотеке. Исполняемую реализацию
держать в одном экземпляре, проверять общий модуль и затронутого потребителя.
Запись о выполнении остаётся в журнале направления, со ссылкой на общий результат.
Экранный бот не получает сетевые команды автоматически от появления кодека.
