# Vampir — общие компоненты и результаты

## AppVersion игрового профиля

`login_context.bind_game_app_version` переносит явно выбранный AppVersion
в Version+0x10 / Login+0x40, сохраняя другие поля и отклоняя конфликтующие
значения. Не выбирает INI-слой и не объявляет активный cache игры.
[Профиль, источники и проверка](../vampir-headless/GAME-SOURCE-PROFILE.md).

## Windows CPUID reader

`windows_cpu.observe_windows_cpu` читает реальные vendor / brand через
собственную SHA-проверенную DLL. Она не содержит игровой код или SDK анализа.
Загрузка выполняется только на Windows x64 по явному пути / hash; результат
проходит VersionCpuInput. [Сборка и границы](../vampir-headless/WINDOWS-SYSTEM-INPUTS.md).

## Windows / CPU inputs для Version

`version_cpu.VersionCpuInput` форматирует явные vendor / brand в проверенном
ASCII-профиле. `version_inputs.bind_windows_version_inputs` заполняет только
Version+0x28 / +0x38 из WindowsVersion и CPU inputs, отклоняя конфликтующие
значения. Остальные поля, IO и наблюдение CPU остаются владельцу клиента.
[Native evidence и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-VERSION-CPU-STRING.md).

## Windows version input

`windows_version.WindowsVersion` форматирует пять source-bound полей как
major.minor.build.productType.suiteMask.64bit. `observe_windows_version()`
вызывает GetVersionExW для собственного Windows-процесса; не читает игру,
не заменяет отказ другим API. Reader не вызывается на Android.
[Native evidence, структура и реальные проверки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-VERSION-WINDOWS-CONTEXT.md).

## Ответ начала перемещения ID204

`world_move_start_result.decode_world_move_start_result(body, max_payload_size=...)`
читает полное тело из 30 байт. Вектор хранит float32 bits; enum ограничивается
значением 22, bool нормализуется. Результат неизменяемый, данные скрыты из `repr`.
Декодер требует точного размера и не применяет политику принятия ответа.
[Схема, native-проверки и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-MOVE-START.md).

## Ответ завершения перемещения ID206

`world_move_finish_result.decode_world_move_finish_result` принимает тело ответа
и обязательные `max_payload_size` / `max_collection_items`. Поддержаны все пять
массивов, вложенные необязательные данные и строки. Лимит элементов общий.
Результат неизменяемый, поля доступны по native-смещениям, данные скрыты из `repr`.
Успешное чтение не означает принятие ответа или готовность сессии.
[Источники, API и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-MOVE-FINISH-DECODER.md).

## Запрос завершения перемещения ID205

`send_frame.encode_world_move_finish_frame_b(sequence, key_bits)` кодирует
подтверждённое пустое тело ID205. Побайтно проверен по четырём native-кадрам,
включая резервный XOR-ключ и переход номера последовательности через 65535.
Номер, ключ и условия отправки задаёт вызывающий код; I/O отсутствует.
[Источники и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-MOVE-FINISH-SEND.md).

## Ответ выбора персонажа ID110

`character_select_result.decode_character_select_result` принимает тело ответа
и обязательные `max_payload_size` / `max_collection_items`. Он читает все
подтверждённые поля и коллекции; общий лимит учитывает вложенные элементы
и повторные ключи. Результат неизменяемый, данные скрыты из `repr`.

Неизвестные поля доступны по смещениям через `SelectionRecord.at(offset)`.
`WireVector3` сохраняет биты трёх float32; `WireHeading` — исходный байт
направления. Мировая позиция, принятие выбора и готовность сессии не выводятся
из успешного разбора тела.
[Источники, API и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CHARACTER-SELECT-DECODER.md).

## CharacterSelect: builder из выбранной записи

CharacterSelectPayload.from_character_list(body,index,state_raw_f0=...):
record.u64[0]→raw10, constant0→raw18 и explicit current state→raw20.
Initial state_raw_f0 приходит из accepted ID102 tail[3], но может изменяться;
его нельзя заменять неявным stale snapshot. Native index caller/lookup/virtual 50/
handoff/frame подтверждены, 61 cases/19 frames. Pure builder проверяет code 0 и
index, не заменяет session/policy/readiness gates и ничего не отправляет.
[Source и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CHARACTER-SELECT-SEND.md).

## CharacterList ID102: nested arrays/map и предпочтение

decode_character_list читает appearance items и optional map, с обязательными
max_payload_size/max_characters/max_extension_items. Последний ограничивает
сумму всех wire entries, включая повторы. Appearance enum≤45, value enum≤9,
optional map last-value-wins; immutable sorted tuples, absent=None/present-empty=().
UnsupportedCharacterExtension удалён. preferred_character_index повторяет native
первое совпадение/нулевой fallback после gates; empty/error→None — local policy.
30 native full bodies/489 short prefixes и 45 native body→handler cases.
Нет I/O, session readiness, автоматической отправки ID109 или координат.
[Актуальные источники, API и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CHARACTER-LIST-EXTENSIONS.md).

## Character list/select body codecs

Первичный ограниченный профиль ниже заменён текущим decoder выше:
обе extension ветви теперь поддержаны; третий aggregate budget обязателен.

vampir_core.character_list.decode_character_list: обязательные byte/count budgets,
frozen/redacted записи, exact body consumption. Основной профиль ID102 с пустыми
appearance extensions и отсутствующим optional; другие ветви дают явный
UnsupportedCharacterExtension. Native parity: 12 bodies, 229 short prefixes.
vampir_core.character_select.CharacterSelectPayload: три raw integer fields
→ `<QIQ`/20 bytes, 16 native vectors. Семантика полей/session state не выводится.
Без I/O/автоматического выбора/frame/live входа.
[Источник, поля, проверка и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CHARACTER-CODECS.md).

## PktLoginResult body decoder

vampir_core.login_result.decode_login_result → frozen/redacted LoginResultBody:
7 strings, 3 u32, 2 u16, 8 raw64, 5 normalized flags. Native parity на 21 full
bodies и 332 short inputs; strict trailing/text/budget policy, без I/O/session.
[Source и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-RESULT-READER.md).

## PktLogin body encoder

vampir_core.login_packet.LoginPayload: 15 strings, 4 uint32, 5 raw bytes и
явный opaque uint64. Actual native parity на 25 vectors, 40 IO failure cases
сохранены отдельно. Immutable fields, скрытый repr, обязательный byte budget.
Нет I/O/default profile values/frame/server session.
[Источник и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-PACKET-WRITER.md).

## PktVersion body encoder

vampir_core.version_packet.VersionPayload: десять raw ordered strings и три
uint32 → проверенное тело пакета. Native UTF-8/archive parity на 14 vectors;
immutable data/output, обязательный byte budget, без I/O/decoder/frame/session.
[Источник и строгая локальная политика](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-VERSION-PACKET-WRITER.md).

## SDK sign-in response parser

vampir_core.sdk_sign_in_response: неизменяемые данные, скрытые из repr
идентификаторы и token, обязательный canonical errorCode 0 и свежие поля.
Это строгая локальная политика без I/O и без доказательства игровой сессии.
[Источники, SHA и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## nid_storage_path: offline suffix derivation

derive_nid_storage_suffix: verified aligned ASCII subset, subject bytes minus1
→ AES-256 ECB с 32 ASCII bytes nmDeviceKey → uppercase hex. Case key важен.
Optional cryptography, без token parsing/validation, I/O или active profile.
[Native source/local policy](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-NID-SUFFIX.md).

## DeviceRegistry schema v2, 19 октября

Отдельные nid_device_key/nid_identity_source для NID web/OAuth, не alias
SDK device_key. Миграция сохраняет данные v1 и добавляет пустые поля.
record_real_nid_identity закрепляет наблюдаемое значение; первая запись
сбрасывает старое confirmed, повтор идемпотентен. Реальных ключей ещё нет.
[Source/схема/границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-DEVICE-CONTEXT.md).

## Общий реестр устройств, 19 октября

device_registry.DeviceRegistry хранит постоянную связь почты и устройства
в SQLite: один основной аккаунт, неизменяемые наблюдаемые identity, отдельный
статус подтверждения. Без генерации fingerprint, сети, паролей и токенов.
[Схема и границы](../vampir-headless/DEVICES.md).

## SDK sign-in offline request plan, 19 октября

sdk_sign_in.plan_nid_sdk_sign_in принимает explicit context/constants и
NidSdkCredential33. Формирует JSON body/headers/POST authUrl/v1/sign-in,
optional player_id и отдельный existing_sdk_token. Не подставляет provider
access token как SDK headers. Frozen plan скрывает URL/body/headers в repr.
Portable stdlib only; нет I/O/storage/SDK response/game session.
[Native source/SHA/local policy](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-SIGN-IN.md).

## Provider email → SDK credential object, 19 октября

nid_sdk_credential.build_nid_sdk_credential повторно проверяет NidEmailCredential
и возвращает frozen/redacted NidSdkCredential. as_object → channelAccessToken
и channelCode33. Provider channel20 не переносится как SDK credential channel.
Нет HTTP/storage/SDK mutation или готовой session.
[Native caller/GetObject evidence](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-CREDENTIAL.md).

## SDK percent subset и callback route boundary, 19 октября

sdk_percent.decode_sdk_percent_ascii: корректные %HH, decode один раз,
+ не превращается в space; malformed/%u/controls/non-ASCII отвергаются.
nid_result.parse_nid_email_callback требует explicit expected_game_code,
проверяет route/duplicates/budgets, вызывает existing fields validator.
Результат — provider credential с redacted repr. Это strict local boundary,
без nonce/token validity, I/O, storage или SDK/game session.
[Source/SHA/пределы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-PERCENT.md).

## Общая NID channel table и decoded result boundary, 19 октября

vampir_core.nid_result: channel_key_to_sdk_type (13 source-bound keys, ASCII)
и validate_nid_email_result_fields → NidEmailCredential с redacted repr.
Все lookup keys обязательны, refresh может быть пустым; canonical resultCode0
и country format — явно более строгая локальная политика. Нет URL parsing,
I/O, storage, SDK/game session. Windows/CRT нужны только research replay,
общий runtime использует стандартную библиотеку Python.
[Evidence/пределы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-PRIMITIVES.md).

## Общий NID email request plan, 19 октября

vampir_core.nid_email содержит nid_js_string_bytes, encrypt_nid_field и
plan_nid_email_sign_in. Повторяет наблюдаемый charCodeAt/CESU-8, использует
RSA PKCS1v1.5 через optional cryptography и возвращает immutable plan со
скрытыми в repr URL/body/headers. Context/public key/captcha token передаются
явно; нет HTTP, cookies или хранения пароля. Android backend не проверен.
[Источник и локальные пределы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-EMAIL.md).

## GMC2 response envelope, 19 октября

Общий gmc2_response.decode_gmc2_configuration(body, headers) возвращает frozen
SdkConfiguration/read-only map, скрывает values в repr, не хранит DECKEY.
Real public response: 93 ordinary+1 secret=94 constants. Existing JSON/XOR/
secret-list/map reused, DER PKCS1/PKCS8 поддержаны, strict input budgets.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-PUBLIC-GMC2.md).
Нет I/O/account/session или native callback readiness claim.

## SDK constants pipeline correction, 19 октября

Existing sdk_constants.decode_sdk_constants_string повторно использует
unescape_sdk_utf16le и canonical gmc2_decode.xor_gmc2_utf16_units с zero omission.
Raw xor_sdk_utf16le сохранён как mathematical/pre-append capture transform,
не конечный decoder. Старые budgets сохранены; empty key reject уточнён.
[Регрессии и источник](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-UNESCAPE.md).

## GMC2 XOR primitive, 19 октября

Общий vampir_core.gmc2_decode.xor_gmc2_utf16_units: raw LE uint16 XOR,
повтор key без storage NUL, пропуск zero output units как в native append.
18 native fixtures совпали; empty key/type/size отклоняются. Нет Base64/JSON,
key acquisition или I/O. [Источник](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-GMC2-XOR.md).

## Offline GMC2 GET plan, 19 октября

Общий vampir_core.gmc2_request.plan_gmc2_get_request: explicit URL/service/
game/build/device, optional eTag/player/token; frozen tuple headers/repr redaction.
16 native captures совпали. Нет I/O/device creation/credential acquisition.
[Source и локальная input policy](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-GMC2-HEADERS.md).

## GMC2 URL assembly, 19 октября

vampir_core.sdk_config.assemble_gmc2_config_url_ascii собирает только строку
из явных base/group/sdk_version/build_code/market. 26 native fixtures совпали.
Не нормализует слэши/не экранирует/не выполняет HTTP; printable ASCII subset,
4096 chars fragment/result. [Доказательства](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-GMC2-URL.md).

## SDK BuildCode selector, 19 октября

Общий vampir_core.sdk_config.select_sdk_build_code принимает явный byte int:
1→B, 2→C, остальные→A; bool/вне диапазона отклоняются. Все 256 значений
совпали с native getter на compiled initializer defaults. Активный BuildCode
не угадывается по Zone/версии. [Доказательства](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-BOOTSTRAP-VALUES.md).

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
| Экранный бот и карта | [Vampir TASKS](../vampir/TASKS.md), [MAP-ATLAS](../resource-tools/vampir/knowledge/evidence/maps/MAP-ATLAS.md) |

## Восстановлены PAK-каталог и packed Game config, 19 октября

Generated key callback исполнен native; SHA1 расшифрованных main/full directory
совпали. Получены directory-backed имена 7067 файлов и DefaultGame.ini +
WindowsGame.ini в отдельном immutable снимке. Найдены NetworkSetting defaults:
CDN bases без scheme, AppVersion 0.1.1, prefix dev, CdnConfig=False.
Это packed layers, не доказанные active settings; overrides ещё открыты.
[Источник, SHA, исправление record hash semantics](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-PAK-CONFIG-RECOVERY.md).
Ключ подтверждён хешами каталогов; сетевые запросы ещё не выполнялись.

## Предыдущий поиск актуального источника CDN, 19 октября

CDN-derived candidate не подтвердился для encrypted directory. У encrypted
records SHA1 относится к ciphertext: прежнее сравнение с plaintext не проверяет
ключ. 23 records пропущены по bounds, compressed payloads не проверялись. Восемь plain records прошли hash controls.
Три EncryptionKey name xrefs сохранены как clues без доказанной PAK-связи.
[Источник, воспроизведение и ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-SOURCE-PROBE.md).
Этот прежний probe не восстановил key/config; новый результат описан выше.

## Выбор сервера и поля лобби из CDN, 19 октября

Установлено назначение 145661a70: _SetServerList. select_server/type выбирает
первый ASCII-case-insensitive match в server_list. Читаются detail/lobbyAddress,
lobbyPort, patchURL, dataURL. 31 replay, включая целую функцию для 30 входов.
Общий select_cdn_server возвращает отдельный raw detail plan без globals;
missing fields — None, без наследования адресов другого аккаунта.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-SERVER-LIST.md).
Реальные config values, пригодность endpoint и подключение ещё не проверены.

## JSON CDN и поле окружения SDK, 19 октября

12 native slices уточнили parser/object → fallback/ReadJson и обязательную
следующую validation. Общий decode_cdn_config_document разбирает plain либо
AES-encrypted JSON; read_cdn_sdk_environment читает NetmarbleS/Zone без default.
Проверена offline цепочка whole HTTP body → JSON → Zone → SDK mode.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-JSON-FLOW.md).
Полный ReadJson/secondary validation, actual settings/TLS ещё открыты.

## Запасная расшифровка CDN, 19 октября

Найдена fallback-ветка: IV16 + AES-256-CBC, key = SHA256 от compiled seed.
21 native orchestration replay проверяет аргументы, descriptor и error cleanup;
SHA/EVP primitives — явные backend shims, native crypto core не исполнялся.
Общий decrypt_cdn_fallback возвращает bounded raw bytes через optional crypto.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-FALLBACK.md).
JSON acceptance/реальный config/settings/TLS и HTTP compression ещё открыты.

## Декодирование тела CDN и BOM, 19 октября

31 native body replay и 9 status-gate slices подтвердили BOM-ветки и вход
в CDN body branch для 200–299. Найдено чтение UTF-16LE за длиной тела на
искусственных guard fixtures; общий код его не повторяет: строгий bounded
UTF-8/UTF-16LE decoder, корректные surrogate pairs, запрет NUL, лимит 2 МиБ.
[Источники, SHA и отличия](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-BODY.md).
Сжатие/chunked/EOF/полный JSON callback/settings/TLS ещё открыты.

## Content-Length и полнота тела CDN, 19 октября

30 native сценариев подтверждают lookup/atoi/unsigned receive comparison;
ещё один folded-field fixture остановлен по лимиту инструкций.
Общий take_cdn_length_response ждёт полное тело по одному Content-Length,
с локальными ограничениями 2 МиБ/status 200/без compression, range и chunked.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-RESPONSE-LENGTH.md).
Полный parser/receive loop, остальные framing/decode и JSON ещё не готовы.

## Начальный разбор ответа CDN, 19 октября

52 native сценария подтвердили CRLFCRLF boundary, статус из первых 12 байт
и число уже доступных байт тела. Общий cdn_response.py разбирает только head
со строгой локальной HTTP/1.x политикой и лимитами; полнота тела не заявляется.
[Источники, SHA и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-RESPONSE-HEAD.md).
Повторный аудит установки совпал со снимком обновления: 34 изменённых архива,
один новый, EXE прежний. TLS/body/JSON/actual settings ещё открыты.

## Полный базовый CDN GET header, 19 октября

Native URI/context/header pipeline проверен на 7 default и 4 override сценариях.
Default: GET/1.0, Host с port, Aqua/1.0 и конечный CRLF; пустые body/query/cookie/
range, без Content-Length/Type/Connection. Общий encode_cdn_get_headers и
Draft.header_bytes совпали побайтно с native. [Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-HEADERS.md).
Transport/TLS/response и actual settings/late overrides пока открыты.

## URI parser и строка CDN запроса, 19 октября

22 native URL→URI→GET-line сценария подтвердили scheme/host/uint16 port/path.
Общий parse_cdn_uri_ascii поддерживает строгий ASCII subset; 16 совпадений,
6 native quirks отклоняются. Draft хранит parsed URI и даёт request_line bytes,
без полного HTTP. [Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-URI.md). Реальные settings/headers/TLS/
response всё ещё открыты; network_ready=false.

## HTTP defaults CDN и offline draft, 19 октября

16 native сценариев подтверждают constructor→method 1→GET request line HTTP/1.0,
с пустой query collection и явными parsed-path fixtures. Общий cdn_request.py
даёт immutable draft URL/GET/1.0 со строгой локальной проверкой HTTPS; HTTP нет.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-HTTP.md). Полные headers/body/TLS/response и реальные values
ещё не проверены; native default не выдаётся за готовый сетевой клиент.

## Подготовка CDN версии и Windows platform, 19 октября

15 native replays подтверждают AppVersion dot→underscore. Исполнена цепочка
compiled platform initializer→vtable getter→code 2→window; ещё 7 ветвей проверены
с return-value fixtures. Общий prepare_cdn_config_url_ascii собирает URL из
явных normal/qa/prefix/app_version/platform_code, без HTTP.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-PREPARATION.md). Actual config values и request semantics ещё открыты.

## Сборка CDN URL из фрагментов, 19 октября

16 native сценариев подтвердили завершающую сборку base+platform/prefix/version/
config.json, включая std::string growth/move. Общий assemble_cdn_config_url_ascii
принимает явные готовые ASCII-фрагменты, без HTTP и преобразования AppVersion.
[Source/SHA/границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-URL.md). Реальные базы, version preprocessing и platform getter
ещё требуют проверки; действующий адрес не заявляется.

## Выбор CDN по ConfigPrefix, 19 октября

16 native сценариев подтверждают поиск подстроки real без учёта ASCII-регистра:
она выбирает CdnConfigUrl, иначе CdnConfigUrlQA. Это отличается от точного
сравнения SDK Zone. Общий select_cdn_config_base требует явных prefix/normal/qa.
Config loader связан с логической конфигурацией Game; текущие URLs неизвестны.
[Доказательства и ограниченный поиск в pakchunk0](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CDN-SELECTION.md).

## SDK settings и game override, 19 октября

Подтверждены 9 полей NMSDKSettings и начальные значения (4 native replays).
Найдена игровая InitSetting: compiled globals market nmp/game thered/client ID,
13 native сценариев сравнения environment → production при real без учёта ASCII
регистра, иначе Dev. Общий select_game_sdk_zone требует явного environment.
[Источники, SHA и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-SETTINGS.md). Активный environment и его загрузка пока неизвестны.

## Общий код

`sdk_constants.py:xor_sdk_utf16le` — отдельный XOR 16-битных единиц GMC2,
с ограничением входа/ключа и сохранением нулей/суррогатов. 42 native проверки
и пять тестов: [доказательства](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-VALUES.md).
Модуль также разбирает содержимое JSON-строки перед XOR, отклоняет неверные
escape и сохраняет UTF-16 единицы. 43 корректных и 7 граничных native входов,
три составных примера: [ответ GMC2](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-UNESCAPE.md).
Получение ключа, извлечение полей ответа и проверка схемы ещё не реализованы.
`decode_sdk_base64` в том же модуле декодирует один ciphertext, до 2048 символов,
с каноническим padding или без него. 26 корректных native входов и 8 граничных;
[RSA-параметры и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-SECRET.md).
`sdk_secret.py:decrypt_sdk_secret_chunk` расшифровывает один secret chunk
с явным телом RSA-ключа; optional cryptography backend загружается при вызове.
Windows проверен на искусственных ключах, native OAEP — 24 корректных / 69
ошибочных входов. [Доказательства и лимиты](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-OAEP.md).
`decode_sdk_secret_constants` собирает список расшифрованных элементов в JSON,
проверяет типы/UTF-8/повторные ключи и отклоняет весь результат при ошибке.
9 основных / 4 граничных native сценария orchestration, шесть тестов:
[список и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-SECRET-LIST.md).
`sdk_config.py` объединяет уже строковые normal/secret карты с приоритетом
secret и читает значение по native HTTP(S) prefix check. 24 lookup / 3 replacement /
5 hash native сценариев: [доказательства](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-MAP.md).
Stringify прочих JSON-типов, весь callback → SDK map и Android ещё открыты.
`append_sdk_path` повторяет native path concatenation (70 сценариев),
`auth_request.py:bind_token_request` связывает code/refresh form с явным
authTokenUrl. URL/body скрыты в repr; нет HTTP или автоматического выбора адреса.
[Правила и локальные ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-PATH.md).

`auth_request.py` создаёт offline TokenRequestPlan для code/refresh grants,
explicit authTokenUrl config key/relative v2/access-token, bounded printable ASCII.
24 SDK roots/512 native byte primitive calls: [доказательства](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-AUTH.md).
Нет получения/отправки credentials, browser login, HTTP или game session.
Источник конфигурации исследуется отдельно: [GMC2](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-CONFIG.md).
Адреса и активный режим не зашиты в runtime по наличию строки в EXE.

`socket_send.py:drain_outbound` — bounded send на уже подключённом nonblocking
socket; `OutboundFrames.peek_frame/consume_sent` сохраняют partial tail.
61 native cases/5 tests и real local IPv4 TCP: [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SEND-DRAIN.md).
Connect/auth/readiness scheduler и session lifecycle пока не реализованы.

`send_frame.py` содержит send-B encoders Ping/KeyChanged с explicit key/sequence.
`outbound.py:OutboundFrames` ограничивает bytes/frames, хранит immutable ciphertext,
ставит key ack под старым ключом до переключения следующего кадра.
40 native cases/5 tests: [доказательства и локальная error policy](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SEND-B.md).
Это не socket transport; один session owner, без thread safety/авторизации.

`receive_frame.py:take_receive_b_frame` / `receive_packet.py:decode_game_ping_result_b`
используют явный unsigned64 peer key, не выполняют session bookkeeping.
39 native cases: [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-RECEIVE-B.md).
Input immutable, body policy exact, raw transport layer обрабатывается отдельно.

`receive_packet.py:decode_game_ping_result` — один receive-A game PingResult ID17,
body 12, явный frame limit. Exact body policy строже native trailing tolerance.
24 native Dispatch scenarios: [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-DISPATCH.md).
Без игровых OnHandler side effects и без универсальной registry для lobby/game.

`receive_frame.py:take_receive_a_frame` — один полный receive-A кадр:
length probe + fallback XOR, header сохраняется, вход не меняется.
44 native loop cases и 5 tests: [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LISTENER-LOOP.md).
Не raw transport, не CRC/packet schema; управление сессией ещё не реализовано.

`vampir_core/transport_header.py` — первый уровень приёма: size 23, признак
сжатия и извлечение кадра с явными input/output limits. [Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-TRANSPORT-STAGE.md).
`block_decode.py` распаковывает literals/matches с ограниченным output;
166 valid / 86 invalid native проверок: [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-BLOCK-DECODE.md).
`take_transport_frame` поддерживает обе ветки skip=3. `receive_frame.py` относится
к следующему уровню; применять его прямо к raw stream нельзя.

`vampir_core/key_change.py` — общие IDs11/12 и raw64codec уведомления/подтверждения
смены ключа, repr скрывает значение. [Доказательства и порядок вызовов](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-KEY-CHANGE.md).
Управление сессией и отправка подтверждения пока не реализованы.

`vampir_core/receive_frame.py` — проверка полноты входящего кадра с явным
лимитом и защитой от недопустимой длины; [источники и отличия от клиента](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-RECEIVE-ENVELOPE.md).
Это ещё не packet decoder или CRC validation.

`vampir_core/send_frame.py` — сборка полного исходящего Ping кадра send-A;
[доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SEND-FRAME.md).
Приёмный decoder и подключение пока не реализованы.

`vampir_core/frame_primitives.py` — подтверждённые CRC32 и XOR helpers;
это не полный frame encoder. [Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-FRAME-PRIMITIVES.md).

Первый модуль — `vampir_core/ping.py`, payload encode/decode для Ping/Result.
Только стандартная библиотека Python; импорт `vampir_core.ping` одинаков для
всех потребителей. Package root — `vampir-shared`; тесты подключают его через
sys.path. Упаковка Windows/Android ещё не реализована. В сетевом боте второй
копии нет. Сам модуль не подключается к серверу и не запускает игру.

Доказательство/версия: [HEADLESS-PING-CODEC.md](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-PING-CODEC.md).
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
