# Vampir — общие компоненты и результаты

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
