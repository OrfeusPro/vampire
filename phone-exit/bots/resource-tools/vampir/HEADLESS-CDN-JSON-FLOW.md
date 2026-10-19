# CDN: JSON, fallback и окружение SDK, 19 октября 2026

После [расшифровки envelope](HEADLESS-CDN-FALLBACK.md) общий код связывает полное
тело ответа с обычным/зашифрованным JSON и извлечением NetmarbleS → Zone.
Это offline decoding и выбранное поле; весь ReadJson, следующая native
проверка и применение полной конфигурации ещё не реализованы в общем ядре.

## Источник и проверка ветвей

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект.
Инструмент: [build-headless-cdn-json-flow.py](build-headless-cdn-json-flow.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-json-flow.py`.
Capstone 5.0.6/Unicorn 2.1.4 закреплены в analysis environment.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-json-flow.json`.
SHA256: `b5db41e7874e797bf15e575765d6df9b4465db9d9ee8f26ac39b98bb53147017`.
Записаны source/tool/prior hashes, инструкции/offsets/bytes и 12 native slices.
JSON parser, ReadJson и дополнительная проверка имеют явные return fixtures.
Сами эти функции целиком **не исполнялись**; их roots сохранены статически.

| Участок | Что исполнено и подтверждено |
|---|---|
| `0x145642c79..0x145642c88` | Parser result AL и object pointer: только true + nonnull → ReadJson, остальные три комбинации → fallback |
| `0x145643107..0x145643146` | Настоящие аргументы вызова ReadJson: config object и адрес JSON shared pointer |
| `0x145643110` → `0x14565a5d0` | Return fixture ReadJson false переводит в error branch и обнуляет result flag |
| `0x14564311e..0x14564312f` | После true ReadJson native копирует byte object+0x1a1 в global; назначение byte ещё неизвестно |
| `0x145643135` → `0x145661a70` | Вторая проверка с теми же аргументами: false → error, true → следующий участок `0x145643213` |

Четыре parser-result комбинации и восемь read/validation/byte комбинаций
воспроизведены. Следующий участок ещё содержит request-state/platform/lifecycle
ветви; достижение `0x145643213` не доказывает успешный полный callback.
По этим fixtures нельзя утверждать, какие реальные JSON native parser принимает.
Связь ReadJson с Zone ранее подтверждена отдельно:
[HEADLESS-CDN-CONFIG](HEADLESS-CDN-CONFIG.md).

## Общий модуль

[cdn_config.py](../../vampir-shared/vampir_core/cdn_config.py) предоставляет:

- `decode_cdn_config_document(complete_body)` → Python dict. Сначала plain body
  проходит уже проверенный BOM/text decoder и JSON parser. При ошибке text,
  синтаксиса или не-объектном root пробуется raw-body AES fallback. После него
  используется UTF-8, без повторного угадывания UTF-16LE и удаления BOM.
- `read_cdn_sdk_environment(document)` → точная строка NetmarbleS/Zone.
  Не подставляет dev при missing/wrong type. Результат передаётся существующему
  `select_game_sdk_zone`: real без учёта ASCII-регистра → 2, остальные строки → 1.

Plain path не загружает crypto backend. Fallback использует optional crypto
предыдущего этапа. SDK selector не отправляет HTTP и не меняет состояние клиента.
Сам dict сохраняет остальные поля для дальнейшего исследования, без их
семантической валидации и без присвоения статуса «готовая конфигурация».

**Локальная политика JSON:** корень dict, точные имена section/key и object/
string types, запрет duplicate keys, NaN/Infinity/nonfinite float, строк с NUL
и невалидными surrogate escapes. Лимиты: body 2 МиБ, structural depth 64,
65536 items (включая keys/values), numeric token 128 символов. До JSON parsing
выполняется ограниченный structural scan с учётом строк/escape; после него —
итеративная проверка полученных значений. Это не найденные лимиты игры.

Нарушение этих JSON policy правил отклоняется без повторной попытки crypto.
Invalid body text/syntax/root выбирают fallback; invalid encrypted document
завершается ошибкой. Сообщения не включают содержимое. Empty object остаётся
синтаксически допустимым dict, но extraction Zone для него завершается ошибкой.

## Проверки и продолжение

Семь тестов проверяют source/instructions, все 12 native branch replays,
plain UTF-8/BOM/UTF-16LE без crypto, полный HTTP → encrypted JSON → Zone → SDK
selection, ошибки encrypted JSON, отсутствие обязательного поля, exact-name
policy, Unicode/duplicates/numbers/depth/items/body limits и trailing bytes.
Данные только искусственные; реального CDN запроса и входа аккаунта не было.

Далее: содержание всего ReadJson и проверки `0x145661a70`, реальные config
values/URL и полный startup order, native crypto primitives/Android backend,
TLS и остальные HTTP response modes. `network_ready=false`.
