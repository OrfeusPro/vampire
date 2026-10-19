# Token payload и channelKey migration path

19 октября 2026. Продолжение [NID suffix](HEADLESS-SDK-NID-SUFFIX.md).
Источник — Windows EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Использованы код/данные клиента, не исходный C++ проект или реальные токены.

## Token container caller

Инструмент `replay-sdk-token-payload.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-token-payload-replay.json`,
SHA256 `abcea122600cdb7678b0124e2396af54d03a04fd30c41e7bff00e6820219937e`.
Сохранены source fragments с bytes/file offsets/SHA, literals и tool SHA.

Полный native caller `0x144537b20`:

1. Вызывает split по `.` с bool=true; требует ровно три элемента.
2. Для каждого из трёх рассчитывает padding до кратности4; если нужно3 символа
   padding (длина mod4=1), отклоняет весь container до decode.
3. Дописывает 0/1/2 символа `=` в каждый сегмент.
4. Декодирует только первый и второй сегменты, превращает их в JSON и проверяет
   object gate. Второй объект хранится по output+`0x38`.

Native sequencing/count/padding/branches исполнены в 16 fixtures.
**Split, base64url/UTF-8 decode, JSON parse/assignment/IsObject — fixtures.**
Это не исполнение полного parser stack. Empty-segment/cull semantics не доказаны.
Нельзя обобщать Python decode policy fixture на весь native decoder.

Static wrapper `0x14451d4e0` заменяет `-` → `+`, `_` → `/`, затем вызывает
base64 helper `0x1415230c0`. Source этих calls сохранён, но wrapper здесь не
исполняется. Native JSON object helper source также сохранён отдельно.

Fixtures проверили: 2/4 сегмента и неверные mod4 длины отвергаются; не-объекты,
невалидный base64/JSON в header не проходят при заданных fixtures. Объект payload
без sub, header alg=none и синтаксически непригодный для base64 третий сегмент
при подходящей длине **не мешают true outcome этого caller**.
Третий сегмент не декодируется и не передаётся на проверку подписи в данном helper.

Следовательно, true означает лишь успешный локальный разбор контейнера в рамках
данного контракта. Не означает действительность подписи, alg, expiry, issuer,
sub, server acceptance или активную session. Проверки в других слоях SDK
этим не исключены. Общий runtime не получил parser, принимающий это за login proof.

## Поле миграции отличается от sub

SetupServiceSettingPath `0x14454c7a0` после разбора container имеет ветвь config
`bUseMigration` (fixture/default в source задаётся до config lookup).
Проверяет presence поля global `0x14b4f1a28`; initializer `0x1411b31c0`
связывает его с **channelKey**. Это подтверждённый ключ объекта, не догадка по ID.
Строка сохраняется в global `0x14b4f1ec0`; GetNMDeviceKey задаёт отдельный key.
Новая NID path ветвь использует **sub**, описанный в предыдущем справочнике.

Инструмент `replay-sdk-channel-migration-path.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-channel-migration-path-replay.json`,
SHA256 `3e2007c90553a656e98d69fba8c70fa512d7d29f4f23466eb0167faaeb541d96`.
Переиспользует source-bound Setup/AES/formatter fragments из NID suffix report
и записывает его SHA. Native slice `0x14454c9a1..0x14454cac1`:

- Размер channelKey округляется вверх до кратности16.
- Native loop переносит low-byte каждой wide unit минус1 в byte buffer.
- Native AES-NI и byte-hex writer формируют строку в global `0x14b4f1ed0`.

Восемь fixtures: длины0/16/17/32 × allocation fill00/AA. Обе aligned непустые
длины дают одинаковый результат независимо от fill и совпадают с независимым
AES-256 ECB. Для длины17 caller пишет первые17 bytes, а оставшиеся15 bytes
зависят от **allocation fixture**; результаты fill00 и AA различаются.
Сам allocator `0x141431680` не исполнен, его initialization contract неизвестен.
Поэтому это не доказательство утечки/случайности в игре и не готовая модель
padding миграции. Нельзя молча считать tail zero-padding или PKCS7.

Сохранён тот же честный scope AES replay: dispatch pointer закреплён на AES-NI,
реальные rounds/key expansion исполнены; ANSI conversion/formatting/allocation/
FString helpers — явные fixtures. bUseMigration/presence/read/token parsing,
перемещение файлов и весь Setup entry этим slice не исполняются.

## Состояние и далее

Теперь разделены три задачи: container decode, account-related suffix из sub,
отдельный channelKey migration path. Ни одна из них не заменяет server auth.
Реальные command line, tokens, keys, профили Saved, registry и сеть не читались.
Локальный реестр основной почты не изменён и остаётся без реальных identity values.

Далее: source allocator tail contract и migration config/lifecycle, более полный
token decode/JSON/object binding, затем SaveGame parsing и SDK sign-in response.
Не повторять уже проверенный AES/HEX primitive без изменения EXE или новых границ.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_token_payload.py' -v`.
Три regression tests воспроизводят отчёты, 16 container и 8 migration fixtures,
проверяют independent AES comparison и границы недоказанного padding.
