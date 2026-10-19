# ID102: вложенные схемы, обработчик и предпочтительный индекс

Продолжение: [ID109 callers, источники полей и полный send frame](HEADLESS-CHARACTER-SELECT-SEND.md)
теперь проверены offline. Следующий участок — ID110/lifecycle/реальная сессия.

20 октября 2026. Продолжение [первичного body codec](HEADLESS-CHARACTER-CODECS.md).
Ранее неподдерживаемые ветви appearance array и optional map теперь разобраны и
проверены native-исполнением целых ID102 bodies. Обработчик ID102 проверен после
native reader в том же emulator. Сеть, реальный аккаунт и игра не запускались.

## Происхождение

Код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 106 функций, 53 предупреждения.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-574520ca2499`.
Manifest SHA256 `3324f96c4782b1e043f8fdc88740a57ed230d283e2132f9c0bdc4ea701824375`.
Адреса и выводы привязаны к этому SHA; псевдокод — восстановленное представление
кода клиента, не исходный C++ проект.

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Отчёт | SHA256 | Сценарии |
| --- | --- | --- |
| character-list-extensions-replay.json | `b723a487302d105dd1303f91ee69bad3ad3749beb8ad1973c8e1fedf470a70cb` | 30 full bodies, 489 short prefixes |
| character-list-handler-replay.json | `948a33a6a57e56bbe526da39bf3a026d0a3f452e317b991459a8d876371ac7ad` | 45 body→handler cases |

Оба отчёта содержат SHA генераторов, зависимостей и upstream evidence. Исходный
EXE проверяется перед исполнением; Capstone 5.0.6/Unicorn 2.1.4 закреплены и
проверяются существующим emulator. Инструменты и EXE не входят в runtime бота.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-extensions.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-handler.py
python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_character*.py' -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py -v
```

Проверка: 17 character tests и 3 Ghidra provenance tests прошли; проверяется
повторное получение отчётов, а не только чтение сохранённых результатов.

## Appearance extension array

Record+`0xb0` → reader `0x1457812a0` → callback table `0x1498ef500`.
Array resize `0x1456b60e0`; item callback `0x145737650` создаёт item через
leaf `0x14576f080`. Item table `0x1498cff58`, reader slot20 `0x145771b40`.

После уже проверенных appearance fields: uint16 count, затем для каждого item:
`<IBH` — raw uint32, byte enum с clamp до 45, raw uint16. Item stride в памяти
0x10; wire item имеет ровно 7 байт. Имена enum/назначения полей не угаданы.
Actual callback/constructor/item reader/archive IO проверены вместе с packet/
record reader, а не отдельно подменёнными decoded objects.

## Optional map

Record+`0x110` → table `0x1498d1b90`/reader `0x1456bf640`:
normalized presence bool; при true uint16 count и записи map.
Absent и present-empty различаются. Callback table `0x1498d5038`, callback
`0x1456c3890`, insert `0x1456b99b0`, pair constructor `0x1456b7b90`.

Ключ — raw uint8, без enum clamp. Pair constructor устанавливает value table
`0x1498d1a28` в node+8. Value constructor `0x14577dd50`, reader `0x145782b30`.
После ключа value содержит byte enum clamp≤9, три raw uint32 и вложенный
TimeBase raw uint64. Полная запись wire — `<BBIIIQ`, 22 байта. Память node имеет
stride0x38, padding/vptr/bucket links не передаются по wire.

Actual callback ищет существующий ключ по hash chain. Повторное значение
перезаписывает прежнее, без вставки второго node; общий decoder использует
last-value-wins. Проверены ключи 0/255, коллизии, rehash, повтор до и после
rehash, uint32/64 границы, present byte255 и смешанные appearance+optional bodies.
Счётчик вставок отдельно подтверждает отсутствие нового node при повторе.

Native callback/insert/pair/value constructors/readers исполняются. Выделение
массивов/map, reset, bitvector capacity, predicate вставки заведомо нового ключа,
rehash buckets, shallow record copy и cleanup — явные ограниченные fixtures.
Native allocator/lifetime/реальный UObject registry этим не проверены.

## Общий decoder

`vampir_core.character_list.decode_character_list` теперь читает обе ветви.
Прежний `UnsupportedCharacterExtension` удалён. Обязательны три локальных лимита:
`max_payload_size`, `max_characters`, `max_extension_items`. Последний — общий
на весь body, учитывает appearance и все wire map entries, включая повторы.
Бюджет проверяется до создания коллекции. Отдельные oversized counts не обходят
лимит за счёт схлопывания одинаковых ключей.

`CharacterRecord.appearance_items` — tuple троек `(raw32, clamped_byte, raw16)`.
`optional_items` — None для absent, иначе tuple записей
`(key, clamped_byte, raw32, raw32, raw32, raw64)`, отсортированных по raw key.
Это детерминированное представление map, не исходный порядок пакета. Строки,
числа и коллекции decoder выдаёт неизменяемыми, поля записей скрыты из repr.
Строгие UTF-8/NUL/text policy и exact body consumption сохранены.

## Handler ID102 и выбор индекса

Handler `0x14675dce0`, native result gate `0x1467a8e10`, selection predicate
`0x145c85d90`. 45 сценариев исполняют reader→gate→predicate→handler вместе.
В covered cases code0 проходит gate, десять проверенных error codes не проходят.
Проверенные ошибки: 1/14/22/37/54/9400/9818/9819/90021/0xffffffff.
При gate false handler вызывает service virtual38 и не применяет список.
При gate true список применяется только при predicate==1; policy0/2/4,
disabled lookup и отсутствующий policy object оставляют state без изменений.
Type metadata/policy virtual в этих сценариях — fixtures.

При применении handler пишет count/state+78 и переносит записи в state+70;
capacity/copy/cleanup helpers захвачены. Native stores также связывают
packet+30 → state+80 и low32(packet+28) → state+84; packet+40 передаётся helper
`0x145c930d0` (capture). Отрицательный signed packet+28 вызывает warning helper.

Предпочтение — packet+38, сравнение с record+8. Sentinel по actual constant
`0x14961a378` равен **0**: при нуле поиск пропускается. Для ненулевого ключа
берётся первое совпадение, при отсутствии совпадения остаётся индекс0.
Проверены first/middle/last/missing, duplicate record keys и нулевой record key.
Native UI store `UI+3f8` проверен, отсутствие UI не блокирует остальные действия.
Даже для пустого списка native UI stores index0.

Далее covered путь вызывает owner virtual+a00 (если owner есть), UI finish,
selection helper с **DL=6** и transport setter с 0. Верхние биты RDX для события
не являются аргументом: реальная инструкция перед вызовом — `mov dl,6`.
Сами UI/owner/event/transport backend actions остаются captures.

Общий `preferred_character_index(body)` повторяет правило поиска после
acceptance/policy gates. Он только предлагает индекс; ничего не отправляет и не
объявляет readiness. Явная локальная политика: для пустого списка и error code
возвращает None, чтобы native UI index0 не стал выбором несуществующей записи.
Функция не заменяет session gates. Идентификаторы/имена enum/координаты из
сходства offsets не выводятся.

## Что дальше

ID102 body и covered handler теперь проверены offline, но цепочка входа ещё
не завершена. Следующие обязательные участки: источники трёх raw полей ID109,
реальный caller service virtual50 и его gates; request handoff→ID109 frame;
ID110 nested body/handler и источник позиции; owner hook slot7b0→engine
lifecycle/CharacterSelect_02; actual SDK/device context и подтверждение устройства.
Ни один из этих пунктов нельзя считать закрытым по успешному body decoder.
