# SightEnter: полный optional projectile array

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [вложений SightEnter](HEADLESS-SIGHT-EFFECTS-11316.md).
Optional array packet+50 разобран и проверен native целиком; внешний SightEnter,
остальные массивы и actor / world применение этой проверкой не подтверждены.

## Цепочка и wire

Reader `1456c2f60` читает bool, а при true — vector через descriptor `149924f00`:
`141b0aa50 / 1456d1f70 / 1456c64b0`.
Callback создаёт `PktProjectileCircleData` constructor `1457a2590`,
vtable `149922390`, reader `1457a5c80`. Внутри — `PktProjectileData`,
vtable `149922348`, reader `1457a5cd0`; native stride внешней записи — 98 hex.
После записи callback исполняет настоящий cleanup `1457a38a0`.

Projectile wire — 53 bytes:
`u16; u32,u32,u32; u64; float32 XYZ; u16; byte yaw; u64; u32; float32`.
Circle добавляет ещё float32 XYZ — 65 bytes всего. Значения и единицы последних
scalar / vector не названы по величине. Внешний optional wire:
`bool; if true: u16 count; count × Circle`.
Ненулевой bool означает присутствие, включая 255. Отсутствие — одно byte 0.

`sight_projectile_records.py` сохраняет immutable `SelectionRecord` с native
offsets; в Circle+8 вложен Projectile, в +80 — второй `WireVector3`.
Float Projectile+74 сохраняется как uint32 bits; yaw — как исходный byte.
Для XYZ требуется отдельная проверка finite. uint64 не переводится в float.
Декодер optional возвращает `None` при отсутствии и tuple при присутствии;
пустой tuple не смешивается с отсутствием. Повторы сохраняются в порядке wire.
Ни один из этих результатов не объявляется отсутствием NPC или игроков.

Декодеры требуют точный SHA и immutable bytes. Circle — ровно 65 bytes,
optional — не более 64 KiB; общий count limit 0–4096, по умолчанию 1024.
Length / count проверяются до создания записей. Trailing bytes отклоняются.
Для будущего общего SightEnter caller должен передавать оставшийся единый
бюджет всех массивов; такой caller пока не подключён.

## Native проверка

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_projectiles_11316.py
```

Три теста прошли. 1734 native сценария исполняют optional reader, generic vector,
resize, callback, constructors / nested readers / cleanup на одном memory,
настоящий input и XYZ / yaw math. Проверены absent / empty / present,
bool 0 / 1 / 255, counts 0 / 1 / 2 / 8 / 64, повторные максимальные uint64,
signed zero / nonfinite float bits, все 256 heading bytes. Для count ≤ 8
проверен каждый префикс выбранных тел, для 64 — выбранные границы.
Сопоставлены acceptance, cursor, optional presence, counts, vtables, scalar /
XYZ values и guards packet / input / archive / storage. Raw portable heading
сверен отдельно; native canonical yaw не выдаётся за исходный byte.
Native допускает trailing byte с остановкой cursor на конце записи; portable
намеренно требует точную длину. Guard-тесты проверяют неверный SHA, mutable /
truncated / oversized input, общий count limit и сохранение повторов.

Fixtures: только пустое прежнее хранилище, заранее ограниченное выделение
до 64 records, запрет неожиданного growth. Reuse / allocator / удаление игровых
объектов не доказаны. Yaw использует source SSE2 ветвь и реальные локальные UCRT
`atan2` / `fmod` с проверкой import descriptors; SHA DLL записан в отчёт.
AVX и иные dispatch paths не проверены. Сеть и игровой вход не запускались.

В `update-native-harness.py` добавлен только scope `sight-projectile-array`:
21 точная функция и до 12 exports. Список функций обязан совпасть и с context,
и с фактическим запросом harness. Ошибочный scope / подмена функции отклоняются
отдельным тестом; прежние бюджеты не расширены. Контекст и полные SHA:
[sight-projectiles-11316.json](../../native-contexts/sight-projectiles-11316.json).
Проверка зарегистрирована как `live-sight-projectiles-11316`, с зависимостями
кода, exports, pinned runtime и Windows UCRT / CRT locale.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sight-projectiles-11316/d1f51574854f6a24cc04b61d017cb475afeeef03102bfff53fce70beb95805e8/manifest.json`.
SHA256 отчёта совпадает с именем каталога.

## Остальные зависимости

Получены reader `14579c6b0` для GuildTinyInfo и `1457a5770` для PartyTag.
Последний вызывает PartyOptionData reader `1457a5520`: три byte с clamp
3 / 102 / 8, строка и два bool. GuildTinyInfo содержит GuildEmblemInfo,
уже известный time wrapper и строку. Полные Guild / Party readers ещё не
проверены native и portable. Gadget optional owner использует уже разобранный
`PktActorOwner` reader `145786290`; целый Gadget ещё не проверен.

Новые публичные exports в `ghidra/request-exports/<SHA>/` библиотеки ресурсов:

| Экспорт | SHA256 details.json | Состав |
| --- | --- | --- |
| run-329d82a6707a | bd0b0a53cec59754d2c7f454879fbc7d53ddd369fb5158e7a308f5fa1f8979fa | circle constructor, callback / resize, GuildTinyInfo / PartyTag readers |
| run-733995919a16 | 202e0cbd6be0f91a82662c6c844c2ea49b5dbfcaa54e46424dd1d9250ae36c48 | circle / projectile / PartyOptionData readers |
| run-bd28cc6bca2c | a87299f16e018ec74d205f90493df8f3e4e0480d06ed407ab54d245ca0c421f4 | circle cleanup |

Далее — GuildTinyInfo / PartyTag и полные CharacterOther / Gadget, затем весь
SightEnter с mixed arrays, общим бюджетом и handler / world связью. Runtime
ID 301 пока не подключён; [NPC subset](HEADLESS-OBSERVED-ENVIRONMENT-11316.md)
остаётся partial. Исследование initial visibility и общая цель продолжаются.
