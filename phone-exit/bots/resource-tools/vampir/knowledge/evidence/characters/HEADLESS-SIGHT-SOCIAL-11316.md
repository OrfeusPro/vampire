# CharacterOther: GuildTinyInfo и PartyTag

EXE 1.13.16, полный SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это вложения [начального SightEnter](HEADLESS-SIGHT-ENTER-CONTRACT-11316.md),
не полный CharacterOther и не подтверждение видимости другого игрока.

## Полные записи

| Запись | Constructor | Reader | Vtable | Native object |
| --- | --- | --- | --- | --- |
| PktGuildTinyInfo | 145799940 | 14579c6b0 | 149920598 | 60 hex |
| PktGuildEmblemInfo | 1457904d0 | 145794bc0 | 149920550 | 10 hex |
| Time wrapper | 1457a3500 | 1457fdce0 | 14991f3b8 | 10 hex |
| PktPartyTag | 1457a2350 | 1457a5770 | 149921be0 | 50 hex |
| PktPartyOptionData | inline in PartyTag | 1457a5520 | 149921b98 | 28 hex |

Guild wire: `u64; UTF8 string; u32; 4 × u16; u64; byte; u64; bool`.
Byte clamp 6. Time wrapper хранит последний raw uint64; timestamp / timezone /
единицы не назначаются. Минимальная длина — 40 bytes плюс UTF8 payload строки.
String — u16 encoded byte length и соответствующие UTF8 bytes.

Party wire: `u64; string; PartyOptionData; bool; byte; u32`.
Вложенные options: `byte,byte,byte; string; bool,bool`, clamp 3 / 102 / 8.
Внешний byte clamp 3. Минимальная длина — 23 bytes плюс payload обеих строк.
Любой ненулевой wire bool становится true. Смысл enum / scalar не выводится
из величины или имени поля интерфейса.

`sight_social_records.py` возвращает immutable `SelectionRecord` с native offsets.
Guild+28 — вложенная эмблема; time+48 развёрнут в payload Guild+50.
Party+20 — вложенные options. uint64 сохраняются без float-преобразования;
никакой связи с HP, координатами или идентификатором управляемого персонажа нет.
Требуются точный source SHA и immutable bytes, максимум 64 KiB на запись,
полное потребление тела. Некорректный UTF8, NUL, U+FFFE / U+FFFF отклоняются
по действующей общей политике текста. Это ограничение portable, а не заявление
о совпадающем отказе native на любом некорректном UTF8.

## Проверка

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_social_11316.py
```

9590 native сценариев: два whole constructor / reader пути с emblem / time /
party options, настоящий archive/input и native UTF8 → UTF16. Пустая строка,
ASCII, кириллица / emoji, длины 15 / 16 / 31 / 255, zero / high / maximal uint64,
bool 0 / 1 / 255 и все 256 enum bytes. Для выбранных крайних enum проверен
каждый префикс тела, включая границы encoded length и многобайтных строк.
Сопоставлены acceptance, cursor, FString descriptor / terminator / ownership,
значения строк / scalar / emblem и guards packet / input / archive / allocations.
Native trailing byte оставляет cursor на конце записи; portable требует точный
конец. Guard-тесты отдельно проверяют malformed UTF8 / text policy, byte limit,
mutable input, неверный SHA и точность 64-битных значений.
Portable также проверен на Guild body ровно 65536 bytes; максимальная строка
этого теста не выдаётся за native replay максимального UTF8 payload.

Fixtures — свежие пустые владельцы FString / std::string, ограниченное выделение
памяти, assign / free и проверка stack cookie. Для Guild разрешён только string
destination +10; для Party +10 / +30. Native UTF8 readers / converter не заменены
готовой Python-строкой. Allocator, прежнее хранилище, reuse и engine effects не
подтверждены. Сеть и игровой вход не запускались.

В harness добавлен отдельный scope `sight-social-records`: ровно 21 функция,
до 10 source-bound exports. Имена / адреса context и фактический набор должны
совпасть; произвольный scope и замена reader отвергаются отдельным тестом.
Прежние budgets не расширены. Контекст и полные SHA:
[sight-social-11316.json](../../native-contexts/sight-social-11316.json).
Проверка зарегистрирована как `live-sight-social-11316` с явными зависимостями
кода, string fixtures, pinned Capstone / Unicorn и exports.

Три теста прошли. Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sight-social-11316/f76e889c909921115ed53cfa06a03d9f7ec6684dacf7201a1fc4ebfda867e3c8/manifest.json`.
SHA256 отчёта — `f76e889c909921115ed53cfa06a03d9f7ec6684dacf7201a1fc4ebfda867e3c8`.

Следом — целые CharacterOther / Gadget, затем mixed-array SightEnter с общим
бюджетом, handler / actor / world связью и начальной моделью окружения.
Ранее проверенные [effect records](HEADLESS-SIGHT-EFFECTS-11316.md) и
[projectile array](HEADLESS-SIGHT-PROJECTILES-11316.md) используются как зависимости.
Runtime ID 301 пока не подключён, [NPC subset](HEADLESS-OBSERVED-ENVIRONMENT-11316.md)
остаётся partial. Общая цель и живая multi-account проверка не завершены.
