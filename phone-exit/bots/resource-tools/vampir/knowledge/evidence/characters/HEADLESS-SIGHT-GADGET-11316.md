# SightEnter: полный PktGadget

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это четвёртый массив [SightEnter](HEADLESS-SIGHT-ENTER-CONTRACT-11316.md).
Whole Gadget проверен с настоящими вложениями; внешний SightEnter и actor /
world применение ещё не подтверждены.

## Reader и wire

Constructor `14578fe30`, reader `1457938b0`, vtable `1499218e0`, native object
d0 hex. Wire:
`u64; u32,u32,u32; float32 XYZ; byte yaw; bool; byte; u64; u32; byte;`
`u16 count; count × u64; bool optionalOwner; if true: ActorOwner; byte`.
Минимальная длина — 52 bytes. Два enum ограничиваются 5 / 3.
Последний byte сохраняется как исходный uint8, без bool / enum преобразования.

Массив object+78 читает wrapper `1456bb710`, generic vector и descriptor
`149924c90 = (141b0aa50,1456d2030,1456c6960)`.
Это массив raw uint64; семантика actor / target IDs именно в Gadget не установлена.
Не добавлять его значения автоматически в список видимых NPC / игроков.
Порядок и повторы сохраняются.

В object+88 находится optional wrapper `1456b7060`, vtable `1499218b8`.
При ненулевом flag он вызывает `PktActorOwner` reader `145786290`, vtable
`149921840`, в object+98. Wire owner:
`byte; u64; UTF8 string; u64`; byte clamp 9.
String — u16 encoded length и UTF8 bytes. Названия/единицы scalar полей не
угадываются, имя владельца не означает персонажа текущей сессии.

`sight_gadget_record.py` возвращает immutable `SelectionRecord` с native offsets.
XYZ сохраняет исходные float32 bit patterns через `WireVector3`, для координат
нужен `finite_values()`. Yaw сохраняет wire byte отдельно от native canonical yaw.
Owner — вложенная запись или `None`; uint64 не переводятся в float.
Source SHA обязателен, input только bytes, максимум 64 KiB. Общий count limit
0–4096, default 1024; конец тела должен совпасть точно. Malformed UTF8, NUL,
U+FFFE / U+FFFF отклоняются по общей portable text policy. Это не доказательство
одинакового native отказа на любой некорректной строке.

## Native / portable проверка

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_gadget_11316.py
```

Три теста прошли. 1891 native сценарий исполняет constructor / reader Gadget,
generic vector, настоящий resize / callback массива, optional wrapper / ActorOwner,
archive / input / native UTF8 conversion и XYZ / yaw math на одном memory.
Counts 0 / 1 / 3 / 8 / 64 / 128, повторы uint64, maximum / high bit values,
owner absent / present, пустое имя, кириллица / emoji и ASCII за границей SSO.
Все 256 yaw / enum bytes; исходный portable yaw проверен отдельно.
Для малых массивов проверен каждый префикс выбранных тел, для больших — выбранные
границы. Сопоставлены acceptance, cursor, vtables, все scalar / XYZ / vector /
owner values, string descriptors / ownership / terminator и guards packet /
archive / input / vector / string allocations.

Fixtures — свежие пустые объекты, выделение до 128 uint64 заранее и ограниченные
string allocation / assign / free / cookie. Запрос неожиданного vector growth
отклоняется. Reuse / allocator и engine эффекты не доказаны. Native допускает
trailing data с остановкой cursor на конце записи; portable требует точную длину.
Исполняется source SSE2 yaw path с реальными локальными UCRT `atan2` / `fmod`;
import descriptors проверяются, SHA DLL сохраняется. AVX не проверен.
Другие записи, HTTP UI, игровой вход и live visibility этим replay не проверяются.

Guard-тесты включают byte / count limits, malformed text, raw nonfinite bits,
precision uint64, отсутствие owner, ошибочный source, mutable / truncated /
trailing input. Portable дополнительно проверен на body ровно 65536 bytes;
это не native proof максимальной строки.

Harness scope `sight-gadget-record` допускает только 26 точных функций из
16 source-bound exports. Context и фактический набор должны совпасть; неверный
scope и подмена reader отклоняются отдельным тестом. Прежние scopes не расширены.
Контекст и полные SHA: [sight-gadget-11316.json](../../native-contexts/sight-gadget-11316.json).
Проверка `live-sight-gadget-11316` учитывает исходники, string fixtures, exports,
pinned Capstone / Unicorn, UCRT DLL и CRT locale.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sight-gadget-11316/61108ec1f9d509d85711e3f511ff2efc1549d40ab17deaade4e76f454c14e18d/manifest.json`.
SHA256 отчёта совпадает с именем каталога.

Теперь отдельные readers NPC create, ground / tether effects, Gadget и optional
projectile array имеют bounded native проверки. Следом — целый CharacterOther
с [Guild / Party вложениями](HEADLESS-SIGHT-SOCIAL-11316.md), затем весь SightEnter
с mixed arrays, общим бюджетом и handler / world связью.
Runtime ID 301 пока не подключён; [NPC subset](HEADLESS-OBSERVED-ENVIRONMENT-11316.md)
остаётся partial. Общая цель и живая multi-account проверка не завершены.
