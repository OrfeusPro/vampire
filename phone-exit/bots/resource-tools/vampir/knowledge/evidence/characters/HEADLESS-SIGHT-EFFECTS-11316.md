# SightEnter: ground / tether records и оставшиеся вложения

Клиент 1.13.16, SHA256 EXE
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [контракта пяти массивов](HEADLESS-SIGHT-ENTER-CONTRACT-11316.md).
Два вложенных reader проверены native; это ещё не целый SightEnter.

## Полные вложенные readers

| Запись | Constructor / reader | Vtable | Native object | Wire |
| --- | --- | --- | --- | --- |
| PktGroundEffectData | 14578fef0 / 145793a90 | 1499223d8 | 78 hex | 50 bytes |
| PktTetherEffectData | 1457a3480 / 1457a83c0 | 149922420 | 90 hex | 66 bytes |

Ground wire: `u64; u32,u32,u32; u64; float32 XYZ; byte yaw; u32; float32; byte`.
Последний byte clamp 3. Tether wire:
`u64; u32,u32,u32; u64,u64; float32 XYZ; float32 XYZ; byte yaw; u32; bool`.
Любой ненулевой wire bool становится true. Строк, optional blocks и коллекций
внутри этих двух записей нет. Смысл scalar ID, float или bool не именуется по величине.

Portable `sight_effect_records.py` возвращает immutable `SelectionRecord` с native
offsets. XYZ сохраняет три исходных float32 bit patterns через `WireVector3`;
для координат требуется отдельный `finite_values()`. Float Ground+6c хранится
как исходные uint32 bits, включая NaN / signed zero, без заявления о длительности.
Yaw сохраняет исходный byte через `WireHeading`, отдельно от native канонизации.
Декодеры требуют точный source SHA, immutable bytes и точную длину 50 / 66.
Trailing и truncated тела отклоняются. Поля этих записей не становятся HP NPC.

## Native и portable проверка

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_effects_11316.py
```

Два теста прошли. Whole replay включает 2580 сценариев: оба constructor / reader,
настоящий archive/input, widening XYZ и yaw / vector math, все 256 heading bytes
при трёх наборах uint64 keys / float bits. Для yaw 0 / 127 / 255 проверен каждый
префикс тела. Сопоставлены acceptance, cursor, scalar values, XYZ и guards
объекта / archive / input; исходный heading portable проверен для всех bytes.
Отдельно проверен native cursor при trailing byte, portable exact-size guards,
ошибочный SHA, mutable input, nonfinite XYZ и bool 0 / 1 / 255.

Unicorn исполняет 16 явных функций из восьми source-bound Ghidra exports и
проверенные leaf bodies. Контекст и полные SHA:
[sight-effects-11316.json](../../native-contexts/sight-effects-11316.json).
Используется SSE2 ветвь текущего клиента; AVX и другие dispatch paths не проверены.
Вызовы `atan2` / `fmod` привязаны к точным import descriptors и реальной локальной
Windows UCRT, SHA которой записан в отчёт. Это импортная граница native replay;
Python-замены игровой yaw-формулы нет. Input memcpy ограничен scratch memory.
Проверка зарегистрирована как `live-sight-effects-11316`; кэш учитывает код,
exports, pinned runtime, UCRT DLL и CRT locale.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sight-effects-11316/a7e9754d58d01671060fbb59d240f03dec3f6b54a8c2e899f57d1bd9ab0ebc7f/manifest.json`.
SHA256 отчёта совпадает с именем каталога. Не выполнялись внешний SightEnter,
его callbacks / dynamic storage, handler / actor effects или игровая сессия.

## Что выяснено о других вложениях

Статически просмотрен leaf constructor SightEnter `1456c0300`: он записывает
vtable `149922490` в packet+0 и отдельный vtable `149922468` в packet+50.
Второй reader slot +20 указывает на `1456c2f60`.
Этот reader читает bool в object+8; только при true читает массив object+10 через
descriptor `149924f00 = (141b0aa50,1456d1f70,1456c64b0)`.
Следовательно, packet+50 — optional array, а не одиночная запись actor / позиция.
Тип и wire формат элементов ещё не проверены native.

Для CharacterOther найдены существующие зависимости: appearance `145787a30`,
initial stats `145734dd0`, yaw `1458220f0`, effects descriptor `149948d28` и
ground effects descriptor `149948d70`. Constructor `145799940` создаёт запись
с vtable `149920598` / reader `14579c6b0`, связанную с `PktGuildTinyInfo`;
другая вложенная запись создаётся `1457a2350` с `PktPartyTag`.
Это статические связи, не готовый полный CharacterOther decoder.
`145781ac0` читает effect array, `1456bb710` — массив uint64 через уже известный
descriptor `149924c90`. Оба wrapper требуют проверки вместе со своим caller.

Новая bounded выгрузка:
`ghidra/request-exports/<SHA>/run-bbd19f52e20c/details.json` в библиотеке ресурсов,
SHA256 `531e4e96e2f8c5f5b32ab4f6a803bd21787698c55aedaad0dd3b5e24a8cc14b8`.
В ней четыре явные функции: `1456c2f60`, `145799940`, `145781ac0`, `1456bb710`.

Следом — элементы optional array packet+50, GuildTinyInfo / PartyTag и Gadget
optional data; затем полный native mixed-array SightEnter и общий portable reader
с единым бюджетом всех вложенных коллекций. Только после handler / world проверки
подключать initial entities. Runtime пока не получает ID 301; прежний
[частичный NPC subset](HEADLESS-OBSERVED-ENVIRONMENT-11316.md) сохраняет свои границы.
