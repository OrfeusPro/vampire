# ID110: непустые массивы, 20 октября 2026

Продолжение [минимального reader](HEADLESS-CHARACTER-SELECT-RESULT.md).
Семантические имена неизвестных полей не назначены: используются native offsets.
Это данные/код собранного клиента, не исходный C++ проект.

Клиент SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`,
путь/закреплённые инструменты и math provenance — в предыдущем отчёте.
Ghidra:165 функций/63 warnings, экспорт
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-c19a5eadbb74`.
Manifest SHA256 `f272cd18267b8d14e810a39e2ab9231e2310596785e6310a9fdb6aab5a2f5117`.
Новый reviewed leaf `0x1456b6000` длиной28bytes сбрасывает count, сверяет capacity
и tail-jump в allocator; у него нет PE unwind record. Диапазон помечен явно.

## Подтверждаемые схемы массивов

Offsets относительно main player block, кроме outer+290. Count на wire — LE u16.
Ниже перечислены поля wire element в порядке чтения; bool нормализуется в0/1.

| Native field | Element wire | Native stride | Reader/callback |
| --- | --- | --- | --- |
| main+80 (appearance items) | I32, enum byte clamp45, u16 | 10 | 145771b40 |
| main+158 | I32, u16 | 10 | 14578bd80 |
| main+168 и+220 | I32 | 4 | 1456b3640 |
| main+178 | byte,I32,bool,bool,u16,bool,u16,byte,bool | 40 | 1457f0170/1457f0220 |
| main+1c8 | I32 через archive slot58, rawQ | 18 | 1457f0540 |
| main+1d8 | enum byte clamp91, rawQ | 18 | 145780300 |
| main+1f8 | rawQ,I32,I32,3u16,3rawQ,I32,optional3f32,bool | 70 | 14578b840 |
| main+238 | raw byte | 1 | 1456ef840 |
| main+250 | byte,enum byte clamp7,byte | 10 | 145782c40 |
| outer+290 array+10 | 3I32,enum byte clamp3 | 18 | 1457f0c00 |

Native stride указан hex, wire primitives — little endian. Для+178 вложенные
bool/u16 занимают native+18/+28 records. В+1f8 optional header+40 имеет bool+48,
при true reader1456b2ce0 вызывает145817d60: три float32 хранятся в+58/+5c/+60.
При false тело отсутствует. Завершающий bool хранят в+68. В отчёте float32
сравниваются по raw32 bits, включая отрицательный ноль.

Привязки vtable уточнены по actual archive dispatch: slot+20 — reader,
slot+10 — writer. Таблицы1498d1b30/1498d1a68/1498d88b8 связаны соответственно с
readers1457f0540/14578b840/145782c40. Writers1457f4360/145790690/145787470
сохранены под отдельными именами; их сигнатуры не использованы как reader.

## Native scenarios и границы fixtures

`replay-character-select-collections.py` исполняет целое тело ID110, actual outer
и nested readers, callbacks, constructors и append. Для каждого из11 полей
проверяются1/2/8 элементов; ещё один сценарий заполняет все поля одновременно.
Все34 полных bodies разобраны; все465 коротких префиксов отклонены.
Нулевые и предельные значения проверяют bool normalization/enum clamps и raw
integers. Сохранение spatial vector проверяет отсутствие сдвига после массивов.
Все короткие префиксы совместного тела проверяются отдельно.

Bounded allocator fixtures дают не более8 slots нужного stride. Native callbacks
сами сбрасывают count и добавляют элементы; item/append не подменяются.
Cleanup captures не доказывают native lifetime/освобождение памяти; каждый
сценарий начинает с fresh object. Другие collections/maps сохраняют absent
профиль. Reader count bound4096bytes относится к исследовательскому fixture,
не является доказанным серверным лимитом.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-result.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-collections.py
python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_character*.py'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Report находится вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/character-select-collections-replay.json`.
SHA256 `4e44e567fcbfc5e9b5f878b75c9b3ae7817fa848fc4b807d9633d86dd97279d7`.
Source/tool/dependency hashes, source ranges, constructor leaves, cases и
truncated bodies сохраняются в нём. Обновлённый minimal result report включает
новые source ranges; старый SHA из предыдущей исторической записи относится
к экспорту151 функций.
Текущий minimal report SHA256:
`99e817c926f2b0fe44a12805b6becfa896c4a733986bee8ee83a8ad25e9a0fb8`.
Регрессия:30 character tests и3 Ghidra integrity tests прошли. Native collection
report воспроизведён тестом целиком, включая все465 short inputs.

## Дальше

Полный bounded portable ID110 decoder ещё не добавлен. Главная оставшаяся
ветвь — optional map main+98: entry stridef0/value+8, value constructor145793d90
ставит table1498cf350, его slot20→reader145796480. Вложенный table1498cf308
имеет reader145796df0. Эти два readers ещё требуется экспортировать; уже
экспортированы actual insert1456d33f0/find1456d37a0, value copy1456bbcf0 и
destroy145794f70. Value содержит дополнительные arrays/TimeBase; не считать
его fixed wire record по размеру native object.

После обеих непустых maps — общий decoder с aggregate budgets, handler14675e9a0,
semantic position consumer, lifecycle/SDK/device confirmation и live session.
Этап не запускал игру, не выполнял сетевой вход и не доказывает принятие выбора.
