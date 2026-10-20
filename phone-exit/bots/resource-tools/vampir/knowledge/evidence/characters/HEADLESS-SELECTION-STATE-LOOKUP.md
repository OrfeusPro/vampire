# Selection state: native lookup и граница реальных данных

20 октября 2026. Продолжение [перехода состояния](HEADLESS-SELECTION-STATE-TRANSITION.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Ghidra сначала экспортировала lookup **0x145c5d860**, registry getter
**0x145c38ab0** и связанные table/record routines. Пакет теперь содержит
54 функции, 33 warnings, run `run-5bc881f81b64`.
Общий индекс: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Метки `SelectionState_LoadRows/LoadSource/Register/Initialize` аналитические;
полное назначение этих generic routines по имени метки не утверждается.

[replay-selection-state-lookup.py](../../../replay-selection-state-lookup.py) →
`F:/PhoneExit Resources/Vampir/code-clues/selection-state-lookup-replay.json`.
SHA256: `726b7c9becc779f41300488218b3fe9226dbf0380bee678f7cb29806e80a419c`.
Report содержит source/tool/upstream SHA, native fragments/bytes/file offsets,
hash/accessor leaves и 13 cases. Actual state2 label verified=false.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-selection-state-lookup.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_selection_state_lookup.py
```

## Подтверждённый путь

State-label virtual **0x145dc3f30** теперь исполняет actual:

`lookup 0x145c5d860 → registry getter fixture → hash 0x145c60180 →
descriptor accessor 0x141482990 → record virtual+0x20 → copy fixture`.

Ранее lookup/accessor были fixtures. Теперь native lookup записывает uint32
ключ в descriptor+0, затем returned record address в descriptor+8.
Accessor реально читает+8; label caller при null возвращает empty FString,
при наличии вызывает virtual+0x20 выбранной записи. Сам record virtual и
string assignment всё ещё fixtures; данных работающей игры здесь нет.

Hash routine **0x145c60180..0x145c601f6**:

- count/free-count сравниваются в registry+0x20/+0x4c; равенство даёт null;
- bucket array — external pointer+0x58 либо inline+0x50;
- индекс bucket: `(bucket_count-1) & raw_uint32_key`, count по+0x60;
- узлы лежат в storage+0x18, stride **0x150**;
- key в node+0, next index в node+0x148, sentinel 0xffffffff;
- exact match возвращает **адрес node+8**, не pointer value из node+8.

Последнее различие важно: запись включает inline polymorphic object.
Копирование qword из node+8 вместо адреса передало бы vptr как this.
В native vectors выбранный record this проверяется на virtual boundary.
Не допускается предположение «первый bucket — состояние 2».

13 cases: inline hit/miss, empty registry, count==free-count, empty bucket,
external hit, collision chain `[6,10,2]`, collision miss `[6,10]`, keys 0/1/3/255/
0xffffffff. Native budget ограничивает выполнение; malformed cyclic chain и
изменение реестра одновременно другим потоком не исследованы.

## Где остаётся неизвестное

Registry getter **0x145c38ab0** статически связан с TLS/static initialization
global **0x14b57e8b0** и guard **0x14b57eaf8**. Он создаёт пустые структуры,
а не hardcoded имена состояний. Table **0x1499cec40** и secondary table
**0x1499cec78** связаны с initialize/load routines. Их Ghidra exports показывают
итерацию records и зависимые lookups, но источник содержимого записи key 2
этим не установлен. Эти generic loaders не исполнялись в новом replay.

Доступные CSV indices и ранее извлечённые DefaultGame.ini просмотрены:
подтверждённой цепочки к фактической строке key 2 не найдено. Похожие map/table
имена не подставлялись. Это не доказательство отсутствия данных во всех PAK.
В тестах `registry-label-fixture` — искусственная строка, **не map path**,
не state name и не основание для runtime конфигурации.

## Проверки и продолжение

[Три новых tests](../../../../../test_vampir_headless_selection_state_lookup.py)
перестраивают report, проверяют SHA/leaf bytes, точный ключ/record offset,
collision/miss/empty behavior и сохранённую unknown flag. Три смежных state
transition и три Ghidra tests прошли; полный suite не повторялся.

Следующий источник — **код заполнения storage registry+0x18 и actual record
vtable/virtual+0x20**, затем источник строки и lifecycle после перехода.
TLS initializer и runtime population требуют отдельного source-bound replay;
не выбирать произвольную запись или выводить метку из числового ключа.
Slot90 dispatch, response 102, полный network/session flow остаются открытыми.
Runtime не менялся; игра/профиль/process memory/credentials/network/Android
не использованы. Живой вход и персонаж не подтверждены.
