# Raw 2 → World.Id 2 → уровень CharacterSelect

20 октября 2026. Продолжение [lookup](HEADLESS-SELECTION-STATE-LOOKUP.md).
Источник — собранный Windows клиент и извлечённые CSV, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Подтверждённая связь

Raw 2, переданный selection virtual40 в предыдущем исследовании, используется
как ключ **World.Id**. В текущей patch-таблице и базовой таблице:

| Id | GroupId | LevelPath |
| --- | --- | --- |
| 1 | 1 | Lobby/Title |
| 2 | 2 | Lobby/CharacterSelect/CharacterSelect_02 |

Полное имя «state2» в прежних документах было аналитической меткой. Теперь
установлена связь с World.Id 2/LevelPath; это не восстановленный enum GameState.
Маршрут lookup → World record → getter установлен кодом и данными, а не только
совпадением строки CharacterSelect. Runtime population/mount priority отдельно
не проверены; факт нахождения CSV не объявляется живой игровой сессией.

## Источники, версии и воспроизведение

[replay-world-state-label.py](replay-world-state-label.py) →
`F:/PhoneExit Resources/Vampir/code-clues/world-state-label-replay.json`.
SHA256: `58dd41218b67196f80dc7b50ffea9132d6a7161e87ff8ad8797c1a80158a19d5`.
Report сохраняет EXE/tool/upstream SHA, native fragments/file offsets,
table/getter/column bytes, extraction indices/source archive SHA, header и строки.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-world-state-label.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_world_state_label.py
```

World уже описан в [MAP-ATLAS.md](MAP-ATLAS.md), original extraction:
`pakchunk1-Windows-1568.csv` и `ProjectRED-Windows-6200.csv`.
**Старый patch source stamp не совпал с установленным архивом**. Скрипт
перешёл на существующий audited release snapshot:

- table manifest SHA256 `430a1b516df976ee6b1accfc93c7386f9ac95c66480ce0cf5c56888acfd03ea8`;
- актуальный patch PAK SHA256 `03a229f23a86ac32e287dd5b7095a962ad8f342f1b5ac0addeb678616cf4f9e1`;
- World CSV SHA256 `5ea95616f4970082f5f6428bbe7da8a8905d43c69f2fb84f03de4146f9dfdc2c`;
- базовый PAK SHA256 `c10228ece0e1252bdd3ccf99fd4936e52d7a144f96c634080947d24c429e525b`.

CSV patch совпал с historical World **побайтно**; индекс/offset берутся из
нового snapshot, не переносятся по прежнему номеру записи. Для обоих архивов
заново сверены size/sample SHA и вычислены полные SHA; при изменении входов
скрипт останавливается. Base/patch приоритет монтирования этим не определяется.
Повторное извлечение всех таблиц не потребовалось.

## Native привязка World и LevelPath

Ghidra сначала прочитала registry use/source routines, затем CSV/другие
парсеры World **0x145c62130**, **0x145c65ef0**, **0x145c6aab0**,
find-or-add **0x145c5d390**, insert **0x145c5cca0**, record constructor
**0x145c5c780** и copy **0x145c5d5a0**. Часть предыдущих меток
`SelectionState_*` описывает generic World manager routines; исходные C++ имена
из аналитических меток не выводятся.
Пакет Ghidra: 63 функции, 36 warnings, run `run-0b27e9d388ad`.
Общий индекс: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.

Доказательства:

- Диагностика source routine **0x145c6d350** буквально содержит
  `World/World.xlsx`, sheet `World`, columns `StartSpotInfoId`/`Type`.
  Reference consumer также называет `WorldSpot.WorldInfoId → World`.
- Парсеры содержат точный column literal **LevelPath**, ASCII **0x1499d2c10**.
  Reference **0x145c6230f** и полный parser fragment сохранены.
- CSV header колонка 3 — LevelPath. Parsed string сохраняется в record FString
  **+0x48**; native storage block **0x145c628bd..0x145c62906** реально исполняется.
- Insert вызывает constructor, записывающий key и создающий World record
  с vtable **0x1499d28a8**. Constructor реально исполняется, empty-template
  copy backend — ограниченная fixture. Вставка/расширение всего map не исполняются.
- Table slot+0x20 равен **0x141482e60**, leaf `lea rax,[rcx+0x48]; ret`.
  Actual getter реально возвращает descriptor LevelPath.
- Прежние actual hash/accessor/state-label caller теперь работают с этим
  настоящим vtable/getter вместо record-label fixture.

Hash storage и getter registry подставлены тестом. Пополнение записей из
полного parser ещё не исполнено: в нативный field-store block подаётся
temporary FString из реальной CSV строки после границы CSV/UTF-8 conversion.
Resize/memcpy/string result copy — прежние bounded fixtures. Область теста
позволяет доказать source field→lookup→getter, а не весь loader lifecycle.

Для обеих таблиц реально созданы records 1/2, выполнены field assignments,
lookup/getter вернули две строки выше. Отсутствующий в тестовом storage key 3
дал empty label. Это не утверждение, что key 3 отсутствует во всех runtime данных.

## Проверки и следующий участок

[Три новых tests](../../test_vampir_headless_world_state_label.py), три lookup
и три Ghidra tests прошли. Проверяются native source/table/field bytes,
индексы/CSV/current archive hashes, source rows и lookup output. Полный suite
не повторялся; runtime не менялся.

Теперь следующий переход можно искать по реальному уровню
**Lobby/CharacterSelect/CharacterSelect_02**: cooked world/level и клиентские
hooks его завершения, затем инициатор slot90/CharacterListRead. Полное
заполнение runtime registry и применение patch source ещё открыты, как и
response 102/socket/session. Game/profile/process memory/credentials/network/
Android не использованы. Уровень не загружался в игре.
