# QuestTask: whole loader на исходных строках «Зова крови»

Source EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
QuestTask PAK:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Entry 2983, decoded CSV:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Prepare request:
`c14d404daf99b58b7dde4d53f85a39ca37fd00ebd28a465ff6513c53432bb4fe`.
Все explicit roots уже имели exports; новая Ghidra collection не требовалась.
Контекст закрепляет 8 exports с полными SHA и 15 native roots.

## Исполненная цепочка

Целый loader `145b5f270` выполнен от входа до возврата, включая чтение колонок,
цикл строк, group filter, поиск/создание первичной записи, stores, обход занятых
slots и append указателей в массив этапов. В одном harness объединены
[tokenizer](HEADLESS-QUEST-CSV-ROW-11316.md),
[record constructor / field-copy](HEADLESS-QUEST-RECORD-CHAIN-11316.md) и
[FindOrAdd / insert / growth / rehash](HEADLESS-QUEST-MAP-CHAIN-11316.md).
Внешние зависимости ниже остаются fixtures; whole loader не означает whole game.

Из current PAK читаются исходные физические строки задач 110120005, 110120010,
110120020, 110120030, 110120040, 110120070. Целостность PAK, record index,
reader/Oodle и decoded CSV проверена по SHA; bytes строк не пересоздаются через
CSV writer. Один запуск читает 1220 байт, второй — те же шесть строк в обратном
порядке. Native tokenizer читает поток по одному байту и создаёт 17 cells.

В каждом запуске после возврата loader проверены все 16 data fields записи:
Id, QuestInfoId, TargetSpotInfoId, AreaInfoId, четыре flags, Type, полный Param,
MapIconGroupId, TaskProgressType, XYZ и radius. Param совпадает с исходным JSON
после native удаления CR; float bytes сверены как f32. ServerServiceGroupId —
семнадцатая колонка фильтра, не отдельный store в этих 16 полях.

Обе последовательности создают 6 primary records и 1 quest group; три node
resize и два group-array resize действительно вызываются. Group TArray содержит
указатели ровно на эти records в порядке insertion slots. Обратный CSV даёт
обратный массив: скрытой сортировки по task ID на проверенном пути нет.
Full Param / scalars / flags / position fields сохраняются после роста таблицы.
Guards оставшихся allocations целы, stream полностью прочитан.

Source vtable `1499f67f8` slots +68..+E8 проверены как указатели на exact leaf
`141403b70` bytes `c20000` (RET 0). Они исполняются native, не callback fixtures.
Post-load slot +30 primary table `1499f6948` ведёт к exact leaf `140bb4a10`
bytes `b001c3` (возврат true). Override slot +40 secondary table `1499f69e8`
проверен как `145b69ca0`, но его выполнение пока заменено fixture.

## Явные fixtures и неизвестное

- File/header setup передаёт только выбранные исходные строки и готовые column
  mappings. Native file retrieval / header parser не исполняются.
- Scalar getters используют ограниченные Python int/float conversions;
  реальные getter/CRT paths для всех полей ещё надо проверить. Group gate native,
  но его чтение пустой service cell здесь также через scalar fixture. Прежний
  [отдельный zero-gate proof](HEADLESS-QUEST-EMPTY-GROUP-11316.md) остаётся отдельным.
- Рост/копирование std::string, UTF8→UTF16, FString storage, TArray storage,
  allocation/free, fresh empty-map clear, bit append, hash и duplicate check —
  явные fixtures. Memcpy/memset import identities сверены. Это не доказательство
  работы native allocator или преобразования Unicode во всех случаях.
- Getter override context возвращает null, `145b69ca0` принимает только этот
  null и ничего не меняет. Вызов учтён ровно один раз на запуск; это не проверка
  настоящего override или его отсутствия в живом клиенте.
- Нет full 5944-row load, nonzero service policy, duplicate keys, removals,
  allocation failures или непустого исходного manager.

`order_admitted=false`: доказана совместная control-flow цепочка на выбранных
строках в указанных границах. До live progress-index admission нужны actual
scalar getters, override и загрузка каталога при подтверждённой service policy.
Игровые команды не отправляются, действующий owner не изменяется.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_loader_11316.py
```

`replay-quest-loader-11316.py`, контекст `knowledge/native-contexts/quest-loader-11316.json`,
registered offline check `native-quest-loader-11316`. Артефакт:
`code-clues/quest-loader-11316/46f8601a7cb67a9be7945bab7d67879c7524bee4535d1f00076184f68f72c3e2/manifest.json`.
