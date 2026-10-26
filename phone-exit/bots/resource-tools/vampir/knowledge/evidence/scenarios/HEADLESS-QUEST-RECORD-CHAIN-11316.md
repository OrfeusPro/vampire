# QuestTask: native constructor / field copy внутри map chain

Source EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`ca823af78d2988018c9a5f2acfa51aea63dcb6bb57f313f2da79f99c02bd580c`.
Новый field-copy export run-3135f232de2c имеет SHA
`a452665c119392c9bddf3a74e9e086a8f4de9ba42418356a8f2b8225009ed718`;
block и direct-flow coverage полные. Constructor export run-c5e27e535de5:
`eddd741edacd5750d9e017d24494ef404f210f051cac819831ace94d029c0f1d`.

## Проверенная цепочка

В [whole map chain](HEADLESS-QUEST-MAP-CHAIN-11316.md) первичный constructor
fixture заменён настоящим `145b48860`, который вызывает настоящую field-copy
`145b4bd20`. Новый контекст включает оба explicit roots, старый режим проверки
map chain сохраняется отдельно.

Конструктор читает key через wrapper, пишет его в node+0 и создаёт record в
node+8. Временный объект получает data-vtable `1499f67f8`, kind=1F и
TaskProgressType=2. Field-copy переносит header, scalars, flags и float fields,
вызывает отдельные копирования трёх wide-string полей +30/+78/+90 и возвращает
record pointer. Node stride остаётся 200 байт, record — 184 байта; link/bucket
metadata расположены после record.

Три первичные fresh-map последовательности по 70 уникальных keys дают
210 native constructor/default checks. После каждого FindOrAdd проверяются:

- Key и адрес record в ожидаемом insertion slot.
- Настоящая data-vtable, kind=1F, TaskProgressType=2.
- Нулевые исходные scalar IDs и три пустых wide-string поля.
- После записи synthetic payload — сохранение прежних key/payload при каждой
  последующей вставке, realloc / rehash и existing lookup.

Вместе с тремя group-map контрольными последовательностями это 420 вставок,
840 existing lookups и несколько переходов capacity / bucket count. Existing
lookup не создаёт новый объект и не вызывает внешние mutation callbacks.
Финальный native iterator обходит прежний insertion-slot order. Heap/map guards
проверяются после каждой последовательности.

## Что осталось fixtures

Hash, realloc/bucket allocation/free, bit append и duplicate check остались
явными ограниченными fixtures. Memset fixture обнуляет только проверенный
временный stack region длиной A0; thunk и импорт VCRUNTIME140!memset сверены
с EXE. Empty-wide initializer принимает только source literal `1489e46d8`,
его первые UTF-16 bytes проверены как zero. Три wide-copy fixtures принимают
только нулевые 16-байтные string descriptors с stack и допустимые record offsets.
Непустые строки и native allocator / string implementation не проверены.
Null empty-string fixtures означают, что ветви освобождения temporary strings
не исполняются; cleanup при non-null string storage остаётся неизвестным.

После проверки defaults в record намеренно пишется synthetic payload:
он проверяет сохранность bytes при map growth, а не реальные QuestTask values.
CSV accepted-row stores, loader `145b5f270`, service policy и overrides этот
сценарий не выполняет. Он дополняет
[native чтение исходных CSV rows](HEADLESS-QUEST-CSV-ROW-11316.md), но не
объединяет обе проверки в whole loader. `order_admitted=false`.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_record_chain_11316.py
```

Общий replay `replay-quest-map-chain-11316.py` принимает explicit context path;
новый `knowledge/native-contexts/quest-record-chain-11316.json` включает native
constructor, прежний контекст по умолчанию сохраняет прежний fixture mode.
Registered offline check `native-quest-record-chain-11316` закрепляет 7 exports,
контекст и зависимости. Проверка не использует сеть, gameplay или owner API.
Артефакт в библиотеке ресурсов:
`code-clues/quest-record-chain-11316/b28c12f27f3398fed19231b279eefb54416ef33c615716a58f72d193c875e214/manifest.json`.

Следующий шаг — actual accepted CSV stores / whole loader / overrides до выбора
активного этапа в live adapter. Действующая сессия не перезапускалась.
