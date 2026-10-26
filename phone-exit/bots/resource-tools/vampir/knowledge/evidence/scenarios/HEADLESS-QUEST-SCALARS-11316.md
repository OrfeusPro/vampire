# QuestTask: настоящие преобразования всех числовых полей

Source EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
QuestTask entry 2983, decoded CSV:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Prepare для wrappers / override:
`3b1cf92e094fd4d2e620ec4db21d694459fa9c999bbfb99350ff5240ce31c2a6`.
После сверки unwind bounds export запрошен только для настоящих roots:
`9c0d7ffd17e19d88547069611cc53e8a78fa62ea647885d0b7820e413551748f`.
Run-1f1d981208d1, SHA
`894a46395bb20e624271f898bbdb085fe4c997230de2c5ec468d4462795b1691`:
boolean `1445f5e60`, decimal parser `1445f14f0`; block/direct-flow coverage полные.
Leaf wrappers без unwind закреплены exact bytes в контексте, не собраны из
выдуманных function roots. Неудачные leaf collections не запускались.

## Реальные пути преобразования

| Поле | Native chain | Значение |
| --- | --- | --- |
| Id / QuestInfoId | 1445f5ed0 → 1445f14b0 | Windows `_atoi64`, сохранение 64-битного результата |
| i32 | 1445f5eb0 → 1445f14d0 | Windows `atoi`, low32 |
| flags | 1445f5e60 → 1445f14d0 | `atoi`, затем native nonzero → AL |
| Type / TaskProgressType | 1445f6040 → 1445f1b70 | Windows `strtoul`, endptr=null, base=0; store использует low8 |
| XYZ / radius | 1445f5f10 → 1445f14f0 | native decimal parser, digit leaf 1445e4c30 и Windows `pow` |

Cell getter проверяет unsigned column index, выбирает 32-байтную cell из
parser+28; SSO helpers выбирают inline или heap по capacity+18. Импорты
atoi/_atoi64/strtoul/pow сверены с IAT и DLL/name. Bridge вызывает настоящие
функции System32/ucrtbase.dll через ctypes, а не Python int/float вместо CRT.
DLL SHA и текущая locale записаны до / после; locale не меняется. Memory bridge
ограничивает входы текущими cell buffers, native выполняется только в Unicorn.

Для 5944 current CSV rows учтены 95 104 значения 16 числовых колонок, включая
ServerServiceGroupId. Повторяющиеся kind/text объединены; inline/external layout
дают 26 906 native случаев. Все совпали с ожидаемыми decimal значениями текущего
каталога. Это проверка преобразований, не full native загрузка всех 5944 rows.
Synthetic cells / их descriptors создаёт fixture; источник значений закреплён
через record index, reader/Oodle, actual PAK и decoded CSV SHA.

28 lexical cases (14 строк × 2 layouts) подтверждают существенные отличия:
`true` даёт false для flag; enum `08` → 0, `010` → 8, `0x10` → 16, `256` → low8=0.
Decimal parser отвергает `1e3`, `+1`, leading space и trailing letter, возвращая 0;
`.5` / `1.` читаются. Для `1.2.3` native получает f32 от 12.3: проверена фактическая
ветвь, это не разрешение принимать произвольный текст как корректную координату.
На current CSV этих расхождений с decimal reference нет. Ещё 15 bounds cases
(5 видов × 3 неверных индекса) возвращают 0 без вызова conversion imports.
Все input bytes и guards сохранены; row имеет ненулевое число колонок.

## Подключение к whole loader

В [whole loader](HEADLESS-QUEST-LOADER-11316.md) новый explicit режим
`quest-loader-scalars-11316.json` заменяет все пять scalar fixtures native paths.
Boolean/decimal roots и wrappers выполняются вместе с tokenizer, record/map
chain, field stores и group iteration. На шести исходных строках 110120 в
прямом/обратном порядке сохранены все 16 data fields и порядок указателей.
На каждый запуск пришлись actual CRT calls: 48 atoi, 18 _atoi64, 12 strtoul,
24 pow. Старый fixture режим остаётся отдельным контрольным сценарием.

Для этой цепочки harness допускает 9 individually SHA-pinned exports вместо 8;
лимит 24 explicit roots остаётся, recursive discovery отсутствует. Новый контекст
имеет 17 roots. Это изменение только offline research harness, не runtime.

File/header setup, string/UTF8/FString/TArray storage, allocation/free, map clear,
bit append/hash/duplicate checks остаются fixtures. Override getter/application
по-прежнему null/no-op; настоящий `145b69ca0` не проверен. Full catalog loading,
current nonzero service policy, actual header parsing и overrides нужны до
live admission. `order_admitted=false`, gameplay / owner API не используются.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_scalars_11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_loader_scalars_11316.py
```

Registered checks `native-quest-scalars-11316` и `native-quest-loader-scalars-11316`
закрепляют CRT, code/context, record index, reader и exports. Артефакты:

- `code-clues/quest-scalars-11316/fb145bb4b6c16f0678eedecde6a529613f51c0f77c06bbf4bb64e6c6bbe628f7/manifest.json`.
- `code-clues/quest-loader-scalars-11316/ac1fd0fea7a93740185b031f6b2e65559236260832a98d1b558526691382bfe4/manifest.json`.

Действующая сессия сохранялась без Stop / relogin / изменения owner.
