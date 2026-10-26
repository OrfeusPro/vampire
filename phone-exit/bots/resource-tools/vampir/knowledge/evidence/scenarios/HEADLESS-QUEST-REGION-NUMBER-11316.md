# Числовое чтение RegionSelect: найденный ключ и значение

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `61fc0b8f43292bbb945091b3f99b8481cc871eb88f45dcd2e2c341ae3936d265`.
Новый экспорт run-43e25a15d0c1, SHA256
`4250ababa64369bcd106f90e121b5137a0820e088d23f14563add80f07be7b2e`.
Предыдущий экспорт run-79f96d7ea490, SHA256
`06a0ba8744ea7ea26f06ab5b201641434370d422e5066ece1a21130674dcc3e8`.

## Проверенная цепочка

Native reader `1445ceaa0` вызывает lower storage reader `1445ceca0`.
При найденном ключе helper `141435110` удаляет все запятые из строки,
затем IAT `14899bbb0` вызывает `_wtoi` и результат записывается в output.
Возвращаемый AL означает успешный поиск строки, а не корректность числа.
При отсутствии ключа output сохраняется, преобразование не вызывается.

В 56 сценариях проверены 14 строк × found/missing × два представления пустой
FString (count 0 / 1). Найденные пустая строка и `JP` дают 0 при true;
`1,000` → 1000, `4,5` → 45, `1,2,3` → 123, `,4,` → 4.
`  +7x` → 7, `0x10` → 0, `-1` сохраняет биты signed int32.
Полноширинные цифры `１２` дают 12 в записанной локальной CRT locale.
Также проверены 0, 4, 7, 2147483647; overflow не исследован.
Это уточняет [region lookup](HEADLESS-QUEST-SERVICE-REGION-11316.md):
найденный нечисловой текст не равен отсутствующему ключу и сам по себе
не запускает legacy/fallback ветвь. Совместный replay lookup с этим reader
ещё не выполнен; вывод о его ветвях опирается на отдельное прежнее доказательство.

## Границы

Выполняются инструкции целых numeric reader и comma replacement.
Lower storage read, FString allocation/copy/append/free и сравнение пустого
суффикса — ограниченные fixtures. Последнее проверяет длину 0 и допустимо
только для односимвольного шаблона запятой и пустой replacement.
Реальная локальная Windows CRT вызывает `_wtoi`; SHA DLL и locale проверяются
до и после прогона. Unicode-результат не переносится на другую CRT/locale.
Guards output/allocations, неизменность key/section и cleanup проверены.
Реальные файлы настроек не читаются и не меняются, сеть не используется.
Active region, identity/account mapping, storage path, whole catalog и gameplay
остаются неподтверждёнными; `order_admitted=false`.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_region_number_11316.py
```

Инструмент `replay-quest-region-number-11316.py`, контекст
`knowledge/native-contexts/quest-region-number-11316.json`, check
`native-quest-region-number-11316` (зависит от ucrtbase.dll).
Артефакт: `code-clues/quest-region-number-11316/4f1cb9e73ee6429b0ec3d3f5f95139d0cfbf7f97d2178f798695f012894a6400/manifest.json`.
Следующая проверка — совместная цепочка lookup/reader, затем lower string
storage и active region / ServicePhase до допуска всего каталога.
