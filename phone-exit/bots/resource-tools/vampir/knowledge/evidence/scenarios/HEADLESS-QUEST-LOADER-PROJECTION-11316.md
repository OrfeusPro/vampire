# Native загруженный массив задач и проекция progress

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK SHA256: `15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
QuestTask entry 2983 SHA256:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Russian override entry 2359 SHA256:
`88efc2a29c7a52a4148ef916689b77044b25b4c028ad4feea96d0b4782ee57b7`.
Request: `14375f527ed9d48b603f54864cefc53ece5bf534ad98020e3fd4ea987b18ad75`.

## Совместное выполнение

[Whole base/ru loaders](HEADLESS-QUEST-LOADER-OVERRIDE-11316.md) дополнены
native `145b4be70` и `145de4610`. Они выполняются сразу после загрузки в той
же памяти: manager, group nodes, TArray и data records созданы native loader,
не заново посеяны из Python CSV-полей. Type getter `145b55aa0` читает настоящий
record+8C через исходную vtable. Проверяется её slot и точный leaf.

Два дополнительных уже проверенных exports: run-b865a737d979 SHA256
`e62dea7abd45aa48ce27bcf3ee8c1290fe9ca8991bf5e95792049c8da4c62452`,
run-6978cfe0cd9d SHA256
`604ae3be1bba4bc7c87a9183f94017bdade41ebae0fbd632ebc5244944cc3cbe`.
Остальные exports/leaf bytes закреплены контекстом
`knowledge/native-contexts/quest-loader-projection-11316.json`.
Explicit harness теперь допускает 12 sealed exports вместо 10 для этой общей
цепочки; лимит 24 roots сохранён, здесь их 21. Рекурсивного анализа нет.

36 проекций: шесть индексов × три пары counters × original/reverse source rows.
Проверены task ID, Type, index, low32 counters, zero tail, untouched padding,
output/input guards и неизменность всех loaded allocations и manager.
При original порядке index 0 → 110120005, kind 6; при reverse → 110120070,
kind 6. Остальные индексы следуют фактически загруженному массиву.
Так проверка отличает порядок массива от простого угадывания первого ID.

## Область квеста 110120

Выбраны шесть полных исходных строк: 005/010/020/030/040/070, все QuestInfoId
110120. Их ServerServiceGroupId пуст; инструмент отклоняет этот mode, если
хотя бы выбранная строка получает непустую service group. Для этих шести строк
native zero/empty gate не требует текущего RegionType/ServicePhase.
Это не распространяется на остальные строки полного каталога.

Source row 110120005 имеет Type 6 и Param Time 0.1; названия ru и Param
сохраняются прежней loader проверкой. Live raw index 0 согласуется с этой строкой
только при подтверждённых условиях загрузки/применения модели. Здесь не делается
вывод, что персонаж уже исполняет этот локальный этап или что Time автоматически
разрешает отправку QuestUpdate.

## Fixtures и оставшееся неизвестное

Manager getter возвращает загруженный scratch manager; hash callback общий
для вставки/поиска. File/header/string/storage, map allocation/clear, settings и
выбор ru bytes остаются bounded fixtures. Выполняются обе source orders только
выбранной группы, не полный 5944-row catalog / реальный file resolver.
Пустые service groups доказывают независимость этих строк от nonzero gate,
но не порядок и полноту всех реально установленных overrides.

Не выполнены вместе с этой памятью selected model factory/lifecycle/HUD
handler, engine-corrected position или выполнение Time/Dialog/LevelSequence.
Нет source-bound runtime offer или игровых команд. `order_admitted=false`;
сеть и память живого процесса не используются, соединение не перезапускается.
Следующий шаг — применение полученного progress к task state и native
lifecycle kind 6 для 110120005; реальный sender/admission проверяются отдельно.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_loader_projection_11316.py
```

Check `native-quest-loader-projection-11316`; общий replay
`replay-quest-loader-11316.py`, прежние modes сохранены.
Артефакт: `code-clues/quest-loader-projection-11316/21511838509db765cdbe5ca7211ab59b7f9482f0798fa62b9c8e6d11b1b0aabe/manifest.json`.
