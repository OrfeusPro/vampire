# Текущие CharacterList, clock и metadata consumers

Источник — EXE 1.13.22, полный SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
База CharacterList / clock — 1.13.18,
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Машинная приёмка](ENTRY-NATIVE-CURRENT-VALIDATION.json) содержит точные manifests,
checks и результаты кэша. Это продолжение [готовых экспортов](HEADLESS-ENTRY-COLLECT-CURRENT.md),
а не повтор прежних версий. SDK-вход Silvercrow уже принят
[отдельно](../auth/HEADLESS-FIRST-SDK-PROFILE-CURRENT.md).

## CharacterList

`generate-character-list-current.py` связывает 40 целых current roots, leaves,
таблицы, registration и сохранённые INPUT / gate proofs. Шесть contexts,
варианты проверяющих файлов и harness сохраняются в неизменяемой библиотеке
с полными SHA. Файлы не исполняются из произвольного каталога: текущий runner
проверяет категорию, scope, набор функций / leaves и каждый retained input.
Ограничение source / budget адаптировано отдельно; instruction fence и сценарии
унаследованных проверок сохранены. Исторические native матрицы не запускались.

Проверены WaitingEnd, envelope, character record, appearance / optional extensions,
коллекция records и отдельный handler: 1547 обычных сценариев, две extension
boundaries и пять multi-short guards, всего 1554. Storage, allocation / rehash /
shallow copy, services, SDK / controller / UI / flow и внешнее состояние — fixtures.
Reader и handler проверены отдельно; совместная композиция не заявляется.

Runner сохраняет каждый успешный компонент и общий пакет. Неизменный повтор
использует frozen report; `verify_report` проверяет исходные и generated файлы,
runtime, состав и размеры матриц до возврата результата. Сбой не требует
повторения завершённых неизменных компонентов.

## Clock / Ping / ограниченный world

Текущие contexts связывают source-checked remap, окна вызовов, packet / handler
tables и готовый current INPUT. Исполнены 24 clock, 36 producer, 201 bounded-world
и 36 PingResult сценариев, а также 12 коротких native INPUT. Новый lobby handler
исключён из прежнего clock набора и проверяется собственным пакетом.

`run-clock-world-current.py` сохраняет четыре component reports и общий manifest.
Неизменный повтор проверяет retained plan / INPUT / exports / code и использует
кэш без replay. Тест запрещает даже загрузку replay-модуля при таком повторе.
UTC backend, month length, local offset cache, engine / context / send / recovery
сохраняют явные fixtures. Reserve заканчивается на opaque suffix; полная
семантика вложенных ID 110 / 206 не подтверждена этим переносом.

## Новые поля лобби

После [доказанного reader / decoder](HEADLESS-LOBBY-VERSION-LAYOUT-CURRENT.md)
отдельно собраны только два отсутствовавших whole consumer: `0x145bc9b00`
и `0x145bc7b60`, export `run-748a854efcce`. Их полные unwind ranges и bytes
сверяются до исполнения. Это одна новая JVM; CharacterList / clock использовали
готовые exports без JVM.

362 validation сценария проверяют пустую строку, отсутствие provider, format error,
отказ первого / второго преобразования, совпадение обоих чисел и отдельный
неверный offset. Значения включают int32 minimum / maximum, отрицательные и
положительные offset; native делает sign extension R8D / R9D и умножает на 1000.
Проверено деление отрицательного / положительного времени к нулю. При пустой
строке validation возвращает true без provider.

48 apply сценариев проверяют короткие / длинные имена, равное / изменённое имя,
два состояния cache capacity и пустые / непустые caches. Native сравнивает имя,
при изменении увеличивает generation и сбрасывает поля двух caches; неизменное
имя не вызывает reset. Source literals указывают на `RdScheduleTimeZone::SetZoneName`,
`en-US`, `VV`, `Etc/Unknown` и fallback server zone. Это объясняет назначение
потребителей, но не доказывает актуальные значения ICU / ОС.

Unicode / string allocation, date / now, format / timezone providers, pool internals,
intern / logging / free остаются fixtures. Синтетические provider offsets не
выдаются за данные системы. Public decoder сохраняет raw-поля; новые поля
не отбрасываются старым binder. Полные wire string / time primitives и общая
композиция новых consumers с reader остаются отдельными границами.

## Обновление и оставшаяся работа

Четыре source checks — `character-list-current`, `clock-world-current`,
`lobby-metadata-current` и [viper-class-current](../characters/HEADLESS-VIPER-CLASS-CONSUMERS-CURRENT.md)
— подключены к соответствующим contracts и `on_update`. Tests находятся ровно
в одной tooling-группе каждый; общие зависимости включены в gate.
`entry-current-check-guard.py` удерживает весь selected proof CharacterList / clock
до и после source check, включая попадание в кэш. Повреждение дочернего материала
не становится cached success. Машинный selector — `knowledge/entry-native-current.json`.

Runtime candidate ещё не собран и не активирован. Следующий пакет связывает
готовые source scopes с текущими codecs / binders и отдельными guards. Для Viper
остаются CDO allocation / copy, актуальные integer defaults / tag mapping и
Create 103 / 104; 49 class-consumer случаев не заменяют эти доказательства.
Игровых запросов, создания персонажа, мира и новых проверок семи остальных
аккаунтов этот пакет не выполнял. Наблюдатель обновлений остаётся выключенным.
