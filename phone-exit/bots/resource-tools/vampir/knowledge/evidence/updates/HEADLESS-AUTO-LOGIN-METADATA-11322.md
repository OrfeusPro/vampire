# Автоматические Login metadata и интеграция 20 → 22

Target EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Reviewed база обеих ролей 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Машинные указатели на contexts, transfer proofs, semantic reports и acceptance —
в [AUTO-LOGIN-METADATA-11322.json](AUTO-LOGIN-METADATA-11322.json).

## Исполняемая область

Standalone metadata исполняет шесть полных roots: collector `0x14560b0c0`,
selector `0x145601830`, loader `0x14560a670`, writer `0x144557b60`, copy
`0x145601580` и move `0x145600cf0`. UserInfo имеет размер 592 байта, 37 строковых
descriptors по 16 байт. Поля, условия и порядок исполнения проверяются отдельно
от настоящего происхождения SDK-значений.

288 сценариев: шесть backend states × шесть patterns × optional device on / off
× marketing on / off × два poison patterns. Проверены synthetic shared control
blocks, ветви strong / weak refcount, copy / move, очистка временных значений,
guards и Win64 ABI, включая R13 и XMM6–XMM15.

Статически сверены 85 inputs: точные UTF-16 / ASCII literals и типизированные
globals. Collector содержит 27 ordered key lookups, включая повторный `I_World`;
writer имеет 39 ключей, а fixture field projection — 33 именованных offsets.
Эти три набора имеют разные роли и не заменяют друг друга.
Константы, все инструкции, ветвления, call offsets и ссылки проверяются по обоим SHA.

34 fixtures остаются явными границами. Два destructor hooks — синтетические
адреса `0x2800e000` / `0x2800e010`, memset — точный IAT thunk с проверкой
VCRUNTIME140.dll / name. Четыре non-unwind fixture bodies проверены целиком:
construct-info, settings, source-info и optional-resolve. Последний содержит
virtual tail dispatch, который заменён fixture и не исполняется.
Остальные 27 fixtures имеют concrete unwind boundaries.

SDK backend / shared factory / settings / UserInfo providers, GUID / identity
getters, map / hash / lookup / variant / string primitives и cleanup bodies
остаются fixtures. Строковые операции используют ограниченные подстановки;
настоящие JSON escaping, SDK-значения и пользовательские данные не подтверждены.
Diagnostic branch отключена в памяти эмулятора; её связи и литералы сохранены
как статическое доказательство, а выполнение logger не допускается.

## Интеграция с подготовкой Login

Второй context объединяет проверенные target SDK и target metadata: 11 полных
roots и шесть returning leaves. Старый SDK adapter не получает более широкий
metadata context: SDK проверяется в своей исходной области. Затем собственная
reviewed база интеграции сравнивается с обеими независимыми target-зависимостями.

448 сценариев: 14 Login scenarios × empty on / off × два send results × восемь
metadata triples. Selector фиксирован в 3, poison — 0x55, SDK cache — warm.
Resolve / absent cache не повторялись: они относятся к прежним 2016 SDK сценариям.
`native_sdk_used` и `native_metadata_used` равны true; вызовы всех шести metadata
roots проверяются по каждому случаю, включая отсутствие aux handle.

Обязательны точные связи outer aux getter → collector, SDK field consumer →
metadata selector и общий manager → optional manager. Ключи, literal addresses
и call sites 27 полей сохраняют source provenance. Все roots и leaves различны;
активный hook не может заменить исполняемый код.

Разрешены только семь явных cross-hook pairs: copy / wide / ASCII strings, free,
outer format-number ↔ metadata format, SDK main-store ↔ optional-store и SDK
cache-resolve ↔ optional-resolve. Одинаковые имена variant-number / variant-destroy
не объединяются: это разные адреса. Shared allocator и множество allocations /
freed принадлежат outer Login. Bridge переключает shared hooks только на время
metadata collector и возвращает прежнее поведение после его return address.

Metadata text bound — 4096 UTF-16 units, allocation bound — 8192 байта. Итоговые
строки Login-пакета сохраняют собственный bound 1024 units. Shared refcount blocks,
optional cache и handles синтетические; из реального SDK и сети значения не читаются.

Допуск обоих reports сверяет точную уникальную матрицу, типы значений, guards,
native call counters и field provenance. Дубли не могут заменить пропущенные
сочетания. 288 и 448 имеют пересекающееся исполнение metadata: сумма 736 не
означает независимые функции или доказательства целого входа.

## Обновление, кэш и повтор

Шесть missing exports собраны одним Ghidra пакетом с переиспользованием проекта.
Полный EXE analysis не выполнялся. Pure transfer использует независимый SDK caller
как seed и сравнивает 3497 instruction / call / data links, без выбора по близости адреса.
Metadata и integration зарегистрированы в
[native-check-adapters.json](../../native-check-adapters.json) и выполняются через `update --auto`.

Новый общий `portable-native-family.py` обслуживает immutable lifecycle:
source-bound baseline, missing-only exports, transfer proof, semantic check,
целостность входов и атомарную публикацию. Конкретный adapter задаёт строгие roots,
scope, правила переноса и допуск отчёта; произвольные семейства не разрешаются.
Готовые Version / Login SDK adapters и их proofs не переписывались под этот lifecycle.

Кэш отдельно каждой роли включает фактические baseline и target chains:
contexts, proofs, semantic reports, exports, инструменты и fixtures. Изменение
вложенного proof / export меняет inputs или оставляет ошибку целостности.
Большие Ghidra artifacts сверяются по SHA без лишнего разбора JSON при чтении lineage.
Внутри frozen прохода SDK seed и PE images переиспользуются; memo key учитывает
полные lineage hashes, а SourceStore проверяет источники после обработки.

Публикуются отдельные `generated-login-metadata/login-metadata/index.json` и
`generated-login-metadata/login-prepare-metadata/index.json` в библиотеке ресурсов.
Same-target повтор сохраняет исходный proof. Эти индексы — базы для следующего
переноса, а не активированные runtime profiles.

Новые suites исполнены по одному разу. Два повтора не запустили native или JVM;
последний использовал шесть этапов кэша. Общий проход 17 drivers переиспользовал
51 этап, без новых JVM / native. Прежние готовые suites не исполнялись повторно;
их caller code мог исполняться внутри нового integration scope.
Selected driver timings не включают предварительный сбор exports и полный аудит установки.

Один субагент подготовил черновик и достиг лимита; второй завершил pure rules,
тесты и независимый аудит. Третий подготовил case contracts и adapter regressions.
Координатор выполнил интеграцию, native acceptance и проверку повторного использования.

Далее — перенос остальных LoginResult input / nested readers / handlers и
registration / response composition, clock / heartbeat и world contracts.
Настоящий SDK backend и provider effects остаются отдельными пробелами.
Авторизация, игровые команды, переключение профиля и онлайн-допуск 1.13.22
этим пакетом не выполнялись.
