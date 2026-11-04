# Автоматическая проверка данных Map 10/11

Штатный resource pipeline теперь проверяет текущие именованные Map / World
для ранее изученной проекции Map 10/11. Это отдельная проверка данных.
Native-перенос трёх функций карты, runtime выбор мира и геометрия UI остаются
неподтверждёнными для текущего EXE; исходная allowlist не расширялась.

## Что считается входом

Selector resource-map-tables.json закрепляет точный archive slot pakchunk1
и canonical paths CSV/Map.csv, CSV/World.csv. Таблицы принимаются из готового
авторитетного directory report того же SHA owner; проверяются source SHA,
reader rules / runtime, имя, payload SHA, размер, header и число строк.
Другие CSV не угадываются по схеме или похожему набору колонок.
Полный архив и клиент входят в свежий общий барьер.

База — неизменяемая копия данных из ранее проверенного map-projection-audit
для EXE 98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e. Его полный SHA, captured table manifest
и точные SHA старых Map / World CSV проверяются. Отдельно сохранён projection
JSON, совпавший с parent audit. Baseline maps / worlds / geometry выводятся
из этих bytes и сверяются заново. Это captured evidence; старый PAK не
читается как текущий. Исторический атлас и старый аудитор не переписывались.

## Результат на текущем клиенте

EXE: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f; ресурсный патч Revision268356.
Map содержит 163 строки, World — 263. Все 15 полей двух строк Map 10/11
точно совпали с базой, включая GroundDistance / CenterX / CenterY и resource
selection fields. Состав относящихся к этим картам миров и их Id / MapId /
LevelPath совпал: 36 миров. Дополнительные строки вне выбранных карт не
считаются подтверждёнными проекциями. Изменения иных полей World также
не выдаются за проверку их семантики.

Проверяются уникальность Id и корректная CSV-структура. Изменение проверяемых
Map полей / состава колонок, исчезновение или добавление относящегося мира,
другой LevelPath / MapId оставляют конкретные requires_review reasons.
Unknown/missing/ambiguous named table и неполный каталог не получают data_matched.
Положительный результат содержит target_native_projection_verified=false,
runtime_activated=false и profile_activated=false.

## Обновление, кэш и журнал

Map table adapter включён selector и definitions; resource pipeline наблюдает
обработанные архивы, готовит анализ до owner barrier и публикует квитанцию
после его успеха. Отказ проверки попадает в очередь обычного update.
В журнале результат доступен как map_table_data, копия — metrics.resource_pipeline.map_tables.

Анализы — resource-map-table-results-v1, квитанции — resource-map-table-receipts-v1
библиотеки. Cache pointers — knowledge/resource-comparison-cache-v3/map-tables-<key>.json.
Ключ учитывает target client SHA, exact baseline / current named / table pointers,
наблюдённые источники, код, selector и runtime. Неизменный результат используется
после fresh SHA проверки; порча bytes не запускает тихую пересборку.
Изменение installation / source / artifacts / runtime препятствует публикации.

Реальный компонентный проход одного архива занял 29.780016 с:
один новый анализ двух таблиц. Повтор — 19.515981 с, один cache hit,
ноль новых analyses. Data pointer сохранился, свежая owner receipt новая.
Готовые directory / CSV использованы повторно; новых record decode, CSV
extraction, native replay, JVM и полного ordinary CLI update не было.

## Проверки и следующие общие пакеты

Добавлены 22 автоматических случая: поля Map / World, membership, посторонние
строки / колонки World, duplicate IDs, malformed CSV, источники / pointers,
baseline ancestry, cache corruption, SHA barrier, hook pipeline и очередь update.
Общий набор завершил 1787 тестов с тремя прежними пропусками; шесть
дополнительных checks прошли. Проверка подключена к aggregate on_update.

Данные Map 10/11 на текущем SHA подготовлены в указанной области; три старые
native map functions ещё требуют своего переноса и проверки цепочки. Текстуры,
проходимость, engine correction, UI bindings и полная runtime dependency closure
этим результатом не подтверждены. Лёгкий MapProjection и профиль игры не менялись.

Для квестов / обучения более новая доказанная база находится на d00a... /
1.13.16, а не в legacy checks 98802... . Ближайший общий пакет — input archive,
QuestSync 1854 и Tutorial 9905: 22 уникальные основные функции, из них девять
общих. Использовать готовые contexts quest-sync-11316 / tutorial-update-11316;
затем отдельно QuestUpdate 1810 / quest-update-wire-11316. Действующий output
archive-wire GameVersion / GameLogin не подтверждает эти input callbacks.
Готового adapters-only переноса нет; native-tutorial пока unsupported.

Ресурсные 54 inputs и 247 hashes не требуют повторного декодирования.
Watcher, сессии, prepared-next и admission не менялись. Сохранены 59 frozen
native inputs, 49 прежних facts и исторические разделы документации.

- [Машинный отчёт](AUTO-RESOURCE-MAP-TABLES-V1-268356.json).
- [Историческая проекция](../maps/HEADLESS-MAP-POSITION.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
