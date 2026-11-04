# Подтверждённые имена ресурсов и адаптер directory v1

[Машинный selector](../../resource-directory-engine.json) включает отдельный
адаптер в штатном resource-pipeline-v3. Новая проверенная привязка хранится
отдельно от bounded record scan: его исходные поля и receipts не переписаны.
Новый адаптер не выполняет native-код, не запускает Ghidra и не сохраняет ключ.

Исторический key proof фиксирует полный SHA EXE, целые fragments и четыре
готовых native cases. Helper сверяет все bytes инструкции по source file
offset, дизассемблирует их Capstone и собирает восемь последовательных dword
literal stores только в памяти. SHA результата обязан совпасть со всеми
четырьмя сохранёнными outputs. Это кандидат для расшифровки; binding callback
в текущем EXE остаётся unverified. Готовый native replay не повторяется.

Для каждого PAK сверяются полный archive SHA, AES main-index и full-directory
SHA1, bounds/counts каталога и encoded table. Ограниченный prefix reader
читает position / sizes / method / encryption fields без block-array decoder.
Смещение, размеры и flags сопоставляются с точным record-index. Существующий
CSV verifier заново проверяет source / record / runtime / outputs. Только затем
имя связывается с payload SHA. Имя не выводится из schema или похожего содержимого.

Разрешены проверенные multiblock prefixes и пустые stored entries. Последние
встречены в настоящем INI каталоге с обоими размерами 0; сжатые нулевые записи
отклоняются. Полный SHA архива, доказательства, helpers, runtime и selector
входят в ключ кэша. Ключевые bytes не попадают в отчёт или diagnostic.

## Реальные результаты Revision268356

На девяти изменившихся PAK прочитаны 53 299 имён каталога. Нормализованные
mount/path подтверждены для 48 023 записей. Для 5276 raw paths с начальным
slash canonical join оставлен неизвестным; исходные строки сохранены.
Это один общий пробел формы пути. Все 3109 CSV-файлов получили точные имена,
unmatched CSV records — 0.

Ещё одна CSV-подобная запись в pakchunk0 на деле имеет имя
ProjectRED/Content/RED/Data/DataVerification/PathFindingGolden.txt.
Прежний счётчик 3110 относился к результату синтаксического CSV-парсера;
имя и назначение файла из этого счётчика не следуют.

У 755 текущих именованных CSV-записей payload не встречался среди прежних
CSV того же архива; они содержат 754 уникальных новых bytes. Это отдельная
сверка exact CSV hashes, независимая от меньшего record decode budget.
Подтверждены текущие пути CSV/Npc.csv, NpcBattle.csv, NpcSpawn.csv, World.csv,
WorldSpot.csv и QuestTaskAction.csv. Из изменённых русских текстов названы
CSV/L10N/ru/Npc_Name.csv, QuestTask_Name.csv, World_Name.csv и WorldSpot_Name.csv.
Файлы и hashes доступны в details receipt. Их игровое применение не подтверждалось.

Первый полный компонентный проход занял 36,089681 с и назначил девять
результатов после общего свежего SHA/alias/output barrier. Второй занял
35,327489 с: девять cache hits, ноль новых результатов. Тёплый проход заново
аутентифицирует небольшие индексы и проверяет имена; он не повторяет native
replay или CSV extraction. Кандидат ключа восстанавливается статически один
раз на проход и очищается при закрытии Scope.

## Включение, проверки и границы

При отсутствии selector сохраняется прежний pipeline. С ним каждый новый
архив получает собственное доказательство по фактическому SHA без списка
версий в Python. Результат содержит named report и конкретный blocker,
если часть путей / CSV не связана. Ошибка directory сохраняет готовые CSV.
Cache pointers назначает общий owner после заключительного барьера; при
повреждении, неоднозначности, смене source/runtime или retarget выдаётся отказ.

Добавлены 39 автоматических случаев: 16 чистого формата и 23 Scope/pipeline.
Проверены SHA-bound literal proof, multiblock/empty/truncation, mount traversal,
точные offset-привязки, same-content/different-name, unmatched/ambiguous paths,
AES/SHA1 roundtrip и повреждение ciphertext/footer, cache tamper, deferred
publication и fresh source/runtime failures. Настоящие PAK проверены отдельно
от fixtures. Зарегистрированный набор завершил 1608 тестов с тремя прежними
пропусками; шесть дополнительных checks и knowledge validation прошли.

Текущие названия не доказывают идентичность старых unnamed table baselines.
План потребителей пока остаётся консервативным. Runtime / profile admission,
semantic checks и текущая игровая сессия не повышались. Полный ordinary update
и онлайн этим компонентным результатом не заменяются. Watcher не включался.

- [Машинный отчёт](AUTO-RESOURCE-DIRECTORY-V1-268356.json).
- [Предыдущий патч без имён](HEADLESS-RESOURCE-PATCH-268356-11322.md).
- [Порядок обновления](../../RESUMABLE-UPDATE.md).
