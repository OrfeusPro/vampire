# Выбранные исследования и стабильная публикация v2

Новый слой подключён к обычному `knowledge-index.py update --auto`; существующий
ярлык и `update-watch` используют прежний независимый worker и того же владельца.
Профиль / текущая сессия не переключаются. Машинный selector —
`knowledge/update-engine.json`, каталог семейств — `knowledge/native-drivers-v2/`.
[Машинные отчёты, входы и границы](AUTO-UPDATE-INFRASTRUCTURE-V2-11322.json).

Frozen v1 engines и 59 прежних code/context inputs сохранены побайтно.
Новый native driver использует прежние stage keys и semantic reports; добавление
семейства оформляется отдельным reviewed descriptor с точным module SHA.
Структурная валидность descriptor не является доказательством новой семантики.
После добавления отдельного UTF-8 bridge эти 40 неизменных components / descriptors
сверены по полным SHA; использованные Journal helpers сверены также по AST.
Замеры 34 drivers переиспользованы, сценарии не запускались повторно.

Scoped admission использует SQLite только для поиска кандидатов. Выбранные строки
восстанавливаются из проверенных completion receipt / report / pseudocode и
точного EXE. Подмена body_json/status/name в discovery DB не даёт допуска.
Для frozen adapters создаётся отдельная SQLite только с допущенными строками;
общая search.sqlite3 не переписывается. Missing не означает доказанное отсутствие.
Сбор недостающего ограничен явным набором до 32 адресов и прежним владельцем JVM.

Новый `research-scoped-v2.py prepare → collect → finish` хранит собственные requests,
collection attempts и completions. Повтор использует сохранённые pointers; неизвестный
результат сбора не запускается вслепую. Finish проверяет обязательные checks,
scope результата, evidence, source и атомарную запись facts с сохранением старых
objects / rollback. Tooling check не доказывает client semantics.
Поля вывода question можно обновить между операциями; изменение decision rules
требует нового request. SHA-контексты остаются неизменяемыми входами.

Publication v2 отделяет стабильный алгоритм и выбранные descriptor / release rows
от полного mutable registry. В ключ входят точные context / proof / report,
source, tools, transitive lineage и фактические runtime-файлы. Все прочитанные
mutable selectors проверяются до / после invocation. Первая миграция создаёт
новую квитанцию через полный frozen adapter publish, без native replay;
historical migration inputs учитываются отдельно от последующего selected key.
Старые receipts не переименовываются в новые доказательства.
Старый UTF-8 report связывается по source / bindings / native admission отдельным
typed bridge, без добавления context_sha256 в исторический файл. Его публикация
прошла отдельно за 6,168176 с, повтор из кэша — за 1,190765 с.

Прошли 1162 инфраструктурных теста, из них 80 новых.
Первый общий проход 34 drivers: 738.300569 с; повтор: 185.417547 с.
Повтор использовал 102 этапа и 34 публикации из кэша, без native / JVM / native PE
rebuild. Admission headers PE проверяются отдельно; нулевое SHA I/O не обещается.
На реальных 12 exports scoped prepare занял [4.084042, 3.9868] с,
collect — [1.580999, 1.516532] с, finish —
[5.557242, 5.098418] с. Глобальных historical pseudocode
reads в scoped пути — 0. Benchmark использовал отдельную копию facts и сохранил
24 старых fact objects; product facts им не менялись.
Полный тёплый проход v2 здесь медленнее прежнего v1 замера 118,639629 с:
есть дополнительные selected admission проверки и 84 SourceStore validation reads.
Ускорение всего обновления этим результатом не заявляется; следующий шаг —
убрать повторные проверки внутри одного frozen invocation с сохранением барьера.

Область квитанции — `selected_materials_only`, `global_history_verified=false`.
Повреждение выбранного материала блокирует использование, даже при прежних
size/mtime. Неиспользованная история этим проходом не сертифицируется.
Обязательная `knowledge-index.py check` перед коммитом сохранена; это отдельный
полный аудит. Он не заменяет semantic checks и проверку числового смысла.
Отдельный обычный CLI plan-only завершил SHA inventory установки, затем был
остановлен во время долгой legacy resource-readiness сверки. Аудит сохранён;
этот диагностический запуск не считается завершённой проверкой всего update.
Повторное чтение исторических resource inputs остаётся отдельным блокером скорости.

Следующий общий native блок — frame / writer / CRC-XOR → queue с lifecycle.
SDK / clock / heartbeat / world, engine helpers и онлайн-допуск остаются отдельными
неподтверждёнными контрактами. Новые команды и границы описаны в
[инструкции обновления](../../RESUMABLE-UPDATE.md) и
[порядке исследования](../../RESEARCH-WORKFLOW.md).
