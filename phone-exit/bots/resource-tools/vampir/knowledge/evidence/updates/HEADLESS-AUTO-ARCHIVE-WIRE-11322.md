# Автоматический archive-wire 20 → 22

28 октября 2026. Target 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Baseline 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
[Машинная квитанция](AUTO-ARCHIVE-WIRE-11322.json).

## Результат и область

Generic `archive-wire-v1` использует опубликованный string-writer target SHA,
автоматически переносит архивные методы и целые Version / Login wire writers.
На реальном EXE 1.13.22 выполнены 45 сценариев archive IO и 64 полных тела
Version / Login. Сверяются байты, размеры, порядок полей, canaries, временные
выделения / освобождения и Win64 ABI, включая R13 и XMM6–XMM15.

Общий wire пакет теперь имеет отдельные действующие native квитанции того же SHA:
222 UTF-8 + 228 string writer + 109 archive / packet = 559 сценариев.
При добавлении archive adapter прежние самостоятельные UTF-8 / writer suites
не повторялись. В новых packet сценариях эти функции исполняются как часть
проверяемой цепочки. Результат не подтверждает игровой вход или runtime admission.

Область: 14 настоящих unwind roots и три ограниченных leaf spans. Growth body
не экспортируется и не исполняется: его адрес должен быть unwind entry без alias
с roots / leaves / fixtures, а достижение всегда отклоняется. Аллокаторы, free,
memcpy и security остаются явными fixtures. Архив заранее выделен на 16 КиБ.

## Перенос и доказательства

По полной форме инструкций находятся девять archive roots и два packet writers.
Каждый callee / RIP edge связывается с типизированной ролью; несогласованные
переносы, внешние branches, новый indirect dispatch и несколько кандидатов
дают конкретный блокер. Некорректный посторонний кандидат исключается из поиска;
ошибка декодирования доказанной базы останавливает перенос.

Raw writer `0x144aacaf0` включает все три chained fragments, а не только первые
33 байта. Их покрытие проверяется по реальным экспортам и PE.
Архивная таблица осталась на `0x149673420`, но её полный target SHA изменился:
`9f0a27d4134d973e2886e9b5a9bdabdcb4df0c602dc693fff8fb156a099da2ec`.
Подтверждены семь вызываемых slots и alias topology. Остальные 24 slots
закреплены как данные и явно исключены из semantic coverage.
Две transient vptr tables учитываются как перезаписываемые ссылки конструктора;
вызов методов через них не допускается.

Version writer перенесён на `0x1456e8a30`, Login writer — на `0x1456e8520`.
Таблицы находятся по writer slot `+0x10`; прежние размеры / поля пакетов
подтверждаются полной инструкционной формой и независимым native ожиданием.

## Автоматизация и проверки

Правило зарегистрировано в [native-check-adapters.json](../../native-check-adapters.json)
и вызывается штатным `update --auto` после string writer. Driver использует общий
Journal и missing-only collector. Три roots переиспользованы; 11 missing roots
получены одним collect в прежнем Ghidra project. Полного анализа EXE не было.

Context / proof / native report неизменяемы; указатель следующей базы этого
семейства хранится в `knowledge/generated-archive-wire/index.json` библиотеки.
Он используется самим archive adapter для следующего патча, отдельно от исторических
catalog projections и next-profile. Готовые UTF-8 / writer proof engines не менялись.
Изменения независимого семейства не требуют повторения готового writer suite.

23 новых synthetic tests проверяют edge mapping, таблицы, ambiguity / decode,
growth boundaries, native scope, подмену proof и публикацию. Три дополнительных
теста общего driver используют настоящий Journal: изменение archive пересчитывает
только archive; неизменный повтор переиспользует оба семейства. Агрегат — 93 tests.
Реальные проходы выбранных drivers и времена перечислены в машинной квитанции;
они не являются замером полного аудита установки.

Дальнейшие пакеты: preparation / SDK / metadata, response readers / handlers,
clock / heartbeat и world contracts. Framing, OS / engine effects, allocation
failure, рост архива, настоящая сеть и серверное принятие не подтверждены.
Новый игровой профиль не активирован, авторизация и игровые действия не выполнялись.
