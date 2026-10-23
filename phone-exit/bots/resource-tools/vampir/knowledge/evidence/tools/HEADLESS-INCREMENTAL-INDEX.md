# Импорт только новых экспортов в базу знаний

23 октября 2026. Исследование вопроса release-update-target-discovery на текущем
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [dispatch проверок](../updates/HEADLESS-UPDATE-CHECK-DISPATCH.md).

## Выявленное повторение

`knowledge-index.py build` уже переиспользовал полностью неизменную базу и
обновлял отдельно документацию. Но добавление нового export переключало его
на полный повторный импорт всех native observations. При последовательных
исследовательских заданиях это повторялось после каждого collect.

Теперь, если tool inputs неизменны, все прежние reports присутствуют и нет
новых completion receipts для ранее непроверенных reports, выполняется
append-only path. Старые artifact / receipt / pseudocode / source SHA и SQLite
integrity проверяются до работы. Создаётся отдельная копия SQLite; в неё
импортируются только добавленные reports существующим source-checked importer.
Context обновляется при изменении его inputs. После импорта повторно проверяются
источники, outputs, inventory, tool inputs и integrity. Только затем закрытая
копия атомарно заменяет рабочую базу.

Удаление report, новый completion receipt и изменение builder dependencies
сохраняют полный rebuild path. Повреждение прежнего или нового evidence
отклоняется; рабочая база при отказе сохраняется. Порядок выбора полных variants
не меняется, неполный export не скрывает полный; одинаковые адреса разных SHA
сохраняются раздельно. При повторе без изменений новые observations не создаются.

## Проверки

13 тестов `test_vampir_knowledge_index.py`: добавлены проверки импорта только
нового report, эквивалентности полному rebuild, разных SHA, повреждения нового
export, повреждения прежнего evidence при новом export, неполного добавленного
variant, нового completion receipt и удаления report без stale observations.
Прежние проверки corruption / placeholders / uncovered switch сохранены.
Также прошли 15 update, 14 workflow и 8 requested-function tests.
Эти tests используют synthetic fixtures и не запускают настоящий Ghidra / auth.

## Замер на настоящей библиотеке

Создан отдельный benchmark index вне Git. В первый полный build включены все
текущие exports, кроме нового `run-7c5a462e9d0c/details.json` с пятью функциями.
Затем добавлен только этот export, затем повторён неизменный build.
Production index и материалы не изменялись. Для девяти таблиц кода обеих баз
посчитаны SHA ordered rows; все совпали: releases, artifacts, functions, variants,
observations, calls, literals, literal_refs, unresolved. Context и metadata
этим сравнением не объявляются побайтово одинаковыми.

| Фаза | Секунды |
| --- | ---: |
| Полный импорт без нового export | 66,000 |
| Добавление одного export / пяти функций | 16,991 |
| Повтор без изменений | 6,864 |

Один последовательный замер на этом ПК, не гарантированная производительность.
Результат не измеряет полный patch audit, время Ghidra, перенос протокола или
живой вход. В append остаются полные проверки SHA; кэш по одному mtime не введён.

Report вне Git:
`F:/PhoneExit Resources/Vampir/knowledge/index-performance/c1b1348e3a0858c15ac8df31eea53669b4eeb3c5c58b16ba79144d2dd51364d8/manifest.json`.
Там записаны source/tool/report SHA, outputs фаз и флаг совпадения таблиц.
Следующие bottlenecks / пакетирование описаны в плане автоматизации обновлений.
