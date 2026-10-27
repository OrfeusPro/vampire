# Автопроход constructors/tag Version/Login 1.13.18

[Native проверка и ограничения](evidence/updates/HEADLESS-TAG-CONSTRUCTORS-11318.md).

Штатный `update --resume` подтвердил очередь 134 → 122 строки: 12 удалённых
причин, новых нет. Всего закрыто 28 строк из исходных 150.

Закрыты пять reviewed bindings, два context adapter `version-login-tag`,
два `packet-writer-projection`, обязательный compiled-tag check и два ранее
непортированных общих offline checks. Source-specific specs оставляют
старые параметры 1.13.16 неизменными.

В журнале четыре новых context отчёта содержат соответственно 4/56/4/104
native случая для Version tag / Version projection / Login tag / Login
projection. Все passed. Три offline набора используют результаты кэша,
полученные при prepare/finish; ручной перенос их для каждого потребителя
повторно не выполняется. На следующем SHA требуется проверка кандидатов,
а не автоматическое признание текущего результата совместимым.

В завершающем автопроходе новых Ghidra-запусков 0, переиспользовано 9 этапов.
Журнал в библиотеке ресурсов:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
Список: `knowledge/reports/update-manual-queue-11318-122.md`.

Состояние остаётся `needs_review`, profiles пуст, activation и baseline
promotion false. Полные preparation/result и SDK/GMC2/NID ещё нужны перед
профилем и настоящим входом.
