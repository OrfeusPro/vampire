# Автопроход VersionResult reader 1.13.18

[Native проверка и границы](evidence/updates/HEADLESS-VERSION-RESULT-READER-11318.md).

Штатный `update --resume` подтвердил очередь 100 → 98 строк: удалены две
причины (reader binding и `native-version-result-context`), новых нет.
Всего закрыто 52 строки из исходных 150. Новый общий input archive готов
к отдельной композиции со следующими result readers; это не подтверждает их
поля или handlers автоматически.

Пять тестов, 127 native случаев прошли. Source-specific context и повторяемый
alignment включены в зарегистрированный `on_update` check; полные SHA tools,
contexts, runtime и exports входят в dependency cache. Подмена base table
старого SHA отклоняется. Завершающий проход использовал сохранённый report,
новых Ghidra-запусков 0, переиспользовано 9 этапов.

Журнал в библиотеке ресурсов:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
Список: `knowledge/reports/update-manual-queue-11318-98.md`.

Следующий конкретный unknown — gate switch. Ограниченный разбор сохранил
`code-clues/version-gate-switch-11318/c73646164419b35c2e5cd721c6c67fb13a730a643a59cfe71f5a72a6074f3abe/manifest.json`.
Dispatch `1467CDE9D`: index table `1467CE0A8`, 227 bytes, значения 0..3;
RVA table `1467CE098`, четыре элемента. Цели `1467CE065`, `1467CDE9F`,
`1467CDFA7`, `1467CE065` находятся на границах инструкций до RET. Это
статическая навигация с полным SHA EXE, не native gate proof. Нужно проверить
switch mapping/code-data separation и registration/handler composition.

`needs_review`, profiles пуст, activation/baseline promotion false. SDK,
Login и настоящий вход ещё не подтверждены.
