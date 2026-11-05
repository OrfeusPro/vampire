# Групповые квитанции инфраструктурных тестов v1

27 групп покрывают 144 модуля и 480 зарегистрированных зависимостей.
Общий `automatic-update-tooling` сохраняет fixture-only scope, исходный каталог
модулей и стандартный unittest loader. Штатные update / scoped routes используют
новый dispatcher; client checks и frozen producers сохранены.

Холодный проход двух workers: 2036 cases, 4 skips,
248.823 с. Все прежние 1989 case IDs сохранились
с исходной кратностью; проверено сравнением Counters с прежним журналом,
без повторного монолитного прогона.

Неизменный повтор: 0 запущенных групп,
27 групп / 2036 cases из кэша,
10.102 с. Immutable aggregate совпал побайтно.
Реальный dispatcher повторно принял те же квитанции; шесть дополнительных
зарегистрированных проверок прошли. Новых JVM и игровых native replay — ноль.

Ключи учитывают полные SHA выбранных inputs, Python / библиотек и исполняемого
кода. Whole manifest / catalog проверяются отдельно; в ключ группы входит
её запись и программная часть catalog без литерала `MODULES`. Source aliases,
shadow packages и устаревший timestamp `.pyc` не могут подменить выбранный исходник.
Durable group pointer записывается только после свежих source / runtime barriers.
Повреждённая квитанция даёт blocker; failed / timeout требуют явного retry.

Workers получают временные ROOT, собственный Windows Job и handshake до imports.
Завершение родителя / timeout закрывает принадлежащих потомков. Owner OS lock
исключает одновременную запись одного кэша и освобождается после аварии процесса.
До / после сравниваются полные SHA; атомарного filesystem snapshot нет.

AST-аудит намеренно консервативен: общие dispatcher ветки и 11 неоднозначных
прежних inputs сохранены. Изменение общего helper может запускать несколько
групп; узкая зависимость не выводится из одного похожего имени.
Семейные, shared, runtime, damaged receipt, interrupted resume и coverage
сценарии проверены синтетическими fixtures. Один symlink fixture пропущен
из-за прав Windows; существующие skips сохранены. Реальные Job / descendant,
shadow import и stale `.pyc` проверки выполнены.

Игровой вход, native-контракты и online admission этим пакетом не подтверждаются.
Старые v1 requests сохраняют frozen workflow; история не переписывается.
[Запуск, retry и регистрация](../../TOOLING-GROUPS.md).
[Машинная квитанция](AUTO-TOOLING-GROUPS-V1.json).
