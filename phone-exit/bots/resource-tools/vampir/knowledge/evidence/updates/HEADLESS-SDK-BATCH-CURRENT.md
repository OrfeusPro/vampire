# Общий SDK/GMC2/NID пакет 18 → 22

Источник — EXE 1.13.22 с полным SHA
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Последняя проверенная база SDK — 1.13.18,
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Машинная квитанция](AUTO-SDK-BATCH-CURRENT.json) содержит transfer, generation,
native proof, результаты cold / warm и девять component pointers.

## Перенос и генерация

Перенесены 34 roots, две switch tables, четыре leaf / tail тела и две
внутренние code boundaries. Отображение содержит 6465 уникальных связей.
Конструкторы с одинаковой формой различаются по исходному literal и global
destination, наблюдаемому у потребителя. JSON wrappers ограничены связями вызовов.
Каждый root сверяется по полным unwind fragments. NID и platform switch
сравнивают полный code prefix, padding и относительные цели таблиц.
Поиск ограничен ±128 KiB. Неоднозначность отклоняется.

`sdk-batch-transfer.py` использует закреплённый context и финальный native
report базы. `generate-sdk-batch.py` проверяет 12 исходных templates и создаёт
обычные Python-файлы вне Git. Преобразование AST выполняется при генерации.
Native вызовы используют сгенерированные файлы и проверенные EXE / exports.
Недостающий mapping останавливает генерацию до записи файлов.

Коллектор получил оставшийся набор одним успешным пакетом из 31 root,
включая две явные tail targets. До него две попытки остановились на внешнем E9
и запрете нового setter leaf в Java. Неполные выгрузки не использовались.
Новая декларация returning store имеет точные SHA, bytes и transfer pointer.
Python и Java проверяют конечное тело MOV [RIP], ECX; RET длиной семь bytes.
Сбор экспорта использует эту модель только для фактического E9 выбранного caller.

## Исполнение

| Компонент | Native cases |
| --- | --- |
| Defaults / GMC constructor / SDK version | 9 |
| Game override | 106 |
| PC / platform | 12 |
| Constructor → Start | 512 |
| URL | 27 |
| HTTP argument / headers capture | 73 |
| Geo | 672 |
| NID context | 32 |
| NID result | 1100 |
| NID result с actual primitives | 1124 |

Всего 3667 случаев выполнились на target SHA за 44,141 с. Numeric primitives
покрыты 112 входами, channels — 176. Native NID audit проверил семь bindings.
Дополнительная проверка полного target export coverage сверяет все 34 roots
и обе switch tables независимо от replay fixtures.

Опубликованы девять неизменяемых отчётов под `code-clues/`.
Существующий `update-profile.assemble()` построил offline candidate по фактическим
результатам Constructor → Start → URL → Headers и прочим компонентам.
Active startup settings, backend и серверная авторизация ещё требуют проверки.

## Обновление, кэш и сохранение прогресса

Три обязательных source checks SDK имеют явный target-вариант общего runner.
Они используют один native cache. Диспетчер сохраняет SHA всех generated files
и входов в check proof, проверяет их при каждом обращении, включая cached route.
Контекст проверки сверяется с выбранным полным SHA до запуска. Отдельный guard
разрешает внешний Python runtime только по текущему executable и его точному SHA.

SDK bindings текущего SHA зарегистрированы по полученному native результату.
Полный игровой профиль по этому пакету не назначен. Launcher и world-контракты
сохраняют собственные prerequisites.

Runner сохраняет каждый завершённый компонент и неизменный отказ отдельно.
OS lock исключает второго владельца и освобождается после завершения процесса.
Проверенный повтор использовал все 3667 случаев за 0,845 с при нуле native
исполнений и без импорта generated replay modules.

Fixture-проверки воспроизводят прерывание следующего компонента, возобновление,
порчу checkpoint, неизменный отказ, исключение владельцев, неизвестный mapping,
подмену leaf, generated input/output, CRT/source binding и metadata runtime.
Новые инфраструктурные модули включены в штатный tooling gate.

Для следующего SHA предусмотрены отдельные перенос, collect, генерация и исполнение
по этому recipe. Новый target получает собственные exports и proof. Source variant
и runtime context для следующей сборки требуют регистрации после её проверки.
Готовые неизменные материалы используются по проверенному кэшу.

## Границы и следующий шаг

Память SDK, JSON/storage/engine/HTTP effects ограничены объявленными fixtures
проверенных templates. Реальные HTTP запросы и вход не выполнялись.
Исторические native матрицы не запускались повторно. Offline candidate
не подтверждает серверную сессию.

Далее — Launcher keys, request/response dependencies и runtime composition
текущего SHA, затем остальные контракты входа и создания Carnage.
См. [статические entry формы](HEADLESS-SDK-LAUNCHER-ENTRY-11322.md).
