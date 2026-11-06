# Проекция прогресса и применение к существующей модели задачи

7 ноября 2026. Клиент 1.13.22, SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Пакет продолжает [приём 1811](HEADLESS-QUEST-REPLY-CURRENT.md)
и [проверку параметров](HEADLESS-QUEST-PARAMETERS-CURRENT.md).
Три недостающих функции выгружены одним collect. Из целой проекции установлена
точная lookup-цель `145b4c280`, полученная отдельным missing-only collect.
Готовые current state / progress exports и 324 сценария использованы повторно
после проверки матрицы, всех retained inputs и aliases. Новый native replay
этих 324 сценариев не выполнялся.
[Контекст и manifests](../../native-contexts/quest-model-current.json).

## Lookup и проекция

79 сценариев исполняют целые `145b4c280` и `145de7870`, а также настоящий
pointer getter `141500740`. Проверены inline / external buckets, пустая map,
free count, пустой bucket, коллизии в начале и конце цепочки, отсутствующий ключ,
null task, signed index и верхняя граница массива. Manager и hash provider —
fixtures; массив и записи созданы стендом, а не реальным CSV loader.

Входной `progress+8` читается как signed byte. Native-код проверяет верхнюю
границу, но не исключает отрицательное значение. Для 16 таких сценариев стенд
явно выделяет отрицательные слоты; runtime их не допускает. Результат получает
ключ из `task+0x40`, virtual kind в `+8`, исходный индекс в `+9`, low32 счётчиков
в `+0x0c` / `+0x10` и нулевой хвост `+0x18`. Padding сохраняется.
Отказ даёт нулевой ключ, kind `1F`, индекс `FF`, нулевые счётчики и хвост.

Диагностические форматирование, вывод и освобождение — fixtures; варианты
выделения строки и объекта проверены независимо. Hash function pointer имеет
единственный явный setup shadow в source-bound слоте `14b0c5b00`: точные CALL,
RIP-цель и восемь байт привязки контролируются, native-запись туда запрещена.
После каждого сценария pointer неизменен. Алгоритм hash этим не подтверждается.

## Обёртка модели

20 сценариев / 32 Win64-вызова связывают целую `1455b4d30` с настоящими
current state `1455f4a70`, progress `1455fd340`, copy и index getter.
Проверены null record, два выравнивания, flags `0/1/2/3/4/255` и strong / weak
счётчики input control. Ключ record намеренно отличается от ключа task / progress:
map и notification получают `record+0x20`, копирование — входной progress.
Callback видит уже скопированный progress и прежний record state; state
записывается после возврата callback.

Map operations, notification, setter, lifecycle и удаление control — fixtures.
Map fixture не удерживает дополнительную ссылку, поэтому её реальное владение
не доказано. Setter `1455e7560` закреплён отдельным 55-байтным окном с четырьмя
virtual tail-слотами; native-исполнение и эффекты этих слотов не заявляются.
Factory и replacement ветви в этой композиции останавливаются trap.

## Фабрика: статические границы

У `1455b8fe0` проверены 1 078 экспортированных инструкций, 108 внутренних
direct branches, 1 024 fallthrough, 31 switch-цель и 23 vtable-слота копирования.
Case 6 ведёт к constructor `1455ab5c0` / table `149907e00`, control constructor
`1455a9330`, shared move `141473540`; общий участок копирует 32 байта progress.
Их source bytes и адреса зафиксированы, но whole helper exports и native
factory execution остаются открытыми. Kind 6 сам по себе не определяет
Time / Dialog: это зависит от параметров конкретного scripted task.

## Обновление и оставшиеся проверки

Отдельный `quest-model-current` включён в штатный `on_update`, собственный кэш
и tooling-группу. Guard удерживает proof, исходники, exports и runtime.
Прежние wire / reader proofs не изменены. При повторе проверяются точная
матрица, SHA и завершающий барьер; конфликт runtime с reused proof отклоняется.
[Машинная приёмка, проверки и измерения](QUEST-MODEL-CURRENT-VALIDATION.json).
Покрытие ограничено текущим SHA; автоматический поиск следующего контекста открыт.

Действующий Bipoberiho сохраняет прежнего владельца. Этот пакет не применяет
native model к живой headless-сессии и не выдаёт `offer_quest_step`.
Открыты загрузка / фильтрация / порядок актуальных QuestTask, factory replacement
closure, настоящие task callbacks, setter и выбор активной задачи. Для действия
дополнительно нужны TargetId, readiness, актуальная позиция после коррекции
движка и ожидаемый подтверждённый переход. Затем нужен отдельный current action
admission и живой сценарий; наблюдения 1811 / 1854 сами по себе не означают успех.
