# Создание и замена задачи типа 6 в текущем клиенте

7 ноября 2026. Клиент 1.13.22, SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Пакет продолжает [lookup / проекцию и существующую модель](HEADLESS-QUEST-MODEL-CURRENT.md).
Два недостающих конструктора получены одним scoped collect. Whole shared
move / release уже был в готовом current экспорте; factory и state / progress
также использованы повторно. Прежние 378 сценариев другого SHA не запускались.
[Точные функции, exports и границы](../../native-contexts/quest-task-replacement-current.json).

## Исполненная цепочка

48 сценариев / 96 Win64-вызовов исполняют current factory `1455b8fe0`,
case-6 constructor `1455ab5c0`, control constructor `1455a9330`, shared move /
release `141473540`, state / progress и index getter. Все обычные roots сверены
с целыми unwind ranges. Для factory с inline switch data применяется локальный
адаптер уже проверенного листинга: source bytes 1 078 инструкций, внутренние
ветвления, fallthrough и 31 switch-цель проверяются перед его использованием.
Общий native harness не изменён. Прочие ветви factory не исполняются.

Матрица покрывает пустой record и замену существующего task с отличающимся
ключом, два выравнивания, state `0/2/255`, index `0/1/255`, success и primary
allocation failure, strong / weak `1/1`, `1/2`, `2/1`. Включены знаковые границы
ключа и wrap uint64. Native signed comparison определяет вызов old advance;
это не доказательство игрового порядка заданий.

При 24 успешных выделениях создаётся task table `149907e00`; все 32 байта
progress копируются в `task+0x20`, getter затем читает индекс из `+0x29`.
В остальных 24 сценариях исполняется fallback после отказа primary allocation:
table `149906828`, нулевой key, kind `1F`, index `FF`, без success data/init.
Final record получает новый task/control с strong=1 и weak=1.

Реально исполняются stores конструктора, атомарные изменения счётчиков,
перенос ссылки и условия вызова destructor / free. Old task, входной progress,
данные, padding record/control и guards выделений сохраняются. Проверяется
порядок old advance / освобождения, owner binding и start до записи нового state.
Метрики закрепляют не только 96 ABI-вызовов: factory/state/progress/getter
имеют по 48 входов, case-6 constructor — 24, control — 48, shared move — 96;
также проверяются все 656 fixture-вызовов.

## Что остаётся fixtures

Allocator, memset, вложенные delegate/string/container init, task-data lookup,
owner binding, lifecycle, destructor и free имеют явные ограниченные providers.
Init slot `+0x48` ведёт в `1455d2620`: его эффект здесь fixture, а прежняя
проверка передачи Param не считается выполнением сценария. Parent weak control
равен нулю, optional cache отключён по проверенному source global. Отказы control,
fallback allocation и data lookup, другие kinds и реальные callbacks не покрыты.

Kind 6 означает scripted task. Он не определяет Time / Dialog / LevelSequence
без параметров конкретной строки и проверки соответствующего исполнителя.
Новое доказательство не задаёт активную задачу, позицию актёра, TargetId,
readiness или допустимый запрос в игру.

## Обновление и следующий пакет

Отдельный `quest-task-replacement-current` подключён к штатному `on_update`
и своей tooling-группе. Кэш удерживает исходный SHA, exports, code, runtime
и доказанный пакет модели. Его матрицы переиспользуются без native replay;
финальный SHA-барьер сохраняется. Проверка повреждённого результата, отсутствия
constructor coverage, runtime conflict и запрет повторного исполнения входят
в автоматический набор. [Машинная приёмка](QUEST-TASK-REPLACEMENT-CURRENT-VALIDATION.json).
Покрытие ограничено этим SHA; поиск контекста следующей версии ещё открыт.

Bipoberiho остаётся в прежней онлайн-сессии. Следующий общий пакет — реальная
загрузка и порядок актуальных QuestTask, включая фильтр service group и RU
override. Навигация по current manager дала candidates `145b54bb0`,
`145b5f680`, `145b6a0b0`; whole exports и semantic перенос для них ещё нужны.
Текущие таблицы уже извлечены: повторная распаковка не требуется. После порядка
каталога остаются реальные task callbacks, provider действия и отдельный current
action admission с проверкой результата. Игровые команды в этом пакете не отправлялись.
