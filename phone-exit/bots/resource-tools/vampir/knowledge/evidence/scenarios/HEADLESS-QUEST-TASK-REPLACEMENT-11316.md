# Создание и замена объекта задачи

Источник EXE 1.13.16 SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки существующего task](HEADLESS-QUEST-STATE-APPLICATION-11316.md).
Это offline replay с синтетической памятью; игровых команд и чтения процесса нет.

## Что исполняется

Целые state / progress `1455f4a80` / `1455fd350`, factory `1455b8ff0`,
constructor case 6 `1455ab5d0`, control constructor `1455a9340` и shared move/release
`1414734e0`. После применения исполняется sender getter `1455e7510`.
Factory вызывается только с kind 6. При отказе первого object allocation
исполняется её настоящий fallback. Остальные kinds не покрыты этим replay.

Нативны создание полей control block, перенос ссылки, LOCK XADD счётчиков,
условия вызова destructor / free, выбор factory branch, constructor stores,
копирование progress и сохранение record state. Внешние действия не приписываются
этому результату: allocator, memset, вложенные delegate / string / container init,
task-data lookup, lifecycle, owner binding, destructor и free — явные fixtures.

## Сценарии и проверяемые инварианты

378 сценариев: keys 0 / 110120005 / UINT64_MAX; record без task или с отличающимся
old key на -1 / +1 по модулю uint64; new state 0 / 2 / 255; index 0 / 1 / 255;
успех / отказ primary allocation. Для existing control проверены initial strong /
weak 1/1, 1/2 и 2/1; для empty record control отсутствует. Old state равен 2 при
index 1, иначе 0: эти параметры не образуют независимый Cartesian product.

- 189 успехов: table `149905340`, все 32 байта progress сохранены в task+0x20,
  getter читает index по +0x29; task-data / init / post вызываются по одному разу.
- 189 fallback: table `149903d68`, key 0, kind 31 / index 255; success init / data
  lookup не вызываются, лог отказа и освобождение временного null control — по разу.
- Final record владеет новым task/control, strong=1 / weak=1. При old strong=2
  остаётся strong=1 без destructor; при strong=1 вызывается destructor, а free
  зависит от прежнего weak. Эффекты этих двух callbacks не исполняются.
- Old advance определяется настоящим signed JGE по key; это не доказательство
  игрового порядка заданий. Callback вызывается до освобождения старого control.
- New start вызывается только при state 2, после owner binding / установки новой
  ссылки, но до записи нового record state. Старый task, input, record padding,
  old control padding и guards всех heap allocations сохраняются.

Parent weak control отсутствует, optional provider cache отключён, task-data lookup,
fallback object и control allocations успешны. Отказ control allocation, остальных
ветвей factory, загрузка настоящих таблиц и реальные lifecycle эффекты не проверены.
Необычные ID / state / index — тестовые входы native кода, не runtime разрешения.

Тест `test_vampir_quest_task_replacement_11316.py` прошёл; offline check
`native-quest-task-replacement-11316` закрепляет зависимости, exports и контексты.
Артефакт:
`code-clues/quest-task-replacement-11316/2da841aa88230480c5900763e2e57d35c128f9b3d9c2222684f9ec9a91e93c24/manifest.json`.

## Обнаруженный пропуск экспорта

Первый запуск остановлен строгим native harness по `1455ba01a`. Старый factory
export `run-8087d5072f02` не содержал этот fallthrough после JNZ `1455ba018`,
хотя decompiler block coverage был true. Он сохраняется как исторический материал;
прежняя matching-task проверка factory не исполняла и не доказывала этот путь.

Индекс теперь отмечает неполным block-covered export, если у обычного короткого /
длинного x64 Jcc отсутствует следующая инструкция. Это отдельная проверка двух
основных encodings, не полный decoder всех вариантов x86 flow.
Ghidra дополнительно обходит native fallthrough / jump destinations внутри явных
unwind ranges с конечным бюджетом. Не расширяет набор roots и не следует внешним
callee. Collector требует direct_flow_coverage_complete; неполный листинг не sealed.

Новый factory export `run-2c32a5472a00`: 1078 instructions / 5147 bytes,
на 17 инструкций / 57 байт больше прежнего, включая ветку без optional cache.
Shared helpers: `run-4511094667cb`. Остальные два exports прежние;
полные SHA и исключение старого factory export закреплены в
`knowledge/native-contexts/quest-task-replacement-11316.json`.
Новый collector действительно выполнен на закреплённой Ghidra / JDK.

14 tests индекса, 14 collector tests и 14 workflow tests прошли, в том числе
запрет sealing без native direct-flow coverage и обнаружение missing Jcc fallthrough.

## Дальше

Связать загрузку / порядок task map с current QuestTask CSV и живым progress,
затем допускать конкретное действие через owner adapter. Полное выполнение игры,
route, dialogue / skip / equip не подтверждены. Текущая онлайн-сессия сохранена;
runtime contracts и игровые команды не включались.
