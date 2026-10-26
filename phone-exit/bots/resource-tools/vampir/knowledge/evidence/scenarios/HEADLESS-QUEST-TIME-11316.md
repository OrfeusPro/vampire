# Time задачи: параметры, запуск, два обновления завершения

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK SHA256: `15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
QuestTask entry 2983 SHA256:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Final request: `1bac5e62ebc1c04b222e3619f9eac159553d232b75a50adc274d2c8c8627eaca`.
Предыдущие запросы расширялись по найденным конкретным callees. Collect запроса
665b918c был отклонён до Ghidra: callback 1455b5830 не имеет unwind root.
Его точные пять байт E9 `e91ba8ffff` ведут в root 1455b0050; unwind ему не выдуман.
Текущий replay проверяет bytes/target этого tail и init LEA/CALL по исходному EXE.

## Источники и исполнение

Новые exports с полными SHA256:

- run-6ba3bac90477 — `555fac0e82d64426df3762c5075a6853ca467f5f41eccf8cde21b548ababb0cd`.
- run-3cf3cb9c01a4 — `80c3b3e8bd0821a5f529b7f5f2fefc2a7b7288d23e5e805c9ce80c33be9345cd`.
- run-7260328169ab — `16fd80f57da81e1919f064b280ac6352d788ba184682c9139b3e04fb44218a40`.

Исполняются целиком callback `1455b0050`, start `1455c3eb0`, tick `1455cd9e0`,
timer `14549a800`, completion builder `1455ca200` и exact getter leaf `1455e7510`.
Vtable 149905340 slots +20/+28/+48 сверены с tick/start/init.
Init 1455d2630 связывает data virtual +38, parser 1445d38f0 и callback tail;
init/post 1455d1060/parser здесь **не исполняются**, остаются static navigation.

Две полные исходные CSV строки читаются из текущего PAK: 110120005 / 110120070.
У обеих Type 6, QuestInfoId 110120 и empty service group. Param содержит
`"type":"Time"` и `"seconds":0.1` / `1`. Source JSON decoding/unescaping —
явная Python fixture; native engine text reader и getters значений не доказаны.
Native callback сам сравнивает type со строкой Time, выбирает byte task+118=0
и передаёт адрес task+11C numeric getter для seconds. FString allocation/free
и JSON field getters остаются ограниченными fixtures с проверкой ключей/адресов.

## 24 сценария

Две source durations × 12 режимов, по пять обновлений: половина длительности,
ещё половина, ноль, полная длительность, ноль. Дельты явно округлены float32.
При открытых условиях actual start обнуляет elapsed+1A0, копирует duration
из +11C в +1A4, ставит +1A8=1 и active byte+A0=1. Проверены start status 0x17
(аргумент DL, не весь RDX) и broadcast до таймера.

После достижения duration helper ставит **integer state FFFFFFFF** и elapsed
равным duration. На следующем обновлении он переводит state в 0; tick видит это,
сбрасывает elapsed=0/state=1 и вызывает native completion builder.
Декомпилятор ошибочно отображает integer state как float/NaN; проверяется
исполнение исходных инструкций и точные биты, float enum не вводится.
Для open режима states: `[1, FFFFFFFF, 1, FFFFFFFF, 1]`, число request sink
вызовов после каждого обновления: `[0,0,1,1,2]`.

Если после первого вызова owner record state меняется с 2 на 0, последующий
вызов прекращается: `[0,0,1,1,1]`. Это explicit fixture серверного изменения,
не полученный ответ игры. Без такого изменения native период может повторяться;
переносить его как слепой runtime retry нельзя.

Builder при успешном model lookup формирует именованные свойства
QuestInfoId=110120 и QuestTaskIndex=0 / 5, затем вызывает `1455ca010`.
Getter индекса читает настоящий task+29. Missing model не вызывает request sink.
Свойства фиксируются в памяти fixture; это ещё не packet или server acceptance.

Проверены четыре отказа start: нет owner pointer, control null, strong count 0,
data null. Отдельные tick gates: active false, owner state !=2, environment
byte+30 =5 вместо 6, false predicate 14568cad0, false predicate 14568ca20 при
закрытом data virtual +20. Смысл environment enum и обоих predicates не установлен;
это не подтверждение ServicePhase из серверной таблицы. Остальные таймеры /
animation readiness принудительно готовы в fixtures.
Owner/control/data после выполнения неизменны, кроме explicit state update;
refcounts сбалансированы, строки освобождены, guards task и строк сохранены.

## Границы и продолжение

Model/data lookup, engine environment, оба predicates, other timers, weak-object
проверка, broadcast/status, property bag storage и final request sink — fixtures.
Init/factory/model применения progress и реальный каталог не исполняются вместе
с этой цепочкой. Исходные данные сами по себе не доказывают открытость live gates.
`action_admitted=false`, `network_used=false`; процесс и сессия не меняются.

Далее — route `1455ca010` к конкретному producer/результату, source-bound условия
predicate/readiness и действующий selected model. Engine-corrected actor position
и actual JSON reader остаются открытыми. После этого нужен один owner action с
серверным подтверждением, прежде чем разрешать автопродолжение.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_time_11316.py
```

Контекст `knowledge/native-contexts/quest-time-11316.json`, check
`native-quest-time-11316`, tool `replay-quest-time-11316.py`.
Артефакт: `code-clues/quest-time-11316/5efc68f5e0514614ecf1997a0ae1ef60e3c97057587950112a7916296983fa6e/manifest.json`.
