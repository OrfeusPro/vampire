# Native Login: publisher → backend → writer / framing / cleanup, 1.13.22

Источник — `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Машинные указатели и измерения:
[AUTO-LOGIN-BACKEND-WIRE-11322.json](AUTO-LOGIN-BACKEND-WIRE-11322.json).
Правило `backend-wire-v1` / `login-backend-wire` подключено к автоматическому
обновлению и кэшу. Этот bounded replay не допускает целый игровой вход.

## Исполняемая цепочка

Нативный publisher инициализирует service object и публикует singleton. Внутри
него сначала записывается базовая vtable, затем вызывается явный helper fixture
и устанавливаются окончательные primary / secondary vtables. Publisher обнуляет
`service+0x10`; последующая привязка подготовленного backend — отдельный ambient
provider. Готовность к конкурентному использованию, реальный backend assignment
и полный lifecycle сервиса этим не доказываются.

После setup выполняется один native prepare. Подготовленный packet проходит
SDK / metadata → sender → service getter → исходный service slot `+0x38` →
thunk с загрузкой RCX из `service+0x10` → backend → packet slot `+0x10` → Login
writer. Координатор не вызывает backend / thunk / writer отдельно и не записывает
готовые ожидаемые bytes в archive. Service vtable берётся из EXE, синтетический
sink прежнего пакета в этой проверке отсутствует.

Допуск фиксирован: 29 целых функций, 13 returning leaves и 3 tail fragments.
Packet — 320 байт, session — 160, service — 240, backend storage — 784,
каждый stack archive — 64. Source backend достигает byte `+0x300`; дополнительный
storage и guards не расширяют область допустимых native writes. Version writer
не включён. Все whole instructions, branch / call relations, используемые table
slots и source inputs привязаны к полному SHA. Tail fragments отделены от
returning leaves; append выполняет исходный terminal `JMP RAX` в archive raw slot.

## Байты, провайдеры и память

Исходный ID getter возвращает 3; pending response ID 4 — отдельный ID.
В inner archive записываются `U16LE(3)`, старый sequence и 25 полей Login.
Хранимый sequence увеличивается modulo 65536. FString lengths — длины UTF-8,
scalars — little-endian, bool archive сохраняет raw bytes, включая `0x80` / `0xff`.

Frame содержит 3 младших little-endian байта `inner_size + 7`, checksum provider
result и весь inner. Fixture checksum `0x6a09e667` получает именно весь inner,
включая ID и старый sequence. Identity transform наблюдает alias / key / диапазон
`frame+3 … end`; первые 3 bytes не входят в transform. Настоящие checksum / cipher
algorithms здесь не исполняются. Transport fixture копирует настоящий native
frame до cleanup и возвращает AL 0 / 1 при непрозрачных старших битах RAX.
Ни отправка в сеть, ни асинхронное владение transport не доказаны.

Archive flags и поле enum, используемое в packet `+0x120`, читаются из одного
исходного global. Per-case provider задаёт 0 / `0xffffffff`; оба конструктора
архивов получают то же текущее значение. File-backed initial value 1 остаётся
статическим anchor и не выдаётся за аргумент всех сценариев.

Исходный raw writer сам запрашивает первый capacity 1024. Bounded growth fixture
выделяет память по этому вызову и создаёт vector begin / end / capacity, где end
равен begin + capacity. Перераспределение, aligned allocation, OOM / SEH находятся
вне проверенной области. Prepared body — 91–807 bytes, inner — 95–811,
frame — 102–818; два initial buffers достаточны для этой матрицы.

У подготовки, UTF-8 / C++ temporaries и архивов один guarded allocation ledger.
Callback определяется исходным caller, ролью, видом allocation и размером;
одинаковый адрес fixture не позволяет случайно подменить ABI последним installer.
Prepared packet / строки сохраняются до destructor. Inner buffer защищается от
записи после writer, outer — после transport capture. Cleanup идёт outer → inner,
до возврата sender и prepare destructor; повторное / чужое освобождение и доступ
к retired buffer отклоняются. Соседние stack archives не разделяются искусственными
canaries, которые меняли бы соседний объект. Проверяются Win64 nonvolatile registers,
stack и допустимые поля native writes.

## Матрица и приёмка

1807 сценариев: 224 независимых prepared inputs × 4 pending states × 2 transport
policy bytes = 1792; ещё 15 focused negative cases достигают backend через miss.
Sequence seeds: 0 / `0xfffe` / `0xffff`; debug branches используют разные diagnostic
words `[1,0]`, включая short circuit. При pending hit transport policy не
наблюдается и не считается полученным исходом.

1807 native сценариев и 902 теста общего набора прошли.
Наблюдались 1359 backend calls, 1344 writer / checksum / transform / transport captures, 448 pending hits, 6 fallback calls и 444 sequence wrap.
По 2688 constructor / initial growth / cleanup calls; реальные archive flags и ID getter return проверены.
Первый проход нового семейства: 2772.507949 с.
Последний повтор: 3 этапа и одна publication receipt из кэша за 27.192972 с, без JVM / native replay.
Общий проход 31 drivers: 1824.417842 с; тёплый: 302.339482 с.
Оба использовали 93 готовых semantic stages; тёплый переиспользовал 31 publication без transfer / publish и PE rebuild.
Byte SHA 50 tools / contexts совпали с Git checkout. Готовые parent native suites не повторялись; новых экспортов и JVM не было.
Измерения drivers не включают prepare и глобальную проверку исторического индекса.

Ожидаемые поля берутся из отдельно доказанного prepare report. Byte oracle
сравнивает captured native bytes с независимой схемой; фактические counters
агрегируются из результатов. Error diagnostics сохраняют source / proof / tools /
spec и actual row, если она получена. Ранний guard failure сохраняется без
придуманной actual row и не публикуется как пройденный сценарий.

## Открытые границы

Pending insertion / delegate, SDK / OS / engine / storage providers, allocation,
checksum / cipher / transport effects остаются явными fixtures. Реальные
service backend assignment / lifetime и asynchronous ownership требуют отдельного
общего source-bound исследования. Также открыты Version sender, clock / heartbeat,
остальные entry / world contracts и текущий online admission.

Текущая игровая сессия и prepared bundle не менялись. Ограниченный native proof
не заменяет фактический онлайн-вход и серверное подтверждение.
