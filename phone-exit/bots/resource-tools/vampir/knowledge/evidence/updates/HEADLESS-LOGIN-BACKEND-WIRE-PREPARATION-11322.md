# Подготовка общего Login backend / wire стенда, 1.13.22

Источник — `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Это статическая подготовка следующего эксперимента. Новый native adapter пока
не опубликован, 1807 сценариев не исполнялись. Предыдущие 30 drivers и их
доказательства остаются самостоятельными результатами.

## Готовые материалы и автоматизация

Машинный [рецепт](../../research-recipes/login-backend-wire-11322.json) содержит
точные указатели на готовые handoff / wire contexts и подготовленные поля,
четыре новых целых экспорта, три дополнительных returning fragments, три tail
fragments, таблицы, исходные данные и SHA матрицы. Адреса из Markdown не читаются.

[Проверка исходников](../../../login-backend-wire-source.py) сверяет полный SHA
EXE, целые инструкции и границы экспорта, исходные таблицы и переходы, целостность
родительских proofs / reports и prepared input. Она не запускает готовые native
suites, JVM или игру. Изменённые данные, неполные exports и неизвестные переходы
дают конкретный отказ. Рецепт не включается в реестр native admission.

Воспроизводимый запуск из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/login-backend-wire-source.py --recipe phone-exit/bots/resource-tools/vampir/knowledge/research-recipes/login-backend-wire-11322.json
```

Исходная связь установлена: service publisher → primary vtable `+0x38` →
RCX-adjusting thunk → backend → packet vtable `+0x10` → Login writer.
Новые whole roots: publisher — 43 инструкции / 214 байт, backend — 120 / 488,
append — 19 / 69, cleanup — 37 / 133. Общий будущий допуск — 29 whole roots,
13 returning leaves и 3 tail fragments. Version writer в этот набор не входит.

Первый сбор append / cleanup остановился: Ghidra проследовала за cleanup tail
за границы запрошенного unwind range. Добавлена ограниченная source-specific
модель `LEA / MOV / JMP`: точные байты, SHA, исходная таблица и конечный адрес.
Изменение любого из них отклоняется. Модель меняет только analysis metadata;
EXE и требования полного покрытия не меняются. Новый запрос получил только два
missing roots; publisher / backend повторно не выгружались. Failed run сохранён.

## Контракт следующего общего прохода

[Матрица](../../../login-backend-wire-case-contracts.py) содержит 1792 основных
входа: 224 подготовленных варианта × 4 pending states × 2 transport policy bytes.
Ещё 15 входов проверяют backend gates на трёх подготовленных примерах. Все
отрицательные случаи достигают backend через pending miss; их sequence seeds
различаются, чтобы обнаруживать незаметный сброс состояния.

По исходным ветвям ожидаются 1344 writer / transport calls, 448 pending hits,
1359 backend calls и 6 fallback calls. На pending hit transport policy не
наблюдается и не выдаётся за полученный исход. Это ожидаемые количества,
а не результаты native выполнения.

[Независимый byte oracle](../../../login-backend-wire-oracle.py) строит ожидание
по 25 полям готового Login: UTF-8 длины строк, little-endian scalars и сырые bool
bytes, включая `0x80` / `0xff`. Ожидаемый inner archive:
`U16LE(3) || U16LE(old_sequence) || Login_body`. Pending ID 4 — отдельный ID.
Хранимый sequence увеличивается modulo 65536; сериализуется прежнее значение.

Frame начинается с младших трёх little-endian байтов `inner_size + 7`, затем
checksum provider result и весь inner archive. Checksum fixture — `0x6a09e667`.
Transform — identity observer: будущий стенд проверяет alias, key и диапазон
`frame+3 … end`, не подтверждая настоящий cipher. Transport fixture должен
скопировать настоящий native frame до cleanup и вернуть AL 0 / 1 при непрозрачных
старших битах RAX. Ожидаемые байты нельзя записывать в native archive.

Prepared body занимает 91–807 байт; inner — 95–811, frame — 102–818. Исходный
raw writer впервые запрашивает capacity 1024. Ограниченный fixture может выделить
память по этому запросу; предварительно создавать archive payload нельзя.
Два stack archives соседствуют по 64 байта: искусственные canaries между ними
исказят соседний объект или сохранённые регистры.

## Что ещё не подтверждено

Остаётся реализовать и исполнить единый native стенд этой цепочки, затем
подключить новый semantic adapter, cache и publication к штатному обновлению.
Нельзя заменить исходный путь ручным вызовом backend или writer из координатора.

Publisher обнуляет `service+0x10`; дальнейшая привязка backend — отдельный ambient
fixture. Shared allocation / sized free требуют одного ledger с владельцем и
проверкой callsite; cleanup должен завершиться до prepare destructor. Необходимо
различать returning leaves и tail fragments, запрещать fixture overlap с любыми
native instructions и сохранять подготовленный packet / строки до очистки.

Pending insert / delegate, SDK / OS, checksum / cipher / transport effects,
настоящий lifecycle backend, asynchronous ownership, OOM / reallocation / aligned
buffers и целый онлайн-вход остаются открытыми. Этот пакет не меняет работающую
сессию, профиль или prepared bundle.

## Проверки подготовки

Машинные указатели, SHA и измерения — в
[отчёте](LOGIN-BACKEND-WIRE-PREPARATION-11322.json). Source audit прошёл за
268,973508 секунды: два PE images, 35 image cache hits, ноль новых JVM и native
replays. Полная проверка ранее опубликованной lineage занимает время; это не
измерение будущего native прохода или тёплого update cache.

Зарегистрированный tooling check прошёл 836 тестов. Дополнительно прошли 14
проверок collector, включая прежние source models. Новые проверки матрицы,
байтов, целых экспортов и tail boundaries входят в штатный tooling / cache key.
Число опубликованных native drivers осталось 30; подготовка не увеличивает его.
