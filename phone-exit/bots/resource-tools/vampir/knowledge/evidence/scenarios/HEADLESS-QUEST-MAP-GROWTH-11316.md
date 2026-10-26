# Rehash и рост таблиц задач

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [sparse insertion](HEADLESS-QUEST-SPARSE-INSERT-11316.md).
Offline Unicorn replay; нет сети, чтения процесса, runtime admission и reconnect.

## Rehash: 120 сценариев

Целые primary/group `145b73290` / `145b72e70` исполняются вместе с настоящим
occupied-bit iterator `14142e6f0`. Hash и bucket allocate/free — явные fixtures.
Пять layouts: empty, один occupied, четыре подряд, holes 0/2/5, граница 0/31/32/34.
Для каждого primary/group stride 200/32, inline/external bitset, старые buckets
inline/external, новое bucket count 1/2/16. Это 120 комбинаций.

Проверены hash-call order по возрастающим occupied slot indices, deliberate
collisions, next/bucket fields, точные bytes всех остальных record payload,
неизменные pointers/count/free metadata/bitset и guards. Rehash не переставляет
nodes: переписывает chain links по +0xc0/+0xc4 либо +0x18/+0x1c и bucket heads.
Порядок iteration следует слотам, а не сортировке IDs. Это не доказывает порядок
создания слотов целым CSV loader или отсутствие последующих overrides.

## Growth: 16 сценариев

Целые `1416166c0` / `141437520`, resize wrapper `141436d10` и exact 29-byte
size-provider leaf `141491da0` исполняются совместно. Для двух strides проверены
count 0/1/4/33 и old capacity 0/64. Это искусственные входы helper, не утверждение,
что каждый набор является состоянием настоящего loader перед вызовом роста.

При old capacity 0 размер — max(4,count); иначе count + floor(3*count/8) + 16.
Size-provider global null; leaf возвращает запрошенные bytes. Non-null allocator
rounding provider не проверен. Native wrapper проверяет аргументы, вызывает
realloc boundary и сохраняет новый pointer; count и остальные поля неизменны.
Настоящий realloc / освобождение памяти / allocation failure не исполняются.
Fixture выделяет guarded scratch и копирует старый prefix без перестановки;
эта копия — модель контракта allocator, не native доказательство его реализации.

## Материалы и допуск

Тест `test_vampir_quest_map_growth_11316.py` прошёл. Контекст
`knowledge/native-contexts/quest-map-growth-11316.json` закрепляет exports:
`run-ba88307b3fbf` (4 roots), `run-774fa227622a` (iterator),
`run-4f4fd948c8b9` (resize). Leaf без unwind root допускается точными байтами.
Offline check `native-quest-map-growth-11316` зарегистрирован с полными зависимостями.
Артефакт:
`code-clues/quest-map-growth-11316/8d49a21274160167380dfe7a1d5af53631cec2f5feb3cb18c4aa0c0397211093/manifest.json`.

В отчёте `order_admitted=false`. Проверены стабильность nodes при rehash и
делегирование growth, но ещё нужны CSV row creation / fresh load / filters /
overrides и связка whole insertion→growth→rehash. Порядок текущего серверного
индекса и игровые действия пока не допускаются. Онлайн-сессия сохранена.
