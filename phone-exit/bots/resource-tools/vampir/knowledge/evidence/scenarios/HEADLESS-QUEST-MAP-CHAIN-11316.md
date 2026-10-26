# Связная цепочка поиска, вставки и роста таблицы задач

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [отдельных growth/rehash проверок](HEADLESS-QUEST-MAP-GROWTH-11316.md).
Offline replay, без игрового сокета и памяти процесса.

Исполняются совместно native FindOrAdd primary/group `145b4ab90` / `145b4ad00`,
insert `145b4a420` / `145b48b50`, growth `1416166c0` / `141437520`, resize wrapper
`141436d10`, rehash `145b73290` / `145b72e70`, occupied iterator `14142e6f0`
и exact size-provider leaf `141491da0` с null provider.

Шесть fresh-map последовательностей: primary/group × ascending / descending /
permuted 70 уникальных keys. Итого 420 вставок и 840 existing-key lookups:
повтор сразу после вставки и повторный проход по всей итоговой таблице.
Все hash values намеренно равны 1, поэтому lookup проходит collision chains.
Во время вставок реально вызываются несколько переходов ёмкости и bucket count;
это не вызов отдельных helpers с вручную готовым состоянием.

Проверены после каждой вставки:

- Новый slot равен текущему порядковому номеру; count / free metadata корректны.
- Все прежние key / value payload сохраняют bytes и slot при перемещении массива.
- Existing FindOrAdd не вызывает allocator / constructor / duplicate callbacks
  и не меняет bytes map / nodes.
- Финальный rehash обходит исходный insertion-slot order, не сортирует key.
- После него payload неизменен; occupancy соответствует 70 занятым slots;
  guards всех heap allocations и manager сохраняются.

Allocator realloc / bucket allocate/free, bit append, primary constructor,
duplicate check и hash остаются явными fixtures. Native FindOrAdd сам ищет
existing key до duplicate fixture. Fixture realloc моделирует prefix-copy;
настоящая allocator реализация не исполняется. Bitset заранее имеет 128 inline
bits, нет removals/free slots, allocation failures или non-null size provider.
Тестовые keys и payload не являются реальными заданиями.

`replay-quest-map-chain-11316.py`, контекст
`knowledge/native-contexts/quest-map-chain-11316.json`, тест
`test_vampir_quest_map_chain_11316.py`. Registered offline check
`native-quest-map-chain-11316` закрепляет 5 exports и зависимости.
Артефакт:
`code-clues/quest-map-chain-11316/b61d0f822b13524f4ed7d88bed44ac9a735f3d2cfb798658635923c023154846/manifest.json`.

`order_admitted=false`: доказано свойство fresh map chain в этих границах, но
ещё не исполнены CSV row creation / фильтрация / complete loading / overrides.
Следующий шаг — связать фактический порядок accepted CSV rows с этой цепочкой,
затем проверять индекс текущего персонажа. Runtime не включает новые contracts;
действующая сессия не перезапускалась.
