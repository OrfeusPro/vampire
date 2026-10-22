# Полное чтение ответа списка квестов

22 октября 2026. Продолжение [отдельной записи квеста](HEADLESS-QUEST-RECORD.md).
EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Добавлен `vampir_core.quest_list.decode_quest_list_result` для полного тела
ID 1802. Сетевой запрос, handler и игровое действие этим не реализованы.

## Порядок wire-полей

Все числа little-endian, каждый count — uint16. Минимальное тело — 21 байт.

1. Code uint32, затем байт raw14 с clamp 12.
2. Count и массив PktQuest, каждая запись 39 байт.
3. Count и массив PktAssetChange: байт с clamp 97, затем два uint64.
4. Два bool raw38 / raw39, любой ненулевой байт преобразуется в true.
5. PktQuestData: count групп; для каждой — байт с clamp 12, count и массив
   записей PktQuest. В конце всего PktQuestData — uint64 raw18.

Ранее неизвестный descriptor `0x14994bc18` содержит resize `0x1457aad70`
и callback `0x1457a9dd0`. Callback создаёт временный PktQuestTypeData,
читает его, затем копирует во внешний массив с native stride 32 байта.
Таблица PktQuestTypeData `0x14994aae8`, reader `0x1457a7a80` читает тип
и массив через уже известный Quest descriptor `0x14994bc30`.

Reader полного ответа `0x14582cac0` вызывает PktQuestData reader
`0x1457a7980`. Поэтому вложенный массив нельзя трактовать как простой список
номеров квестов или пропускать после двух флагов. Типы групп и смысл остальных
raw-полей ещё не связаны с handler / игровыми таблицами; decoder их не угадывает.

## Native-проверка

`replay-release-quest-list.py` исполняет целый ID 1802, nested thunk,
PktQuestData / PktQuestTypeData / Quest / Progress / AssetChange readers,
цикл input-массивов, callbacks и resize wrappers. Псевдокод сверяется
с инструкциями и full SHA исходного EXE.

Начальный объект свежий, нулевой, с заданным vptr PktQuestData.
Выделение памяти, копирование записей без указателей, cleanup и free —
ограниченные fixtures. Конструктор ответа и повторное использование непустых
массивов не исполняются. Native allocator / growth / destructor не заявляются
проверенными. Fixture хранит не больше восьми элементов одной коллекции;
набор успешных сценариев покрывает count 0 / 1 / 2.

Проверены 243 полных тела: независимое заполнение верхних квестов, assets,
групп и вложенных квестов; крайние числа, enum clamps, bool 0 / 1 / 255.
С portable decoder совпали все scalar-поля, количество и содержимое каждой
коллекции, включая uint64 после последней вложенной записи. Все 295 коротких
префиксов составного тела отклонены; native input cursor не вышел за длину.

Portable decoder отдельно отклоняет лишние байты, неверный source SHA / тип
body и неявные / неверные лимиты. Он требует `max_collection_items`,
`max_total_items`, `max_payload_size`. Общий бюджет включает группы, assets
и все квесты каждого уровня; превышение отклоняется до чтения элементов
соответствующего массива. Частично разобранный результат наружу не возвращается.

## Материалы и следующий шаг

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-quest-list-replay/22d12958fe8b8bdb3468675ea2231423edd0f73ccc538069b73cb93daf387ab0/manifest.json`.
Полный SHA256 равен имени каталога. Сохранены инструкции, scalar / descriptor
bindings через код инструмента, результаты и границы fixtures.

Новый Ghidra export пяти явных функций:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-b25ee312ccc9/details.json`,
SHA256 `b79eaf9158bd493eb3878b730468b108e59c4baf8fa5c6e0db1b2716fd24a063`.
Остальные три готовых экспорта использованы повторно и проверяются инструментом
по полным SHA. Автоматического обхода EXE / дерева вызовов не было.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_quest*.py'
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-quest-list.py
```

Следующий этап — запрос списка и его producer / handler, затем ограниченное
чтение текущих квестов в живой сессии. ID 1802 сам не приходил в сохранённых
последних сессиях; повтор входа без нового запроса / обработки это не изменит.
ID 1836 и автоматическое прохождение по карте не подключены.
