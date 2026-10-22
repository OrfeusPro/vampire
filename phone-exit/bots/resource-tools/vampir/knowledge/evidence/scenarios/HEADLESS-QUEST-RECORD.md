# Запись квеста и структура списка

22 октября 2026. Продолжение [привязки выбора панели](HEADLESS-QUEST-PANEL-RESULT.md)
после [сохранённого состояния обучения](HEADLESS-LIVE-TUTORIAL-PERSISTENCE.md).
EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

## Вложенная запись: проверенный формат

Таблица `0x14994aaa8` / PktQuest связывает slot +0x20 с целым reader
`0x1457a77c0`. Его вложенный объект по +0x18 имеет таблицу `0x14994aa60` /
PktQuestProgress, slot +0x20 → `0x1457a7a20`. В wire нет указателей таблиц
и padding native-объектов. Размер полной записи — 39 байт:

| Wire offset | Формат | Поле native-объекта |
| --- | --- | --- |
| 0 | uint64 | Quest +0x08 |
| 8 | uint8, clamp до 6 | Quest +0x10 |
| 9 | uint8 без clamp | Progress +0x08, внутри Quest +0x20 |
| 10 | uint64 | Progress +0x10, внутри Quest +0x28 |
| 18 | uint64 | Progress +0x18, внутри Quest +0x30 |
| 26 | bool, любой ненулевой байт → true | Quest +0x38 |
| 27 | uint32 | Quest +0x3c |
| 31 | uint32 | Quest +0x40 |
| 35 | uint32 | Quest +0x44 |

Все числа little-endian. Input table `0x1496726a8` связывает +0x50 с
uint64 reader `0x144aad7f0`, +0x60 с uint32 `0x144aad5f0`, +0x78 / +0x80
с byte `0x144aad590`, +0x88 с bool `0x144aad840`. Поэтому байт Progress
нельзя автоматически считать bool: он сохраняет 127 и 255 без нормализации.

`replay-release-quest-record.py` исполняет целые Quest / Progress readers,
реальный nested thunk `0x144aae4e0` и scalar input. Начальная форма объектов
задана явно, как у callback коллекции: нулевые поля и два проверенных vptr.
Конструктор, добавление элемента и allocator этим replay не исполняются.
Единственный внешний fixture scalar-чтения — ограниченный memcpy.

Проверены 216 полных тел: крайние uint64 / uint32, независимые байты состояния
и прогресса, clamp 6 и bool 0 / 1 / 255. Поля совпали с лёгким
`vampir_core.quest_record.decode_quest_record`. Все 39 коротких префиксов
отклонены; input cursor не вышел за переданный размер. Runtime требует точный
размер и текущий source SHA, не отправляет запросов и пока не подключён
к обработчику списка. Имена raw-полей сохранены: ключ экземпляра, ID из таблицы,
статус завершения и назначение чисел ещё не доказаны.

## Whole reader списка: статическая структура

Готовый reader ID 1802 `0x14582cac0` читает code uint32 по packet+0x10,
затем байт с clamp 12 по +0x14. Далее очищает и читает две коллекции:

- packet+0x18: descriptor `0x14994bc30`, callback `0x1457a9cc0`.
  Callback читает временный PktQuest и добавляет объект stride 72 байта
  только после успеха вложенного чтения. Временные vptr соответствуют
  проверенным Quest / Progress tables.
- packet+0x28: descriptor `0x149922240`, callback `0x1456b8e10`.
  Вложенный объект PktAssetChange имеет таблицу `0x149921178`, reader
  `0x145787dd0`: байт с clamp 97 и два uint64; native stride 32 байта.

Затем whole reader списка читает два bool по +0x38 / +0x39 и вложенный объект
по +0x40. Таблица этого объекта `0x14994ab30` / PktQuestData, reader
`0x1457a7980`: коллекция по +8 с descriptor `0x14994bc18`, затем uint64 по +0x18.
Конструктор-кандидат `0x1457a3d40` статически устанавливает эту таблицу
и обнуляет три qword по +8 / +0x10 / +0x18. Этот же объект конструируется
по packet+0x20 в ответе выбора панели ID 1837.

Для конструктора нет однозначного unwind root, поэтому `collect` сохранил
объяснение в очереди; автоматического экспорта по угаданной границе не было.
Коллекции списка, PktAssetChange, PktQuestData и отказные пути whole ID 1802
ещё не проверены native replay. Полный decoder ID 1802 не заявляется.

## Материалы и воспроизведение

Внешняя библиотека: `F:/PhoneExit Resources/Vampir/`.

- Native record replay: `code-clues/release-quest-record-replay/a6f82bda75e58923d85152c756852a25f043505d1e89514e33a20ea5fbd96c5b/manifest.json`.
  SHA256 совпадает с именем каталога; сохранены тела fixtures, instructions,
  scalar bindings и границы.
- Готовый ID 1802: comparison `c7552efd2125-98802d550890/run-fd4956a37b3c/`,
  `details/run-df3c5d97b2b8/details.json`, SHA256
  `658e92284a85cbcd397427d8008910a209b148eb6c03151b6da3aa973b053f9b`.
- Callback Quest: `details/run-f47f7eb31681/details.json`, SHA256
  `8f4a6d97417cb1c50a5e857cc6a3c75a1179fadf114ef64e9e5942b05e847bba`.
- Четыре whole readers: `details/run-6c286a6860d8/details.json`, SHA256
  `a9698c44e788c5e38cb3d31b0a7d02604ffd197c5f0959e91c30d552f5a7d622`.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_record.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-quest-record.py
```

Следом — элемент descriptor `0x14994bc18`, ограниченное чтение массивов и
whole ID 1802; затем источник запроса списка и handler. Не выполнять новый
игровой вход только ради счётчиков известных ID 1827 / 1840 / 1854.
Нужна новая обработка их содержимого или доказанный запрос текущего списка.
