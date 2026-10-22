# Структура запроса QuestUpdate из официального эталона

22 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [timeline официального клиента](HEADLESS-QUEST-REFERENCE-TIMELINE.md).

## Проверенная wire-структура

ID 1810 / PktQuestUpdate: table `0x149967590`, constructor `0x145829dd0`,
ID getter `0x145835760`, writer `0x145838300`, mirror reader `0x14582cf30`.

| Wire offset | Тип | Native field |
| --- | --- | --- |
| 0 / 4 / 8 | Три float32 little-endian | packet+0x10 / +0x18 / +0x20, три double |
| 12 | uint64 little-endian | packet+0x28 |
| 20 | uint64 little-endian | packet+0x30 |
| 28 | uint8 | packet+0x38 |

Тело — 29 байт, без native padding. Writer helper `0x144aae5d0` преобразует
три double в float32; reader helper `0x144aae290` расширяет три float32
в double. Последний байт сохраняется без нормализации, включая 2 / 255:
называть его bool нельзя. Output +0xe8 → `0x141e4aef0` → +0x78 →
`0x144aadc60`, обычная запись байта. Float alias +0xa8 → `0x14149b760`
→ +0x38 → `0x144aadcf0`. Два qword используют +0xb8 / +0x48.

Constructor задаёт vptr и обнуляет два qword / байт, но **не инициализирует
вектор**. Нельзя считать весь запрос готовым после одного constructor.
Новый `quest_update.py` предоставляет encode / decode без сетевого подключения;
названия raw28 / raw30 / raw38 сохраняют неизвестную семантику.
Локальный codec дополнительно отклоняет нечисловые / bool-координаты,
нефинитные значения и переполнение float32. Это локальная политика для будущего
runtime, а не заявление, что native reader сам отвергает NaN / infinity.

## Native-проверка

Исполнены целые constructor / ID getter / writer / mirror reader, vector helpers
и scalar methods. Проверены 48 комбинаций: три вектора, включая signed zero,
минимальное положительное normal float32 и maximum float32; четыре qword-пары
с нулём, единицей, high bit и maximum; байты 0 / 1 / 2 / 255.
Все wire bytes и восстановленные native поля совпали с лёгким codec.

Шесть отказов raw output проверяют остановку на каждом шаге
4 / 4 / 4 / 8 / 8 / 1. Все 29 коротких префиксов отклонены без overread.
Raw append и memcpy входного archive — ограниченные fixtures; allocator,
producer, очередь транспорта и серверное принятие не исполнялись.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-quest-update-replay/fe1171fe5cdcf096a807691dde4e2459a78a78c1665220ba9c4cec64fb8c12cf/manifest.json`.
SHA256 manifest равен имени каталога. Native source проверяется полным SHA;
готовые Ghidra exports также сверяются перед исполнением.

## Сверка десяти запросов capture

Тела ID 1810 из flow 124 эталона `b70d6be4e33f6fd0086342f0f9d13d86`
прочитаны только в памяти через существующий CRC-checked outgoing inspector.
Все десять разобраны codec. Первый qword raw28 во всех равен нулю и не совпадает
с raw10 выбора персонажа ID 109. Второй qword raw30 во всех десяти совпадает
с ключом текущей таблицы Quest; различных значений два. В QuestTask совпадений
этих двух полей нет. Байты raw38 по порядку: 0 / 1 / 2 / 3 / 5 / 6 / 7 / 8 / 9 / 0.
Вектор не является нулевым во всех запросах.

CSV Quest / QuestTask взяты из уже проверенного
`release-quest-panel-audit/f6ce5181e1c30f7fcb0a3e0e98aa4ebb909b7fc4150b18d41d069dd9666a1ecf/manifest.json`
в библиотеке ресурсов; SHA двух CSV сверены перед чтением. Такое совпадение
даёт кандидатную связь raw30 с Quest, но не заменяет producer / setter proof.
Смысл raw28, raw38 и выбор конкретного вектора ещё не установлены.
Указанные значения не дают разрешения копировать сохранённое тело в новую сессию.

## Материалы и продолжение

Ghidra comparison
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

- `details/run-cf97103628c6/details.json`, SHA256 `e62f7fc833983810fdd17dde26763a70bcb122ac952417c811c8fed588d4be65` — writer / reader.
- `details/run-fd2ff86519da/details.json`, SHA256 `e6a0c96cddafc285a1df6a3ab36cb94d40f6c75b1e6e944b58e0d8a897c9afc3` — vector writer; leaf constructor оставлен в очереди Ghidra по отсутствию unwind, его точный вход отдельно проверен native replay.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-quest-update.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_update.py
```

Следом — источник текущего Quest / прогресса и producer ID 1810: какой vector,
raw28 и raw38 выбираются по серверному состоянию. Ответ ID 1811 ещё не разобран.
Codec к отправке не подключён; новых входов, движения или игровых действий нет.
