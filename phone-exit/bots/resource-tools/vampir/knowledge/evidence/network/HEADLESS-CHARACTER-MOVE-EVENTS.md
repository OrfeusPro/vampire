# Входящие события движения текущей сборки

22 октября 2026. Источник — сохранённый EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Это проверка формата и кода клиента без подключения к игре.

## Привязки и тела

| Имя | ID | Таблица | Reader / writer | Проверенный формат |
| --- | --- | --- | --- | --- |
| PktCharacterMove | 305 | `0x1499227c8` | writer `0x1456d4b80` | Вызывает `0x144aae5d0`, затем slots +0xa8 / +0xb8; полный формат исходящего действия ещё не разобран |
| PktCharacterMoveResult | 306 | `0x1499229e0` | reader `0x1456c5190` | Одно поле uint32 little-endian; смысл результата не установлен |
| PktCharacterMoveNotify | 307 | `0x149922870` | reader `0x1456c5b60` | uint64 key, float32 X, float32 Y; всего 16 байт |

Имена найдены по точным literals. Getters возвращают 305 / 306 / 307.
Конструкторы ID 306 / 307 (`0x1456c0060` / `0x1456c0040`) записывают
соответствующие таблицы; это дополнительно проверено исполнением native-кода.
Reader ID 307 вызывает `0x144aae220`: две float32 читаются через slot +0x40
и расширяются в double для объекта пакета. Ключ читается через slot +0x50.
Reader ID 306 использует slot +0x58. В ID 307 нет высоты или ID мира.

`PktCharacterPosition` нельзя считать отдельным сетевым пакетом по одному имени:
у кандидата slot +0x28 ведёт на `0x141403b90`, bytes `32c0c3cccccc`,
а не на проверенный getter ID. Инструмент отклоняет эту привязку; роль типа открыта.

## Регистрация и применение

В уже сохранённых инструкциях `0x1467b62f0` повторно использованы конкретные
блоки регистрации, без нового экспорта всей большой функции:

- ID 306: вызов конструктора `0x1467b7819`, регистрация `0x1467b782c`,
  таблица обработчика `0x149dc6bf8`, slot +0x10 → `0x141403c50`.
  Последняя функция содержит `RET 0` (`c20000`); отдельная семантика результата
  из этого пустого обработчика не следует.
- ID 307: вызов конструктора `0x1467b7864`, регистрация `0x1467b7877`,
  таблица `0x149dc7eb8`, slot +0x10 → `0x146797d00` → `0x14679eab0`.

Receiver `0x14679eab0` ищет объект через `0x145514ef0` по packet+0x10.
При отсутствии объекта действие пропускается. Есть дополнительные проверки
состояния объекта. Z берётся из существующего transform объекта, XY — из пакета;
далее вызывается `0x1456a6770`, сохраняется целевой вектор и выбирается ветвь
применения через transform wrapper либо virtual slot +0xa48. Часть этого пути
пересекается с уже разобранным применением позиции после ID 206.

Это статический разбор receiver, а не исполнение его ветвей. ID 307 нельзя
выдавать за окончательную текущую позицию персонажа: обработка зависит от объекта,
его состояния и движка. Связь ключа с собственным персонажем, нормализация
`0x1456a6770`, высота и различие цели / фактической позиции требуют продолжения.

## Проверки и runtime

`replay-release-character-move.py` исполняет целые текущие конструкторы, getters,
readers и вложенное чтение XY в Unicorn. Проверены 28 тел и 20 коротких префиксов:
ключи 0 / 1 / 2^63 / 2^64−1, signed zero, обычные значения, infinity и NaN.
Граница фикстуры — ограниченный memcpy архива; тела синтетические.

Лёгкий `character_move_event.py` сохраняет исходные биты XY; `finite_xy()`
отклоняет неконечные координаты перед использованием. Оба decoder требуют
точный размер тела и SHA текущей версии. Три offline-теста проверяют границы,
происхождение, биты и соответствие native readers. Проверка
`release-character-move` зарегистрирована для вопроса `world-position-events`.
Обработчик событий ещё не подключён к игровой сессии; исходящий ID 305 не отправлялся.

Из корня репозитория:

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_move_event.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-ping-result.py --packet PktCharacterMoveNotify
```

## Сохранённые материалы

Корень ниже — `F:/PhoneExit Resources/Vampir/`.

- Native replay: `code-clues/release-character-move-replay/220dde1da513c32b256de0588152a0565bb85bb2d5129c6dfc85df02e5a8f189/manifest.json`.
- Discovery ID 305: `code-clues/release-world-packet-discovery/cf0f79634bd1715f53ce3969068e1af6ea0bea9700b0c071305eb1cd780df056/manifest.json`.
- Discovery ID 306: `code-clues/release-world-packet-discovery/d04421eec542c88ee37c434a1aa1044893cdb4b47e62d87768712922b1411f43/manifest.json`.
- Discovery ID 307: `code-clues/release-world-packet-discovery/fb3dfa93d5ce90200cff6d3f1fc8eac608cbb7d4bbd0f906195a6af92575d285/manifest.json`.

Экспорты находятся в
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-3cc1c3aeb25b/details.json` | `42cad9c107821d91e1783be10a6b1b19ccddd9ae2ba5da38bf343d523d62eeda` |
| `details/run-e94b2afaa516/details.json` | `ced9ba6f512331429cf3cf0e6644d4d3d27ce2708cd2b87e52d40f917a2658c4` |
| `details/run-e00b0374dd24/details.json` | `7bf145d7b9c1797420fd50efca70bc14a758f8e07f5ca1eb1582606f30e59368` |
| `details/run-248f49f30ed3/details.json` | `d55a590b5ceb9abfdf3b9b9295b5db9599f98e79d108ba18b629d37b2ee4bb1f` |

Инструкции регистрации сохранены в `details/run-36c407109687/details.json`.
Псевдокод всей factory завершился timeout; перечисленные блоки инструкций есть
в экспорте. Имена прежних ролей не переносились в новую версию автоматически.

Следующая проверка — ветви receiver и `0x1456a6770`, затем identity guard
собственного персонажа и применение входящих событий к модели сессии.
