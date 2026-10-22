# Тело запроса обучения ID 9903

22 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [пути действия обучения](HEADLESS-TUTORIAL-ACTION-ROUTE.md).

## Проверенный формат

Целые constructor пакета `0x14584d050`, getter ID `0x145857180`, writer
`0x145858ef0`, constructor output archive `0x144aada00`, его base constructor
`0x144aae500`, aliases и скалярные writers исполнены в ограниченном native replay.
Настоящий raw output IO `0x144aadd50` заменён явным fixture: он сохраняет переданные
байты либо возвращает отказ на выбранном вызове. Выделение памяти, расширение
буфера и счётчики raw archive не исполнялись.

Тело содержит ровно 9 байтов, без ID / транспортного заголовка:

| Поле объекта | Формат | Установленный источник |
| --- | --- | --- |
| +0x10 | uint32 little-endian | Ключ из producer |
| +0x14 | uint32 little-endian | Селектор строки из producer |
| +0x18 | Исходный байт | Constructor задаёт 0; смысл флага не установлен |

Output archive constructor устанавливает vptr `0x149672748`.
Slot +0xc8 ведёт через `0x144aadae0` в +0x58, slot +0xc0 — через
`0x1418d4de0` в +0x50. Оба последних slot указывают на `0x144aadcc0`,
пишущий 4 байта. Slot +0xf0 ведёт через `0x144aadaf0` в +0x80 /
`0x144aade40`, пишущий байт. Это проверенная связь текущего SHA;
совпадение со старым layout не использовалось как доказательство.

64 вектора покрывают key 0 / 1001 / 0x80000000 / 0xffffffff,
selector 0 / 2 / 0x80000000 / 0xffffffff и raw18 0 / 1 / 2 / 255. Native bytes совпали с
переносимым кодеком. Ненулевые raw18 2 / 255 сохраняются writer без нормализации;
это не подтверждает их допустимость сервером.

Три отказа raw fixture останавливают writer на соответствующем поле с return 0;
сохраняются префиксы длиной 0 / 4 / 8 байтов. Следующие поля не вызываются.
Constructor отдельно проверен на обнуление девяти байтов полей и ID 9903.

`vampir_core/tutorial_request.py` содержит только source-bound encoder с явными
key, selector и raw18. Он отклоняет неправильный SHA, bool вместо int и значения
вне диапазона. В сетевой lifecycle, кнопку карты и автоматический сценарий
кодек не подключён. Условия реального действия, ответ и снятие ожидающего ключа
пока не проверены.

## Следующий ответ

Имя / getter связывают `PktTutorialUpdateResult` с ID 9904 и таблицей
`0x14996ba48`. Отчёт поиска содержит constructor candidates и инструкции;
reader, handler, результат сервера и корреляция с запросом пока не разобраны.
Следом проверить эти ветви, loader TutorialStep и callback панели.
Не считать успешную сериализацию подтверждением выполнения обучения.

## Воспроизведение и источники

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_tutorial_request.py
```

Два offline теста проверяют native parity / отказы и границы encoder.
Проверка зарегистрирована как `release-tutorial-request`, без авторизации и
игровых действий.

Материалы в `F:/PhoneExit Resources/Vampir/`:

| Файл относительно библиотеки | SHA256 |
| --- | --- |
| `ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-a9e1e1b3eeea/details.json` | `9cb0c83ad394995dbb4f7dd27e87628bf24457e266697dfeb64d13614af5274f` |
| `code-clues/release-tutorial-request-replay/b2232809bba78e4c668d26bb3a86e1d2ebc400b654eceacb1507a08b145907fe/manifest.json` | `b2232809bba78e4c668d26bb3a86e1d2ebc400b654eceacb1507a08b145907fe` |
| `code-clues/release-world-packet-discovery/2be7a2c4c60656498793857357a56c4a2eb46bb662bfdf79e56acab775bb61dd/manifest.json` | `2be7a2c4c60656498793857357a56c4a2eb46bb662bfdf79e56acab775bb61dd` |

Экспорт writer и его SHA приведены в предыдущем исследовании. В отчёте replay
также сохранены точные байты constructor / leaf и целых unwind functions.
