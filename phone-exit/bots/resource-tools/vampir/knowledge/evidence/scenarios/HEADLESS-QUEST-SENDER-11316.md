# Целая отправка QuestUpdate по текущей модели

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [именованных параметров](HEADLESS-QUEST-UPDATE-PRODUCER-11316.md).
Игровое соединение / процесс не использовались, пакеты не отправлялись.

replay-quest-sender-11316.py исполняет целиком sender 145d85360,
position wrapper 145517d40, constructor ID 1810 145828b00 и точные leaf
lookup 1455bbcb0 / state getter 1455e7510. Lookup выполняет настоящий hash /
обход коллизий по синтетическим buckets и records, не заменён Python-словарём.
Входы leaf закреплены по прямым calls; constructor 31 байт, lookup 140 байт
со всеми внутренними ветвями / RET, state getter 17 байт. Unwind им не выдуман.
Source, exports, инструкции и leaf bytes проверяет общий current harness.

## 640 сценариев

Матрица: четыре ключа 0 / 1 / high bit / max uint64, inline / external buckets,
empty / missing / null value / found, task pointer отсутствует либо byte
0 / 1 / 2 / 255, четыре пути позиции. Первый узел намеренно коллидирует,
второй может совпасть. Проверяются неподвижность всех model / actor данных и
guards; итоговый temporary packet проверяется до cleanup.

- empty / missing / null value завершают sender без send и без packet cleanup;
- found создаёт один packet и передаёт его send fixture, затем один cleanup;
- сохранённый ключ попадает в QuestInfoId (+0x30), TargetId остаётся 0 после
  настоящего constructor; state byte попадает в QuestTaskIndex (+0x38);
- null state pointer даёт FF. Это наблюдаемая native ветвь, не разрешение
  отправлять FF в будущей runtime-команде;
- вектор берётся через native position wrapper из fixture component+0x1f0,
  при null component — из globals 14b0c0298 / 2a0 / 2a8;
- при отсутствующем manager или actor wrapper копирует globals
  14b186100 / 108 / 110. Проверяются реальные bytes этих globals текущего EXE.

160 из 640 сценариев дошли до send fixture, все native поля совпали.
Это не wire bytes: serializer, очередь транспорта и server acknowledgement
в этой проверке не исполняются. Смысл engine object / исправленная координата
и связь с серверной целью headless персонажа автоматически не установлены.

## Fixtures и границы

Model singleton, engine manager, weak-reference resolver, network getter,
virtual send и packet destruction — явные ограниченные fixtures. Они возвращают
только подготовленные объекты и проверяют receiver / pointer / порядок вызовов.
Системный allocator, engine, реальный socket и сервер не запускаются.
Искусственный model record не доказывает соответствие полученного PktQuest.raw08
ключу текущей модели или origin byte +0x29. Нет доказанного HUD delegate,
маршрута, движения или выполнения квеста. Кнопка следования ещё не подключена.

Контекст knowledge/native-contexts/quest-sender-11316.json содержит SHA двух
полных exports (sender / position wrapper), функции, leaf bytes и fixture entries.
Native report, SHA равен имени каталога:
`code-clues/quest-sender-11316/7e08b3d1a83200afafb1ad3c314879035c98999f33c6d3a9aff55df14a69f93b/manifest.json`.
test_vampir_quest_sender_11316.py проверяет всю матрицу; зарегистрированная
проверка — native-quest-sender-11316.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-quest-sender-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_sender_11316.py
```

Далее: current входящий Quest → model key / task field → callback панели →
local route executor. После этого current serializer / action adapter и живой
результат. Не подменять запуск автоматики прямым повтором QuestUpdate.
