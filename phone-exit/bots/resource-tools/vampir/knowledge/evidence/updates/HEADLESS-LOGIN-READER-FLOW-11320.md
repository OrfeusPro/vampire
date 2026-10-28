# Автоматический поиск LoginResult и проверка reader 1.13.20

28 октября 2026. Продолжение
[автоматического пакета](HEADLESS-AUTOMATIC-FOLLOWUP-11320.md).
Полный SHA EXE:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.

## Результат

`discover-login-result-11320.py` использует текущую таблицу `0x149929040`,
её reader `0x1456dc140` и ограниченные окна ±65536 вокруг прежних функций.
Raw совпадения используются только для отбора; ссылки проверяются по границам
декодированных инструкций. Новый EXE сверяется полным SHA.

- Два root со ссылкой на таблицу разделены по virtual slot: deleting destructor
  `0x1456da120` исключён, constructor candidate — `0x1456d7660`.
- Из текущего reader извлечены **23 операции**, их destinations и вызовы.
  Прежний reader 1.13.18 имел другой порядок и структуру; старый context к новому
  reader не применялся. Имена и wire-смысл новых полей этим не установлены.
- Среди **211** функций, вызывающих текущий gate, дополнительная связь с
  source-bound post-state `0x146758950` оставила один handler candidate:
  `0x14679e2d0`. Обе ссылки проверены на границах инструкций. Полная семантика
  post-state и handler не объявлена подтверждённой.
- По ограниченному поиску registration owner через прямой constructor call
  кандидат не найден. Это ограничение поиска, а не доказательство отсутствия.

Один `collect` получил три недостающих полных Ghidra exports:
constructor / reader / handler. Проект переиспользован, очередь экспорта пуста.
Прежний неудачный post-state export не повторялся.

## Native проверка

`verify-login-reader-flow-11320.py` исполняет весь текущий reader с явными
opaque archive / string / nested dispatch fixtures. Прошли **96 сценариев**:
два начальных заполнения памяти × два ненулевых результата primitive ×
(успешный проход + отказ на каждой из 23 операций).

Проверены адрес получателя и destination каждой операции, порядок вызовов,
возврат AL, отсутствие следующих операций после отказа, nonvolatile registers,
неизменность archive и точное содержимое packet с canaries. Успешный fixture
пишет один sentinel byte; это не decoder строк, времени или period.
Конструктор и handler в этих native сценариях не исполняются.

В граф внесена привязка `game-login/result-reader` нового полного SHA.
Область доказательства — whole reader flow, а не полный LoginResult contract.
Штатная проверка `native-login-reader-flow-11320` подключена к `on_update` и кэшу;
прежние полные result checks остаются незакрытыми. Три регрессионных теста
проверяют сценарии, единственную двойную связь и отказ при изменённом destination
или подмене handler. Следующий запуск переиспользует неизменённые результаты.

## Источники и воспроизведение

Относительные пути ниже — внутри `F:/PhoneExit Resources/Vampir`:

- Discovery: `knowledge/login-result-discovery-11320/f01b10ff45c898453488604baa03e6dbbd9afb1e513031d9a7a92eb684d5daf8/manifest.json`.
- Native flow: `knowledge/login-reader-flow-11320/fad61554027892d21604557005ef2b5d286e43e8c22eb2c94abf9007030ecfb1/manifest.json`.
- Collection: `knowledge/collections/aceeb13b02f6044d1f2997fef1229fe94289709ce47a10c200f6d09ca4adea36/manifest.json`.
- Экспорты: `ghidra/request-exports/544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c/run-cc90e4f503ac/details.json`.

Review spec с SHA discovery / exports:
`knowledge/native-contexts/login-reader-flow-11320.json`.
Handler refinement дополнительно сверяет producer и все inputs уже готового
Login alignment; эти зависимости входят в ключ штатного кэша.
Кэш научен учитывать client-code snapshots с проверкой полного SHA и два явно
разрешённых вида публичных content-addressed link reports. Изменённый snapshot,
изменённый manifest и private captures отклоняются. Прошли 16 workflow тестов,
включая два новых теста целостности / границ допуска. Изменение runner меняет
ключи кэша: штатные проверки выполняются автоматически по новому рецепту.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/discover-login-result-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_reader_flow_11320.py
```

## Остаток

Строгий список **346 основных функций и 30 helpers** этим ограниченным пакетом
не сокращён. Следующие доказательства: actual nested layout / primitive decoder,
constructor effects, handler paths, registration, post-state boundary и
continuation anchor. Теперь handler имеет один source-bound кандидат и полный
экспорт, поэтому следующий автоматический пакет не повторяет его широкий поиск.
Runtime, сеть, вход и игровые действия не запускались.
