# Native присваивание строки в consumer настройки

25 октября 2026. Продолжение [потребителей привязок](UI-CONFIG-CONSUMERS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline Unicorn, synthetic память; игра / реальные профили / настройки и
существующий UI snapshot не изменяются. Генерация остаётся закрытой.

## Источники

Задание `951685ee8c2bdda2fad112c8d279b88c192ec683ab5723d5d1504fb0fdc25949`
явно указало assignment root 1414277b0. Готовый Ghidra export переиспользован:
`ghidra/request-exports/<полный SHA EXE>/run-d8dc7f6c51b7/details.json`, SHA256
`3d657d6fb0d305a0e8bddaffdad7e79042c4b259e9a1e647f062e00c2261d12f`.
Псевдокод согласован с полными инструкциями: root 1414277b0…141427850.

Задание `9b48794e9375e2222e74c70057f20889499270fab4717d311d4199248a62940e`
содержит два consumers, clone wrapper / body, hash / lookup и assignment.
Все roots уже ready; collect переиспользует материалы, без новых exports.
Assignment — точная цель проверенного leaf 1445c7970, не функция по сходству имени.

## Локальное native поведение

Если destination.data == source pointer, функция возвращает destination до
сканирования строки, изменения count и вызова services. Это включает null/null.
Иначе null source или первый NUL дают count 0. Для непустого source функция
сканирует UTF16 до первого terminator и включает его в count.

Затем count destination сбрасывается в 0; при capacity != count вызывается
141438050. После него native код записывает новую длину и проверяет достаточность
capacity; fallback 141437970 существует, но в этих сценариях не вызывается.
Для count >0 в 1487f5ab9 передаются destination.data, source и count ×2 bytes.
Возвращается destination, nonvolatile RBX / RSI / RDI сохраняются.

`replay-ui-string-assignment.py` прошёл 80 вариантов: восемь source payloads,
пять начальных pointer / capacity комбинаций, два resize capacity результата.
Есть null, пустая строка, RED, кириллица, surrogate pair, slash, длинная строка
и synthetic embedded NUL. Для A-NUL-B копируется только A с terminator;
это отличается от ранее проверенного counted clone, копирующего весь count.
Дополнительно четыре identity сценария сохраняют объект с разными count /
capacity и buffer без terminator: native ранний выход не сканирует source.

Сверены полные fields / guards, source bytes, все 512 bytes старого / нового
buffer, точные resize / copy arguments, порядок ветвлений, полный RIP / RSP
возврат и nonvolatile registers. Resize и byte-copy — явные fixtures.
Resize всегда обеспечивает достаточную capacity; настоящий allocator,
fallback growth, allocation failure, overflow и arbitrary aliasing не проверены.
Некоторые pointer / capacity комбинации — synthetic boundary probes,
не доказательство допустимого игрового состояния.

## Присваивание внутри read / write consumer

В `replay-ui-config-consumers.py --native-assignment` fixture целого
1414277b0 удалён. Настоящие write consumer → capture getter → leaf → assignment
исполняются на одной памяти с последующим native read / clone.
Вместо whole-assignment fixture используются resize-value и общий byte-copy
service; аргументы, сброс count перед resize и итоговая capacity проверяются.
Fixture resize возвращает capacity с запасом 7 units, native код сохраняет её.

96 последовательностей read → write → read / 288 полных consumer вызовов
прошли повторно. В 64 hit случаях выполнено native assignment; 32 misses
обошли его. По-прежнему проверены 128 read invokes, собственный clone buffer,
неизменность других destinations и контейнера, inline / external captures,
обнуление read output при miss и guard bytes. Legacy режим с assignment
fixture сохранён отдельно для регрессии, его результаты не смешиваются с новым.

Остаются пять primitive services: query FString construction, query free,
clone allocation, byte-copy и value resize. Binding records подготовлены
синтетически по проверенной структуре, не созданы общим registration reader.
Поэтому registration → dispatch интеграция, allocator ownership / lifetime,
caller / событие, persistence, precedence и active settings / Brush не доказаны.

## Повтор проверки

Unicorn 2.1.4 / Capstone 5.0.6, полный SHA / unwind ranges / direct callees,
ранее проверенные leaf bytes / таблицы проверяются до исполнения. Выход за
разрешённые native bodies и primitive services отклоняется.
Все пятнадцать tests tile refresh прошли; проверки добавлены в source-bound
план обновления клиента, без автоматического переноса адресов на новый SHA.

Отчёты вне Git:

- `code-clues/ui-string-assignment-d00a-01.json`, SHA256
  `13697336d77b087d119a437f1974f5bc93ddc667110650ecd32fbe215332d636`.
- `code-clues/ui-config-consumers-assignment-d00a-01.json`, SHA256
  `7f02af27806da27b0847ec436ad3b83f8af54cc634d89e8bcb219543154987cb`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-string-assignment.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/951685ee8c2bdda2fad112c8d279b88c192ec683ab5723d5d1504fb0fdc25949/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-string-assignment-d00a-next.json'
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-consumers.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/9b48794e9375e2222e74c70057f20889499270fab4717d311d4199248a62940e/manifest.json' --native-assignment --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-consumers-assignment-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — общий registration → read/write с native assignment и проверка callers.
Локальная запись по сохранённому destination не означает сохранение настроек
на диск, применение к UI или подтверждение события реальной сессии.
