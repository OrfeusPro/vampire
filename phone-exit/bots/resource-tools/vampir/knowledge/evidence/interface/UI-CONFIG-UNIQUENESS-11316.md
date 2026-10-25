# Поиск и замена привязки настройки

25 октября 2026. Продолжение [общего reader](UI-CONFIG-READER-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline Unicorn, synthetic память; игра / профили / конфигурации не изменяются.

## Источники

Задание `954516ced63021f9ef8b113661d5d6909c6f8fe938ddf23e9105dcbccecaf125`
выгрузило 1445d8430, точный callee insertion. Затем задание
`374ae6682e1327f5efee021f9521c26a015e05f6f41061ff2d15cf9c89659541`
добавило только его lookup callee 1445c29f0. Collect завершились с collected,
пустыми очередями. Ghidra details относительно
`ghidra/request-exports/<полный SHA EXE>/`:

- `run-8dcb78ce41f7/details.json`, SHA256
  `2336c2258eb5b279a0fb38f1fbdf3d628217675c52af0e8e1d89d92fd1fede7a`.
- `run-34b2db3bcded/details.json`, SHA256
  `9f63dfcc96b6f010d731210c773c4baa7594ec440a5276e1d1a81bfe6b29fa6d`.

Запрос `e7be9ebd1a51b46fb7075dac59653133270452c265ebfc195668fb24fa44ddf0`
явно указал compare 14145f1e0. Это leaf без unwind: 71 точный байт до
14145f227, затем INT3. Collector для него не запускался. SHA256 тела
`591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0`.
Таблица 128 ASCII bytes по 1489f4400 имеет SHA256
`fc5b9b2c32b0ecc0354c66f03e60790599a8fbae3511b2b60b2c0f7f27b6ceae`:
uppercase A…Z переводятся в lowercase, остальные ASCII bytes неизменны.
Native compare исполняется вместе с lookup, не заменяется Python casefold.

Задание `46f1d76ed5bc2ae148af9d3454ab6af55f05398954206d72d981333444648a3e`
содержит uniqueness / lookup и ранее проверенный destructor 141421b80;
использует готовые exports. Псевдокод сверён с инструкциями. Общая таблица
capture cleanup и exact leaves переиспользованы из предыдущего replay.

## Подтверждённое поведение

Lookup выбирает bucket через переданный hash и размер таблицы, проходит
связи +0xa0 с шагом 0xb0. При равных count >1 сравнивает UTF16 до terminator.
Равные count 0 / 1 совпадают без чтения строки; разные count 0 и 1 также
считаются пустыми. Остальные разные длины не вызывают compare.

Если текущие UTF16 units различаются и оба ASCII, compare применяет таблицу.
При различающихся non-ASCII units возвращает их разность. Проверены ASCII
разного регистра, точная кириллица, кириллица разного регистра, surrogate pair
и различие младшего surrogate. Это не универсальный Unicode case folding.
Synthetic embedded NUL проверяет остановку compare; он не объявлен допустимым
реальным ключом настройки и не нормализуется сканером.

При совпадении uniqueness очищает два старых capture objects (если active),
освобождает ненулевой data старого ключа и переносит первые 0xa0 bytes новой
записи в старую. Старые hash links +0xa0 / +0xa4 остаются прежними. Временный
новый слот добавляется в free-list, его occupied bit сбрасывается; out index
заменяется индексом старой записи. Optional out bool и AL получают true.
При miss возвращается false, запись и index сохраняются. При одном active
элементе helper обходит lookup и возвращает false.

## Проверки и границы

`replay-ui-config-uniqueness.py` прошёл 512 сценариев: 16 пар ключей, четыре
сочетания old active captures, inline / external storage, пустой / непустой
free-list, наличие / отсутствие optional out bool. Получены 288 replacements,
224 misses, 224 old-key free calls и 288 native cleanup calls. Сверены весь
контейнер / записи / guards, bitmap, free-list links, сохранность hash links,
возвращаемый index / AL / bool и length gate перед compare.

Ещё шесть lookup сценариев проверили цепочку 2 → 1 → 0: совпадение в начале,
в конце и miss, с inline / external buckets. Два empty lookup случая обходят
нулевой query pointer; два single-active случая обходят lookup. Всего 522
полных native вызова. Сам compare, lookup и capture cleanup не подменяются.

Единственные fixtures — old-key free 141483080 и memmove 1487f5abf с точным
размером 0xa0. Память реально не освобождается. Native hash алгоритм не
исполняется: входы намеренно находятся в одном bucket. Growth, реальный
allocation origin / ownership внешнего storage, весь reader с replacement,
последующий dispatch / lifetime и config precedence остаются открытыми.

Unicorn 2.1.4 / Capstone 5.0.6, полные source SHA / unwind roots / leaf bytes /
padding / обе таблицы проверяются перед исполнением; выход за выбранный код
и явные fixtures отклоняется. Отчёт вне Git:
`code-clues/ui-config-uniqueness-d00a-02.json`, SHA256
`0b3e7436712b850dfcab5cfbb64ef0f72bb44400feb7c438e6dfea397775c74a`.
01 сохранён отдельно. Все девять tests tile refresh прошли. Результат не
подтверждает active settings / Brush и не открывает генерацию внешнего вида.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-uniqueness.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/46f1d76ed5bc2ae148af9d3454ab6af55f05398954206d72d981333444648a3e/manifest.json' --compare-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/e7be9ebd1a51b46fb7075dac59653133270452c265ebfc195668fb24fa44ddf0/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-uniqueness-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — убрать uniqueness=false fixture из общего reader, проверить повторный
ключ / новый destination / reuse освобождённого слота на одной памяти.
Отдельно найти потребителей сохранённых invoke pointers и условия их вызова.
