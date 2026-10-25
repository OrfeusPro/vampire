# Native-хеш ключа и общий reader с восемью buckets

25 октября 2026. Продолжение [общего replacement / reuse](UI-CONFIG-READER-REPLACEMENT-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверка offline; игра, реальные профили / настройки и UI snapshot не меняются.
Генерация остаётся закрытой до завершения аудита свойств.

## Источники и границы

Запрос `7c9e28c0bd8200b8a7426c0ab2d700b8502ffda122943b9d1847620b458ad2d8`
содержит точный hash callee 141425d60 из insertion. Collect завершился
с collected / пустой очередью. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-3318f40a35c0/details.json`, SHA256
`e2277c705fd0418674879b0914a2a60683044098879fcb6c93e68713a2262253`.

Ghidra C-листинг показывает void и только цикл уменьшения count; вычисление
хеша в нём не восстановлено. Этот листинг не используется как доказательство
алгоритма. Машинные инструкции, PE unwind chains и native выполнение проверены
отдельно; caller после call использует EAX. Три связанных unwind-фрагмента:
141425d60…141425d6d, 141425d6d…141425dc9 и 141425dc9…141425dce.
Целое тело с полным возвратом исполняется в replay.

Таблица по 14b0c2b10 — 256 little-endian uint32, доступна в самом EXE,
не нулевая BSS-подмена. SHA256 её 1024 байтов:
`0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e`.
Все элементы независимо сверены с восемью шагами полинома 0x04c11db7
для начального значения index <<24. Runtime записи в эту таблицу не исследованы.

## Алгоритм и отдельная проверка

ECX — знаковый count UTF16 units, RDX — данные. При count <=0 результат 0,
указатель не читается. При положительном count начальный hash равен 0;
обрабатываются ровно count units, включая встроенные NUL. Только ASCII a…z
преобразуются в A…Z. Для младшего, затем старшего байта каждой unit:
`hash = (hash >>8) ^ table[(hash ^ byte) &255]`. Завершающего XOR нет.
Это конкретная клиентская формула; обычный zlib CRC32 не подставляется.

`replay-ui-config-hash.py` сравнил native EAX с независимым побитовым oracle,
который вычисляет полиномиальный остаток, не читая native таблицу. 537 случаев:
префиксы строк и явные длины, ASCII / кириллица / surrogate pair, slash,
встроенный NUL, isolated surrogate, три адресных смещения, count 0 / -1 /
INT32_MIN с нулевым и ненулевым указателем. Проверены guards, неизменность
источника / таблицы, полный RIP / RSP возврат и сохранность RBX. Служебных
fixtures на этом пути нет. Некорректные для реальных ключей payloads не
объявляются поддержанным контрактом настроек.

Восемь пар дополнительно исполняют ранее проверенный native compare leaf.
Равные допустимые выбранные ключи имеют одинаковый hash, включая ASCII
разного регистра и точные non-ASCII units. Для synthetic A-NUL-X / a-NUL-Y
compare останавливается на NUL, а counted hash учитывает X / Y и различается.
Это ограничение adversarial данных, не правило принимать такие ключи или
нормализовать их в сканере. Универсальное Unicode folding не применяется.

## Общий reader без hash fixture

Запрос `0945fe0236708e13928ee7390b4b3ae6daf907ff40d3c44916ff712463f8ef07`
объединяет семь готовых roots: reader / insertion / payload / cleanup /
uniqueness / lookup / hash. Collect вернул reused / addresses=[], новых exports
нет. Готовые compare leaf и ASCII table проверяются по exact bytes / padding.

Новый режим `--native-replacement --native-hash` исполняет hash в общей памяти.
На каждом входе проверяются count / data; native EAX при выходе сверяется
с побитовым oracle и затем используется самим insertion / lookup.
Вместо одного принудительно общего bucket выделены восемь buckets.
После каждого вызова сверяются headers, hash links и все живые привязки
с независимым распределением по hash &7.

Пройдены 384 последовательности / 2304 полных вызова reader и hash, 1152
replacements / 768 reuse; все found masks, отдельный / общий destination,
poisoning освобождённых key buffers и прежние проверки cleanup сохранены.
Итог: slot 2 в bucket 4, slot 1 в bucket 5, slot 0 в bucket 6; три живые
привязки и free slot 3. Из всех chains прочитан каждый живой slot ровно один раз.

Остались семь services: virtual lookup, construction / assignment FString,
append-bit, string free, memmove и cookie service. Native hash / uniqueness /
lookup ключа / compare / capture-copy / cleanup не подменяются. Контейнер
заранее выделен, growth / rehash и полный allocator не проверены. Активная
конфигурация, precedence, последующий invoke dispatch / lifetime и Brush
остаются неизвестными; результат не разрешает игровые команды.

## Воспроизведение

Unicorn 2.1.4 / Capstone 5.0.6, полные SHA, все unwind ranges / таблицы и
exact leaf bodies проверяются перед выполнением. Прежние режимы сохранены
для регрессии. Все двенадцать tests tile refresh прошли.

Отчёты вне Git:

- `code-clues/ui-config-hash-d00a-02.json`, SHA256
  `e711cfddb0ecbde5e34b691207348db9330c8d921aedab0c63d6121a9a3d7a4b`.
- `code-clues/ui-config-reader-native-hash-d00a-02.json`, SHA256
  `9d8faadf6ae9f0313d2ae9c8b24767d50950a3c84def28966b6e51a0171cc288`.

Пробные отчёты 01 не перезаписывались. После обновления EXE требуется новый
перенос проверок, а не применение прежнего адреса / CRC таблицы.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-hash.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/7c9e28c0bd8200b8a7426c0ab2d700b8502ffda122943b9d1847620b458ad2d8/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-hash-d00a-next.json'
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-reader.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/0945fe0236708e13928ee7390b4b3ae6daf907ff40d3c44916ff712463f8ef07/manifest.json' --native-replacement --native-hash --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-reader-native-hash-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — потребители сохранённых invoke pointers и условия вызова; source
инициализация / precedence проверяются отдельно от локальной регистрации ключа.
