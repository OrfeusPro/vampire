# Общая цепочка регистрации и вызова строковых привязок

25 октября 2026. Продолжение [reader / replacement](UI-CONFIG-READER-REPLACEMENT-11316.md),
[native hash](UI-CONFIG-HASH-11316.md) и [строкового присваивания](UI-STRING-ASSIGNMENT-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline Unicorn; игра, реальные профили / настройки и UI snapshot не меняются.

## Источники и интеграция

Явное задание `caccee0310394b524d63a3002d769d62827598415e12385a5b72cd916eef8e05`
содержит 12 готовых roots: 1445c2c30 / 1445c1f50 / 1445c4f60 / 141421b80 /
1445d8430 / 1445c29f0 / 141425d60 / 1445cbd00 / 1445d6ec0 / 1445c78d0 /
1445c67a0 / 1414277b0. Collect вернул reused / addresses=[], новых exports нет.
Receipt: `knowledge/collections/f3ca2dc67ceed2e6d21363cd6c1072cf59a494be4ef266ece83e60cc846b14c7/manifest.json`
во внешней библиотеке ресурсов. Source-bound Ghidra details и их полные SHA
переиспользованы из связанных доказательств и зарегистрированных зависимостей.

`replay-ui-config-reader.py --native-replacement --native-hash --dispatch`
сначала исполняет шесть регистраций с тремя replacements и двумя reuse,
как в предыдущем режиме. Затем вызывает read / write consumers на том же
контейнере и той же памяти. Между регистрацией и dispatch контейнер / entries /
invoke pointers / captures не переписываются host-кодом. Исходные synthetic
входы и primitive services остаются явными; это не живая сессия клиента.

## Проверенная последовательность

384 сочетания всех found masks, трёх групп значений и общего / отдельного
destination дают 2304 полных reader вызова. После этого для трёх живых ключей
и Missing выполняется read → write → read: 12 consumer вызовов на сочетание,
всего 4608. Для ContentSubName используется ASCII case variant запроса.

При hit read consumer использует настоящий hash / lookup, capture-address
getter и сохранённый invoke → native clone. Write consumer по второй операции
вызывает leaf и настоящее тело assignment 1414277b0. Получены 2304 read invokes,
1152 write invokes и 1152 native assignments. Miss обнуляет read output и
обходит write invoke; всего 1152 consumer miss вызова.

Подтверждено:

- После replacement consumer получает последний destination ключа. Ранее
  привязанные отдельные адреса остаются в контрольном наборе и не меняются.
- Регистрация missing всё равно сохраняет callable в проверенном сценарии;
  последующее явное обращение находит его. Это не автоматическое событие.
- Read-before возвращает фактическое текущее значение (включая null / empty),
  write присваивает новое значение по capture, read-after копирует его в
  независимый buffer. Resize fixture возвращает capacity с запасом 5 units;
  native assignment сохраняет её, а clone получает count текущего destination.
- После каждого consumer проверяются весь контейнер, allocated / free entries
  и восемь bucket headers: все совпадают со снимком после регистрации.
- Все текущие и прежние destinations, guards, непустые payload bytes и живые
  key buffers сверяются после каждого вызова. Освобождённые при replacement
  ключи помечены DD и не используются действующими bindings.
- Query FString освобождается и помечается DD до invoke. Сохранённый capture
  используется независимо от временного query и временных stack объектов.
- На каждом consumer действительно исполняются native hash / lookup; при hit
  вызывается native compare. Их число и service порядок проверены отдельно.

## Fixtures и пределы вывода

Десять services остаются fixtures: registration config lookup, initial counted
FString assignment 14142a250, key/query construction, append-bit, string free,
replacement memmove, cookie service, clone allocation, byte-copy и value resize.
Consumer assignment 1414277b0, hash, lookup, compare, insertion / replacement,
capture-copy / cleanup и invoke цепочка исполняются native кодом полностью.
Начальное counted assignment reader и terminator assignment consumer различаются;
fixture первого не выдаётся за проверенный native body второго.

Контейнер заранее выделен на четыре slots; реальный allocator / growth /
rehash / allocation failure, bitmap service и общий container lifetime не
восстановлены. Write payloads в dispatch — явные demo строки. Capture lifetime
доказан только в пределах этих последовательностей, не за пределами владельца.
Caller / событие, persistence, config source precedence, активные настройки,
применение к UI, resource / Brush и cooked compatibility остаются открытыми.
Проверка не отправляет команды боту и не открывает генерацию внешнего вида.

## Повтор и результаты

Unicorn 2.1.4 / Capstone 5.0.6; полный SHA EXE, unwind roots, exact leaf bytes /
padding и таблицы проверяются до выполнения. Исполнение за пределами выбранных
тел и services отклоняется; каждый полный возврат проверяется по RIP / RSP.
Все шестнадцать tests tile refresh прошли, включая прежние режимы для регрессии.

Отчёт вне Git: `code-clues/ui-config-registration-dispatch-d00a-02.json`, SHA256
`27bbe9d274ba98278a0a5b331bfbc1b1eee6ffe713bef64509992a0e60939533`.
Пробный 01 сохранён отдельно. Новый режим входит в source-bound план обновления;
новый SHA требует сверки / переноса, автоматического runtime promotion нет.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-reader.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/caccee0310394b524d63a3002d769d62827598415e12385a5b72cd916eef8e05/manifest.json' --native-replacement --native-hash --dispatch --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-registration-dispatch-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — callers / условия вызова consumers и источник / precedence настройки.
Отдельно проверить перечисление 1445cb6c0 и исходный counted assignment;
общий локальный прогон не доказывает применение конфигурации к UI автоматически.
