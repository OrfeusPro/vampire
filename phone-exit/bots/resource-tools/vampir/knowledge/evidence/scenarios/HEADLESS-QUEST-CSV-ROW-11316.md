# QuestTask: native чтение исходных строк и пустой service group

Source EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
QuestTask entry 2983, decoded CSV:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Задача prepare:
`74de4b1f24e4b01c193ad876f7447beb09b256fed8b73d26f8a2618069de3684`.
Collection receipt имеет state=collected, queue пуст; завершённый export
run-c5e27e535de5:
`eddd741edacd5750d9e017d24494ef404f210f051cac819831ace94d029c0f1d`.

## Исполненная цепочка

Целый tokenizer `1445f6520` имеет block и direct-flow coverage. Он получает
поток через virtual +20, число колонок из parser+20, заполняет 32-байтные
строковые cells между parser+28 и +30. Перед следующим чтением очищает прежние
cells. Кавычки, удвоенные кавычки, разделители, CR и LF обрабатывает сам native
код. Его AL — результат чтения; security-cookie fixture сохраняет RAX.

Из current CSV взяты исходные физические строки шести задач квеста 110120:
110120005, 110120010, 110120020, 110120030, 110120040 и 110120070. Они не
сериализованы повторно через csv.writer: сохраняются исходные bytes, CR/LF и
кавычки. Каждая даёт 17 cells, все значения сверены с независимым CSV reader.
Последняя пустая ServerServiceGroupId действительно создаётся tokenizer.

Созданная пустая cell затем проходит exact cell getter `1445f5eb0`, SSO leaf
`1445f14d0`, импорт atoi и целый zero gate `145a4d2f0`: все 6 строк получают
AL=0 («не пропускать»). Это дополняет прежнюю проверку синтетических cells
[настоящим Windows atoi](HEADLESS-QUEST-EMPTY-GROUP-11316.md).
Import DLL/name сверены с EXE; actual System32/ucrtbase.dll SHA и locale
записаны в report и проверены до/после, locale не меняется.

Ещё 8 lexical cases проверяют пустую последнюю / все ячейки, запятую внутри
кавычек, удвоенную кавычку, quoted LF, удаление CR, quoted empty, границу
15/16 байт и последнюю строку без LF. После каждого из 14 случаев повторный
вызов при EOF возвращает AL=0, очищает прежние cells и освобождает все fixture
allocations. Guards массива и строк остаются целыми.

## Fixtures и границы

Поток читает по одному исходному байту через явный fixture. Рост / копирование /
освобождение std::string и очистка vector также fixtures с проверкой аргументов,
строк, указателей и guards. Рост fixture выбирает собственную ёмкость, поэтому
число вызовов роста не описывает allocator настоящего клиента. Native ветви
tokenizer исполняются; реализация std::string / allocator не исполняется.
Vector заранее вмещает 17 cells; неизвестный вызов его расширения запрещён.
Строки ограничены 2047 байтами, allocation success задан явно. Неверный CSV,
BOM/header initialization, file IO, остальные строки каталога, ненулевой service
policy, constructor data record и overrides не проверены этим сценарием.

Это закрывает чтение конкретных исходных строк и blank-cell→zero-filter связь,
но не whole loader `145b5f270` и не accepted-row→record→group order.
`order_admitted=false`; активный этап персонажа по этому результату не выбирается.
Далее — native record constructor/copy и stores вместе с
[проверенной map chain](HEADLESS-QUEST-MAP-CHAIN-11316.md), затем overrides.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_csv_row_11316.py
```

Инструмент `replay-quest-csv-row-11316.py`, контекст
`knowledge/native-contexts/quest-csv-row-11316.json`, registered offline check
`native-quest-csv-row-11316`. Зафиксированы зависимости EXE, двух exports,
record index, decoder/Oodle, actual PAK и системной CRT.
Артефакт в библиотеке ресурсов:
`code-clues/quest-csv-row-11316/2fa62754e61903949c7df623adf6b2ea5378bc9c884d494475c7631933f16815/manifest.json`.

Тест не открывает сетевых соединений и не отправляет игровые действия.
Runtime, UI snapshot и действующий owner не менялись, соединение не прерывалось.
