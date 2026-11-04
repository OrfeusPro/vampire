# Прямое доказательство directory → header → payload

Три прежних missing-index записи получили собственные доказательства без
изменения линейного индекса. На девяти выбранных архивах все 54 объявленных
resource inputs partial-контекстов карты, квестов и UI теперь используют
точные нужные файлы. Это не подтверждение полной runtime closure или входа.

## Зарегистрированное правило

Selector resource-directory-record.json включает directory-record-header-v1
и точный primary proof. Формат serialized FPakEntry закреплён по
[CUE4Parse commit 1e3293d4](https://github.com/FabianFG/CUE4Parse/blob/1e3293d4b3ecaf6ef3d73641b9ffe47fa4cf1562/CUE4Parse/UE4/Pak/Objects/FPakEntry.cs#L36).
SHA исходника: 7836940c53b39cb074c2b1310d11bdd0f1dce6699c57079d978c6d62bd368185. Package и nuspec связаны с тем же
commit и проверены по SHA. Primary описывает layout, а не исполнение игры.
CUE4Parse пропускает 20-byte Hash и не выполняет здесь проверку SHA1.
Наше совпадение SHA1 stored payload — отдельное более строгое условие допуска
данных этим рецептом, а не утверждение о всех вариантах PAK.

Источник обязан совпадать с текущим полным SHA и v11 record manifest.
Имя / offset / размеры / method / blocks берутся из проверенного полного
directory report того же открытого owner. Offset должен отсутствовать в
линейном индексе: новый рецепт не подменяет уже индексированные записи.
Непосредственный header должен иметь local Offset 0 и совпадающие размеры,
method, block count. Flags 0; поддержаны method 0 / 1. Чтения точные и
ограничены следующим distinct directory offset либо началом index area.
Compressed spans положительные, непрерывные, непересекающиеся; их сумма
равна stored size, число согласовано с decoded size и block size.

Plain record имеет одинаковые stored / decoded размеры и blocksize 0.
Пустая запись проходит отдельную явную ветку: обе длины нулевые, flags и
blocksize 0, SHA1 совпадает с пустым содержимым. Старый reader.header не
получает фиктивной положительной длины. Header и stored record имеют свои SHA.
Перечитывается только выбранная запись; payload после хэширования не хранится.

При повторном обращении к одному offset скалярные metadata сравниваются
до memo: второе имя с конфликтующим размером не получает hash первого.
Лимиты — 1 MiB на запись, 16 MiB на проход, 64 уникальные записи. Другой
layout, шифрование, нарушение SHA1 / source / границ или бюджета сохраняют
конкретный отказ; имя файла не снимает проверку.

## Подключение к обновлению и кэшу

Context keys вызывают direct rule только для selected_record_missing_from_index.
Другие причины прежнего обработчика не обходятся. Все 244 готовых indexed
hash receipts остались прежними и использованы из кэша без нового decode.
Исходные directory / record reports и named baselines не переписывались.

Новые receipts хранятся в resource-directory-record-v1 библиотеки, pointers —
knowledge/resource-comparison-cache-v3/directory-record-<key>.json. Ключ
содержит точные source / directory / index pointers, entry / boundary,
decoder, код, selector, primary source и runtime. Сначала проверяется общий
свежий SHA owner barrier; только затем cache назначается для следующих запусков.
Source SHA, aliases и runtime проверяются и при тёплом reuse.

Context proof содержит ссылку на новый hash с method=directory-record-header-v1;
receipt добавляет directory_records metrics. Rule / primary / decoder inputs
входят в ключ ресурсов. Ordinary update учитывает helper и selector в definitions,
aggregate проверка зарегистрирована в on_update. Partial contract guards,
semantic checks, source allowlists и admission не повышаются.

## Настоящие данные и повтор

EXE: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f; ресурсный патч Revision268356.

| Файл | Stored bytes | Decoded bytes |
| --- | ---: | ---: |
| ConcertSharedSlate.uplugin | 514 | 1040 |
| WorldMetrics.uplugin | 865 | 865 |
| TestNavData_Nav.bin | 0 | 0 |

Всего 1379 stored / 1905 decoded bytes; 1 compressed decode, 1 plain read,
1 empty record. Старый selected layer по-прежнему видит три missing-index
offset, но передаёт их новому доказанному правилу. Итоговый fallback — 0.

| Контекст | Inputs по содержимому | Fallback по архиву | Записей в inputs |
| --- | ---: | ---: | ---: |
| game-ui | 18 | 0 | 27368 |
| map-data | 27 | 0 | 5446 |
| quests | 9 | 0 | 414 |

Первый финальный проход: 58.687355 с. Повтор: 57.598088 с,
244 indexed cache hits и 3 direct cache hits, 0 новых resource decode.
Все context values совпали; fresh proof / owner receipts сохранились.
Три диагностических component-directory-record-* этапа повторно взяты из
кэша. Они остаются requires_review, не заменяют semantic tests и не дают допуска.

## Проверки и остаток

Добавлены 30 автоматических случаев: 26 parser / owner / cache и 4 integration.
Проверены все границы truncated header, plain / compressed / empty, flags,
SHA1, соседние offsets, source / directory provenance, запрет замены indexed
records, конфликт metadata до memo, cache corruption и отложенная публикация.
Общий набор завершил 1765 тестов с тремя прежними пропусками; шесть
дополнительных checks прошли. Полный ordinary update, игровой вход, новые
JVM, native replay сценарии и CSV extraction не запускались. Oodle вызван
только для отдельного нового compressed resource record.

Пакет текущих неизвестных resource hashes закрыт в области девяти архивов
и трёх partial contexts. Далее — подтверждение полных runtime / data dependencies
перед source_checks / builders и перенос legacy source checks. Девять старых
historical unknown hashes и ближайшая prepatch named база остаются отдельными
пробелами. Watcher / prepared-next / live session не менялись. 59 frozen
native inputs, 48 прежних facts и исторические разделы сохранены.

- [Машинный отчёт](AUTO-RESOURCE-DIRECTORY-RECORD-V1-268356.json).
- [Предыдущие выбранные hashes](HEADLESS-RESOURCE-SELECTED-HASHES-V1-268356.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
