# CharacterList 1.13.18: общий source-bound пакет

Полный SHA EXE:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Старый источник для сопоставления:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Авторизация, сетевые и игровые команды не выполнялись.

Пакет объединяет WaitingEnd → ID101, envelope ID102, CharacterRecord,
appearance/optional collections, whole list и handler/gate/policy ID102.
40 явных semantic roots сопоставлены по целому коду / control flow; три
одинаковых resize wrappers различены по source-linked callback table slots.
Общие input/UTF8/Time и gate использованы из готовых exports.

Первый экспорт `run-298a8242c322` отклонён: декомпилятор включил код вне
unwind ranges у `1456d2640`. Два E9 к самостоятельным roots `1456d1da0` /
`1456c7660` проверены по EXE и явно добавлены в новый request. Границы collector
не ослаблялись. У остальных 17 roots этого запроса внешних branches нет.
Неудачная попытка сохранена, повтор с теми же входами не выполнялся.

Пять current exports / SHA:

- `run-bd63520caaaf`: `372529e5774232cd2cf01e5d71dc33bbc618cb9d2fceccc5510d8b4bafa4e4d6`.
- `run-d6af42842586`: `6aa57c52b86047cb0e0840116bb41bff3d806a80e0746fdfc903ae973c11abc8`.
- `run-ed5c8eee70bc`: `8463fef01f722fccfca821d50b57824135019a75ef0794e192bdd3ab12d7ae3f`.
- `run-450b89173dc1`: `c4a61844217b6edda4cf4ebc7fdd639b0178ad28460927ef690be9122f14da1c`.
- `run-b66ea903e973`: `3afe56601081a2fb64a90f1196585a55415e56c37f05b4dc950d7e25a0116b95`.

`generate-character-list-contexts-11318.py` проверяет оба полных SHA, fixed
40-root set, shape и фактические calls / data links, таблицы, leaves и
registration. Окна регистрации ищутся внутри явного owner по полному shape
и handler vtable slot +10. Историческое WaitingEnd window начиналось внутри
MOV immediate; старый контекст сохранён, новое окно начинается с MOV ECX,8.
Native проверка нового окна прошла. Notify name проверен отдельно.

Первый native пакет обнаружил старые 152 байта nested input table при уже
новом адресе `149672080`. Генератор исправлен: 19 указателей читаются из
current EXE после проверки исходных bytes; неизвестные byte fields / address
maps отклоняются. Контексты пересозданы, затем весь пакет прошёл.

Доказательства в библиотеке `F:/PhoneExit Resources/Vampir/knowledge/`:

- Alignment: `character-list-batch-alignment-11318/54298b7f234a746ad61faf94347d29ab7ed316a4c2b3d53575171839ee502729/manifest.json`.
- Generation: `character-list-contexts-11318/1e2fc42f1a44f24e90620e8cf0160b85af4db9992954f2ccd81235495f0982ab/manifest.json`.
- Native: `character-list-batch-verified-11318/0d11e9b458e4ec9305b825acac22a56a1da3ed036872e287ed8dbeea7ee19397/manifest.json`.

В отчётах 1554 строки объявленных scenario lists: WaitingEnd 16 + fallback8;
envelope 24/38 short/7 failures; record 128/201 short/128 failures/2 extension
boundaries; appearance 5/58 short/42 failures; optional 19/201 short/94 failures;
whole list 32/291 short/154 failures/5 multi-short; handler101. Дополнительные
trailing-body / local budget observations сохранены отдельно в тех же reports.
Четыре разных записи whole list сохраняют разные strings / collections.
Handler публикует 15 synthetic lists, поддерживает preference и пустой список.

Общий runner проверяет SHA EXE/exports/контекстов/кода/Python/native runtime,
состав шести reports и равенство отдельным snapshots. Положительные тесты
используют один cached native пакет, сохраняя прежние assertions. Негативные
тесты вызывают настоящие verifiers с изменёнными dependencies / tables / calls.
Owner lock исключает одновременный повтор native build; чужие locks не удаляются.

Ограничения: storage/allocator/rehash/copy и engine services заданы fixtures.
Reader и handler проверены отдельно; общая reader→handler композиция, настоящий
dispatcher, серверный ответ, выбор / создание персонажа и вход в мир этим
пакетом не подтверждены. Gate1197 в одном режиме продолжает обработку после
ошибки и не означает успех сервера. Runtime game profile и baseline не включены.
