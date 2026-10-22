# Исправление вложенного объекта ответа квестов

22 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

Эта запись исправляет вывод о suffix ID 1802 в
[прежнем исследовании списка](HEADLESS-QUEST-LIST.md) и его упоминания в
[записи квеста](HEADLESS-QUEST-RECORD.md). Старые evidence сохранены как история.
Прежняя проверка 243 тел исполняла reader с вручную заданным PktQuestData.
Она не доказывает реальную структуру полного ответа: constructor не исполнялся,
а его вложенный vptr был выбран ошибочно. Отдельный формат PktQuest / Progress
этим не опровергается.

## Реальный конструктор и границы decoder

Constructor ID 1802 `0x145829ac0` вызывает по packet+0x40
`0x14579b070`: PktItemChangeList, table `0x149921430`, reader `0x14579e360`.
Это четыре массива, не группы квестов. Их descriptors:
`0x149941560`, `0x149941740`, `0x14994b188`, `0x149941830`.

Исправленный decoder читает code, raw14, верхние PktQuest / PktAssetChange,
два bool и четыре пустых item-массива. Минимальное тело — 19 байт.
При любом непустом item-массиве он явно возвращает ошибку
`Nonempty quest item changes are not supported`: записи предметов ещё не
разобраны. Успешный ответ с произвольным содержимым не считается поддержанным.
PktQuestData / PktQuestTypeData не относятся к этому suffix.

Исправленный replay исполняет настоящий constructor ответа, constructor
PktItemChangeList, целые readers, callbacks квестов / assets и input loop.
Fresh allocation и пустые cleanup / item resizers — fixtures.
Проверены 27 тел с независимым count 0 / 1 / 2 верхних массивов и byte
0 / 1 / 255; совпали все поля. Отклонены 131 короткий префикс составного
тела. Сохранённый серверный отказ также принят native reader целиком.
Native allocator, повторное использование памяти и непустые item changes
не проверены. Заявление о полном decoder из прежней записи отозвано.

## Живой диагностический запрос

Добавлен явный `--read-quest-list` в runner. Это один ID 1801 с reset-полями
0 / 0 после успешного ID 206; локальная экспериментальная политика,
не восстановленный штатный UI lifecycle. Требуется ограниченное наблюдение,
одновременное подтверждение обучения запрещено. Нет повтора при отказе,
таймауте, частичной отправке или обрыве. После полной отправки сопоставляется
один ответ того же соединения с raw14 0. Transaction ID не установлен,
поэтому корреляция ограничена этими условиями.

Redmi M2006C3LG / JP вернул Game Login 58 / BlockedIp до запроса:
`live-login-observations/db59f7e406cc9f31eb43220c8e5179185d9f1468eb1b656c70457b50c4f89d0e/manifest.json`.
HONOR RMO-NX3 / JP прошёл Login / список / выбор / ID 206 code 0, но
первое чтение ответа завершилось ошибкой прежнего decoder:
`live-login-observations/2c0cf6469af28e0e77b87140ff9ec3053e192829c29db47221fbbf320d4343d6/manifest.json`.

Один повтор с новой диагностикой сохранил только ID 1802, 19 байт,
в приватный каталог `.phone-exit/diagnostics` вне Git. В нём code 100,
остальные поля нулевые. SHA тела:
`c26db19960b54a03ad5022ed2bf647f529c823fc3654e583b85baf5c351e4669`.
Сводка: `live-login-observations/25c5ecac0ed23f07bab4fc05246ecfa3feaf96def34bfd111f027517f28c0802/manifest.json`.
Корень всех путей — `F:/PhoneExit Resources/Vampir/`; SHA manifest совпадают
с именами каталогов. Тела auth-пакетов не сохранялись. Wire observer выключен
по умолчанию, требует явного запроса и ограничен двумя телами до 262144 байт.

Настоящий native constructor / reader и исправленный decoder разбирают
сохранённый отказ как code 100. Значение кода не расшифровано; список квестов
успешно не получен. Повторной отправки ради проверки исправления не было:
использован сохранённый ответ. Все временные маршруты завершены с code 0.

## Доказательства и продолжение

Новый Ghidra constructor export:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-387f0cc495c4/details.json`,
SHA256 `1a292ffca303ecf85f86a2a97423188bca387fe6b2c89f2ff3f9f76c06629e43`.
Исправленный native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-quest-list-corrected-replay/681ab3a11de16d216fb3fcc0f1fe8b272aae77e59422a14c9e5bd0708dd4dc60/manifest.json`.

Следом — расшифровка code 100 и источник параметров штатного ID 1801;
не повторять 0 / 0 и не подбирать значения вслепую. Для общего decoder
требуется отдельно разобрать четыре массива PktItemChangeList. Выбор квеста
ID 1836, движение и фарм ещё не подключены.
