# Version/Login 1.13.18: constructors, compiled tag и projection

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [общего wire пакета](HEADLESS-WIRE-BATCH-11318.md).
Ни авторизация, ни активация профиля не запускались.

## Источники и связи

Ограниченный поиск в пределах ±64 KiB старых roots дал кандидатов по полным
masked instruction shapes для Login constructor, двух prepare и wrapper.
Version constructor дополнительно найден по прямой RIP ссылке на уже
проверенную packet table. Префикс с RIP displacement сам по себе не совпал;
это не было основанием подставить старый адрес. Поиск не расширялся на весь EXE.

Пять roots получены одним успешным collect:
`run-b92399af7eb5/details.json`, SHA256
`960ac4e0d502d7290284acfe31c3e733d0e843231ba04c05ba12976a18fb102b`.

| Роль в проверяемой цепочке | Адрес | Инструкций |
| --- | --- | ---: |
| Version constructor | 1456D7FC0 | 36 |
| Login constructor | 1456D7950 | 53 |
| Version prepare, только tag slice исполняется | 1467CEB70 | 255 |
| Login prepare, только tag slice исполняется | 1467CE500 | 418 |
| Version wrapper constructor, только статическая связь | 1467CC850 | 115 |

Оба constructors читают pointer `14B1BBE98` → literal `149961820`:
`32283C4C6485307BCF524765A84409C3`. Значение совпало с 1.13.16, адреса другие.
Version использует table `149928508`, ID 1, имя PktVersion, tag field+B0,
object size D0. Login использует table `149927BD0`, ID 3, имя PktLogin,
tag field+110, object size 140. ID leaves исполняются, имена сверяются по
актуальным name getter/data references. Старые захваты не являются входами.

Wrapper constructor связывает table `149DCACB0`, slot+48 с Version prepare.
Это статическая связь, а не исполнение wrapper или всей подготовки.
В Login prepare проверен прямой constructor call `1467CE6A3` и соответствие
стекового назначения tag полю+110. Constructor и prepare используют один
актуальный pointer/literal, не историческое значение из кода теста.

## Native проверки

Оба constructors и реальные ID leaves исполнены для poison 00/55/AA/FF.
Следом исполняются tag assignment slices, со сверкой UTF-16 строки, `count=33`,
копирования 66 байт и canaries: 8 случаев. ASCII conversion, allocation и
memcpy — точные bounded fixtures. Остальной prepare не исполняется.

Дополнительно целые writers прошли 56 Version и 104 Login projection случая:
13/25 полей, успех и отказ на каждом поле, четыре poison fills. Проверяются
порядок, аргументы, тип archive метода, guards и прекращение после отказа.
Archive methods здесь fixtures; настоящие wire bytes доказаны предыдущим
пакетом и не объявляются новым сетевым тестом.

Новые specs выбираются по полному SHA через `tag_check_by_source` и
`writer_check_by_source`; прежние templates 1.13.16 не менялись. Новый writer
spec закрепляет memcpy `1487F60D9`. Для текущих exports включена проверка
полных unwind ranges, blocks/direct flow и conditional fallthroughs.

Прошли 14 unittest тестов: 5 Version/Login context, 5 writer context,
4 compiled tag. Включены старые регрессии и новые отказы при неверных полях.
Подробный report в библиотеке ресурсов:
`knowledge/native-tag-constructors-11318/65850e56284659f565dab41abf4c181ae870f99d64a066c2057ec1a08ce0c3ca/manifest.json`.

## Автоматизация и оставшееся

Три существующих checks получили новый SHA, dependencies и pinned artifacts:
`compiled-tag-native-11316` (исторический ID), `version-login-context`,
`packet-writer-context`. `on_update` сохранён. В граф внесены пять reviewed
bindings и source-specific data dependencies; поля old SHA сохранены.
Version/Login context adapters используют те же source-specific specs.

Whole constructor/tag slices и field projection не подтверждают полные
preparation/result handlers, SDK/GMC2/NID, framing или принятие сервером.
Кэш и успешные проверки не активируют runtime profile. Далее продолжать
полные preparation/result пакетами, используя готовый общий wire слой.
