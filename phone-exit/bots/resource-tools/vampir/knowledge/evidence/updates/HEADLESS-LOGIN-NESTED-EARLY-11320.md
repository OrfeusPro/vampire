# LoginResult 1.13.20: вложенные readers и ранние ветки handler

28 октября 2026. Продолжение [reader flow](HEADLESS-LOGIN-READER-FLOW-11320.md)
и [continuation](HEADLESS-CONTINUATION-11320.md). Полный SHA EXE:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.

## Вложенная структура

`verify-login-nested-11320.py` использует шесть полных готовых exports:
packet constructor `0x1456d7660`, reader `0x1456dc140`, time constructor
`0x1457a3870`, period constructor `0x1457a2710`, time reader `0x1457fe090`
и period reader `0x1457a5b90`. Source-bound context содержит SHA exports,
проверенные bytes leaf base constructor, ID getter и virtual dispatch thunk.
Таблицы `0x149929040`, `0x149921e68`, `0x149928ff8` сверены с reader slots.
ID getter исполняется и возвращает 4.

Nested dispatch теперь исполняется native: вместо прежнего opaque nested fixture
вызываются actual time/period readers. Полный packet содержит 28 primitive
операций. Новый хвост — string descriptor `+0x140` и raw32 `+0x150`, `+0x154`;
объект проверяется в пределах `0x160`. Значения constructor defaults `+0x130`
и `+0x134` сверены с текущими исходными global bytes, padding сохраняется.
Constructor проверяется по точному ожидаемому содержимому и native vptrs.

Прошли **232 native сценария**: два заполнения памяти × два flag значения ×
два ненулевых primitive результата × (полный успех + отказ на каждой из 28
операций). Проверены тип/порядок/адрес каждой primitive операции, native nested
dispatch, прекращение после отказа, AL, ABI, packet/archive и canaries.

Archive primitives, string reader и создание пустой trailing string остаются
явными fixtures. Это проверка layout и native маршрута чтения, а не actual wire
decoder / UTF-8 / политика нормализации bool. Имена и продуктовый смысл новых
полей не установлены по одному их смещению.

## Ранние ветки handler

Субагент реализовал независимый `verify-login-handler-early-11320.py`;
результат просмотрен и повторён главным агентом. Используется полный handler
`0x14679e2d0` из закреплённого export `run-cc90e4f503ac`.

Прошли **14 native сценариев** для кодов 54, 9818, 9819 и 90021:
два заполнения памяти; для optional object — присутствие/отсутствие.
Проверены точные действия и аргументы, их порядок, ABI и неизменность packet
`0x160`, optional object и canaries. Строки/localization/log/popup/lookup/actions
и finalization — объявленные fixtures. Gate, успешная ветка, callback popup,
внешние сервисы и серверный результат не исполнялись. Неожиданные native targets
отклоняются общим harness.

## Автоматизация и доказательства

Два штатных source-specific checks `native-login-nested-11320` и
`native-login-handler-early-11320` подключены к `on_update` и кэшу с dependencies,
exports и Capstone/Unicorn runtime metadata. В граф внесены шесть scoped bindings:
packet result constructor, четыре nested constructor/reader и early handler.
Ранее проверенный result reader сохранён. Полные result/handler checks не
подменяются этими ограниченными проверками.

Четыре regression tests прошли, включая отказ при подмене nested table и bytes
dispatch thunk. `collect` вернул reuse, новый Ghidra не запускался.
Отчёты в библиотеке `F:/PhoneExit Resources/Vampir`:

- Nested: `knowledge/login-nested-11320/a09e5073f895709213f4d557b744f0f07d80f403e6ddbf6249300179e2d0d5f3/manifest.json`.
- Early handler: `knowledge/login-handler-early-11320/f09b394f52f72663c783814971a85fa57ffd86f9278c3db4ed29b1f8ca5c7b78/manifest.json`.
- Collection reuse: `knowledge/collections/8ca63183f567a13b14de91ce11468e65f5c40b87b1dbbf61242636d6b8d7ed7b/manifest.json`.
- Export SHA и адреса: `knowledge/native-contexts/login-nested-11320.json` в репозитории.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-login-nested-11320.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-login-handler-early-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_nested_11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_handler_early_11320.py
```

## Остаток

В этом пакете **246 native сценариев**, шесть bindings и две штатные проверки.
Остались actual primitive/string decode, более широкие handler paths, включая
новые действия с полями `+0x140/+0x150/+0x154`, registration и post-state boundary.
Строгие **346 основных функций + 30 helpers** не закрыты целиком этим bounded
пакетом. Сеть, авторизация, игровые действия и runtime activation не запускались.
