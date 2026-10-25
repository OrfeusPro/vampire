# NamedSlot: статическая цепочка классов и кандидатное чтение полей

Источник — EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Метод static; native регистрация / serializer / CDO не исполнялись.
Вопрос `ui-named-slot-inheritance-11316`, итоговый request
`b35f2ba11fc0482aecdccb64b590627763b7b72728c3589b05cb9dbd3785cd77`.
Именованные getter exports NamedSlot / ContentWidget переиспользованы.
Новые Ghidra exports: `run-9751e5268367` (PanelWidget / Widget) и
`run-80bbc8219c5a` (Visual), в request-exports текущего полного SHA библиотеки.
Псевдокод сверен с полными unwind-фрагментами и инструкциями.

## Цепочка и массивы

| Класс | Getter | Metadata | Property array | Parent callback |
| --- | --- | --- | --- | --- |
| NamedSlot | 143579140 | 148fd58e0 | 0 | 14356aad0 |
| ContentWidget | 1435b5080 | 148fdfd10 | 0 | 14356ab10 |
| PanelWidget | 1435b5290 | 148fe4270 | 148fe4108 | 14356ab30 |
| Widget | 1435b5340 | 148ff1590 | 148ff0c00 | 14357d570 |
| Visual | 14357d570 | 148fed900 | 0 | 141621180 |

Все getters ссылаются на точные UTF16 имена класса и /Script/UMG и вызывают
1416ab8d0. Пролог сохраняет RSP в R11 и вычитает 0x78; parent callback попадает
в [R11−0x18], то есть аргумент 13. Порядок аргументов / вызов callback в helper
описан отдельно в [GridSlot flow](UI-GRID-CONSTRUCTION-FLOW-11316.md).
Native helper и полный superclass contract этим проходом не исполнялись.

Metadata + 0 содержит getter либо проверенный E9 thunk: 14356aad0 → 1435b5080,
14356ab10 → 1435b5290, 14356ab30 → 1435b5340. Metadata + 40 содержит указанный
property array. Следующий класс за Visual здесь не анализируется.
Первоначальный адрес 14357ea70 оказался leaf-переходом, поэтому не экспортировался
как unwind root; итоговый запрос использует действительный getter 1435b5340.

PanelWidget array содержит две named descriptor rows Slots: flags low byte 82
и 22; сохранены полные 64 bytes обеих. Widget array содержит 28 проверенных
имён / flags; вложенные строки 9, 17, 19, 21, 26 отделены существующей схемой.
Кандидатный порядок для проверки payload: одна Slots строка PanelWidget,
затем 23 самостоятельных строки Widget. Это **кандидатное наследование порядка**,
не подтверждение current cooked schema или native serializer.

## Наблюдаемые экземпляры

`decode-named-slot-candidates.py` требует полный SHA request / source report,
перепроверяет EXE, class metadata, arrays, source package / body / export bytes.
`ui_named_slot.py` получает таблицу от provider и читает только поддержанные
explicit типы. Неподдержанное явное поле, truncation, остаток, неверный bool,
отрицательная / повторная ссылка и слишком большой массив отклоняются.
Omissions и serialized zero хранятся отдельно; defaults не подставляются.

44 / 44 экземпляра потреблены без остатка. Кандидатные поля:
Slot — 43, Slots — 5, bIsVariable — 6, всего 54 явных значения.
Из 48 ссылок 43 согласованы с прежними decoded slot relations по Content;
пять — только локальные exports slot-типа, без подтверждённого Parent / Content.
Пустая запись не превращается в нулевые размеры или отсутствие детей.

В каждом результате сохранены raw bytes, полные SHA и exports.
`candidate_explicit_properties`, `candidate_links`, omissions и limits отделены
от подтверждённых свойств. `defaults_applied=false`,
`inheritance_order_runtime_verified=false`, `geometry_verified=false`,
`renderer_allowed=false`. Данные персонажа и реальные профили не изменяются.

Результат в библиотеке:
`ui-property-scans/named-inheritance/results/df4fa8b1a34e54575209dbc7ac54ca58e95413db4bf6c073fd7ab072785785bd/index.json`,
SHA256 `df4fa8b1a34e54575209dbc7ac54ca58e95413db4bf6c073fd7ab072785bd`.
76 Python tests с прежними pipeline / audit / IR проверками прошли; новые fixtures
проверяют reader, а не выполнение native serializer.

Следующие проверки: реальный порядок inherited property construction / сериализации,
пять дочерних slot relations, CDO / archetype / defaults, текущий cooked вариант,
desired size и renderer. UI-27.09.02.04.02 остаётся открытым.
