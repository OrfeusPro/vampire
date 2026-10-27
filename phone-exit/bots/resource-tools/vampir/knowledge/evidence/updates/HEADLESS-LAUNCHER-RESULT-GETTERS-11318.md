# Launcher result getters 1.13.18: условия lookup и преобразования

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [статической проверки response](HEADLESS-LAUNCHER-RESPONSES-11318.md).
Семь полных функций исполнены с проверкой bytes, unwind ranges,
block/direct-flow coverage и conditional fallthroughs.

| Функция | Инструкций | Роль в проверяемой цепочке |
| --- | --- | --- |
| 1411B0350 | 7 | Инициализатор errorCode |
| 1411B05C0 | 7 | Инициализатор resultData |
| 14447D8F0 | 113 | Получение поля по key view из object root |
| 14447D460 | 39 | Lookup → строковое преобразование |
| 14447D4E0 | 106 | Выбор строкового/числового/boolean преобразования |
| 14447D210 | 39 | Lookup → object wrapper |
| 144472080 | 63 | Проверка типа и перенос object pointer |

## Источники

| Экспорт | SHA256 |
| --- | --- |
| run-8b262adbaa98 | 6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb |
| run-e62a0e8d1709 | 86c20afa2e8d7546a37a657bf4222ded251531f2e7cae4375cddc1eaaa69c1c7 |

Key initializer1411B0350 передаёт global14B563DA0 и UTF-16 literal14952CDE0
(`errorCode`) в constructor141426B30. Initializer1411B05C0 связывает
global14B563DF0 с literal14952CE60 (`resultData`). Exact bytes и аргументы
проверены constructor fixture; cleanup registration1487E976C — fixture.
Это закрывает прежний unknown о названиях этих двух current globals.

## 120 сценариев lookup/type gates

Два пути — строковый и объектный — проверены с шестью состояниями root:
null, тип5 вместо6, отказ virtual+80 getter, отсутствие pair, null object,
пригодный object. Каждое сочетается с пятью типами найденного value
(0/2/3/4/6) и наличием/отсутствием поля: 2 × 6 × 5 × 2 = 120.

Root должен существовать, иметь type6 и вернуть через virtual+80 ненулевые
pair/object. Только тогда вызывается lookup1415F3640. Проверены receiver,
FString key view `resultData` без завершающего NUL и его длина9.
Lookup storage и возврат shared pair — fixtures, все предшествующие gates native.
При отказе root lookup не вызывается. Оба внешних getter возвращают тот же
указатель output, который получили вызывающей стороной.

Object wrapper144472080 принимает только ненулевой value type6. Остальные
типы дают null object. Поля 08..1F и28..37 обнуляются; область20..27 native
constructor не записывает, поэтому её содержимое не объявляется очищенным.
Shared control block здесь null и перемещается отдельной явной fixture.

Строковый путь не ограничен type2: type3 направляется в числовое преобразование,
type4 — в boolean. Null/другие типы дают пустую строку. Отсутствие поля не
считается объектом и не вызывает строковые conversion helpers.

## 12 прямых преобразований

Дополнительно type2/3/4 проверены при двух значениях boolean и двух исходах
numeric string getter: 3 × 2 × 2 = 12. Type2 передаёт исходный value в
1415EA310 с destination FString. Type3 вызывает virtual+58; при true переносит
полученный буфер. При false освобождает partial buffer и вызывает numeric
getter1415EA1A0, затем formatter141438260 с float в XMM1 и R8D=0.
Вход formatter закреплён synthetic float123 (bits42F60000), не integer RDX.
Реальные числовые алгоритмы остаются fixtures.

Type4 выбирает exact UTF-16 literals `true`/`false` и передаёт их constructor.
Оба литерала сверены с EXE. Строковые fixtures используют также кириллицу,
но реальное engine copying/encoding этой проверкой не устанавливается.

Tool `replay-launcher-result-getters-11318.py`, тест
`test_vampir_launcher_result_getters_11318.py`, check `launcher-result-getters-11318`.
Артефакт: `code-clues/launcher-result-getters-11318/d1c3c80838a35839ca53b784427c2306e89c3353a6865b2236e7d509252a4f53/manifest.json`.

## Границы и следующий шаг

JSON storage/object getter, shared-pair copy/move, строковые/числовые helpers,
allocation/free и cleanup registration — fixtures. Все shared control blocks
null; деструкция последней ссылки не выполнена. Сам JSON parser, HTTP/errorCode
gates callback, dispatcher и настоящий SDK context здесь не исполнялись.

Native строковый getter допускает преобразования, которые существующий Python
parser намеренно отклоняет. Не менять строгую политику parser по одному getter:
server success и свежесть токена этим не подтверждены.
`native_execution=true`, `network_used=false`, `profile_activation=false`,
`compatibility=not_established`. Runtime и онлайн-сессия сохранены.

Далее связать эти getters с whole response callback/dispatcher и SDK context,
а подготовку запроса — с настоящими engine writers. Это не допуск нового
профиля и не подтверждение отправки квестовой команды.
