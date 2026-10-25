# NamedSlot: пять дочерних PanelSlot

Продолжение [кандидатного наследования](UI-NAMED-SLOT-INHERITANCE-11316.md).
EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Вопрос `ui-named-slot-inheritance-11316`, request
`48999392d4227b3a10e82869be197617c67dbce5b0757262a6b7449e97a41244`.
Все шесть getter exports уже ready; новые Ghidra выгрузки не требовались.
Метод static. Native код и игра не исполнялись.

## Схема PanelSlot

Provider перепроверяет PanelSlot getter `1435b51e0`, точные literals PanelSlot /
/Script/UMG, полный unwind-фрагмент и вызов 1416ab8d0. Metadata `148fddad0`
содержит thunk `14356ab00` → `1435b51e0`; property array `148fdd840`
содержит именованные Parent / Content с GenFlags low byte 82. Сохранены
полные metadata bytes, descriptors и thunk. Родитель PanelSlot за этой границей
не анализируется; собственные поля не устанавливают CDO или поведение layout.

`basic.decode` повторно используется для полного чтения двух explicit ссылок,
заголовка и suffix. Исходный импорт должен быть `/Script/UMG.PanelSlot`.
Проверяются размер / SHA / диапазон export, owner слота и Parent равные NamedSlot,
существование дочернего контрола в том же WidgetTree. Self-reference, metadata /
slot вместо child, внешний owner, изменённые байты и противоречивый Parent
отклоняются. Это не чтение desired size или placement.

## Найденные отношения

| Исходный пакет | NamedSlot | PanelSlot | Content |
| --- | --- | --- | --- |
| pakchunk500-Windows-3381.json | 41 | 45 | 46 |
| pakchunk500-Windows-629.json | 179 | 207 | 189 |
| pakchunk500-Windows-629.json | 180 | 208 | 190 |
| ProjectRED-Windows-7937.json | 179 | 207 | 189 |
| ProjectRED-Windows-7937.json | 180 | 208 | 190 |

Архивные варианты сохранены раздельно. Результат содержит 44 NamedSlot payload,
54 explicit значения, 48 ссылок: прежние 43 `source_decoded_relation` и пять
новых `candidate_panel_slot_relation`. `decoded_source_relation` для новых ссылок
остаётся null, а чтение находится в `candidate_source_relation`.
Это согласованность исходных ссылок по кандидатному порядку NamedSlot; native
порядок inherited serialization остаётся непроверенным. Renderer запрещён,
geometry / defaults / inherited_serialization flags остаются false.

Результат в библиотеке:
`ui-property-scans/named-inheritance/results/26f83e4375a412c8d923ca619efe8744bf3993d444e64d6f8c6a53ca6605797d/index.json`.
Полный SHA256: `26f83e4375a412c8d923ca619efe8744bf3993d444e64d6f8c6a53ca6605797d`.
78 Python tests прошли вместе с прежними pipeline / audit / IR проверками.
Новые fixtures проверяют локальные связи и отрицательные случаи, не native
serializer или UI. Настройки / реальные профили / команды игры не менялись.

Далее: native inherited property construction / serializer order, CDO /
archetype defaults и desired sizes; до этого не разрешать применение геометрии.
