# Источник pending+44 в текущем receiver и цепочка применения

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `a9e04f988d7a0ad2a5754031047dee207f7610aa789cec39b5d64b174718963b`.
Новый export run-b97aef41fa0c; полный SHA закреплён в
`knowledge/native-contexts/quest-environment-update-11316.json`.
Продолжение [callback после writer](HEADLESS-QUEST-ENVIRONMENT-CALLBACK-11316.md).

## Поиск и текущий код

[Исторический ID204 pipeline](../characters/HEADLESS-WORLD-MOVE-START-PIPELINE.md)
уже устанавливал источник pending+44 в прежнем клиенте. Его адреса не переносились
как актуальные. Для пары 98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e
и d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960 готового BinDiff comparison не найдено: сохранённые comparisons
относятся к одному SHA. Masked prefix из 83 байт прежнего receiver145DAE5A0
дал единственного кандидата145DAD170 на unwind root. Маскировались только
relative calls/branches и RIP displacement; это поиск, не доказательство роли.

Whole current145DAD170 экспортирован и исполняется. Его начальные записи:

| Источник | Назначение |
| --- | --- |
| прежний receiver+40, low32 | receiver+F4 |
| native input+14, u32 | receiver+44 |
| 24 байта input+18 | receiver+60 |
| byte input+30 | receiver+59 |

Текущий код не меняет +40 этими начальными stores. Затем в ветви virtual+A8=true
он уведомляет другой сервис, передаёт pending+44 в145E0F840, получает строку
через virtual+C8 и вызывает14560F9E0 с тем же receiver и значением +44.
Это прямая source-связь producer → writer, а не совпадение смещений разных объектов.
Связь current ID204 dispatcher/gate/reader с receiver в этом сценарии ещё не исполнена;
термин native input относится к подготовленной структуре, не принятому сетевому пакету.

## 48 новых совместных сценариев

Whole receiver добавлен в существующий constructor/initializer/writer/phase/getter/
callback/readiness replay. Перед вызовом pending+44 намеренно равен AABBCCDD.
Observation hook на входе writer только читает +44 и фиксирует уже записанное
значение; RIP/RAX не меняются. Поэтому тест не подставляет готовый pending.

Матрица: прежнее +40=0/5, input+14=0/1/10012/FFFFFFFF, input enum=0/3,
внешний guard missing/deny/allow. Непосредственный input выбран явно, decoder/gate
не вызываются. Контрольная копия input0x50 остаётся неизменной.
Вектор {-0.0,12.5,-44.25} переносится побайтно, включая signed zero;
это проверка полей, не допуск координат движения персонажа.

Проверены +F4, новое значение на входе writer, pending после writer, committed+40,
+59, vector+60, параметры внешних уведомлений и флаг/счётчик пустого listener list.
При allow pending обнуляется, +40 принимает input+14, перехваченный пустой callback
исполняется после возврата receiver. При missing/deny +40 сохраняется, pending
содержит input+14, callback не ставится. Phase handler реально оставляет фазу 3.
Equality predicate14568CAD0 исполняется до и после: совпадение может стать true,
но оно не отменяет отдельное phase>5 условие полного Time lifecycle.

Прежние 97 случаев сохранены; 48 новых дают 145 bounded native сценариев.
Артефакт: `code-clues/quest-environment-update-11316/5013a1dfaf976e349bb9e83c03e9882f50e9e0145a6f7621e264db0a45b796b0/manifest.json`.
Tool: `replay-quest-environment-update-11316.py`;
тест: `test_vampir_quest_environment_update_11316.py`;
check: `native-quest-environment-update-11316`.

## Явные fixtures и ограничения

Для выбора ветви используется копия source base vtable149909370 с единственной
заменой slot+A8 на fixture true. Это не установленная active derived vtable.
Оригинальные +B8/+C8 getters сохраняются. Settings flag+1F4=0 отключает коррекцию
вектора; listener count=0, actor-context field+1E8=0. Эти значения synthetic.
Previous-context selection/notification, secondary service, settings/model/actor
providers — fixtures с проверками аргументов. Прочие ветви receiver не исполнены.
Ограничения guards, строк/allocations, notifications и scheduler сохраняются из
предыдущего replay. Native producer stores и вызов actual writer не подменяются.
`network_used=false`, `action_admitted=false`.

Источник +44 теперь установлен для этой current ветви. Далее подтвердить current
ID204 registration/handler → receiver и фактическую derived vtable, затем путь
завершения фазы. Для real offer остаются active loaded task, data+14, окружение
и actor position. Онлайн-сессия не перезапускалась, игровых команд не отправлялось.
