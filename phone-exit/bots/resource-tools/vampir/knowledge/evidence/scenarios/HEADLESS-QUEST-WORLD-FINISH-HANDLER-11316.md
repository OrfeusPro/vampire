# ID206: полный обработчик, фильтр и завершение окружения

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`
(1.13.16). Продолжение
[receiver → completion](HEADLESS-QUEST-WORLD-FINISH-COMPLETION-11316.md).
На установленную 1.13.18 результат автоматически не переносится.

## Составное исполнение

В одной VM теперь исполняются whole handler1467CA450 → common gate1467CD7B0
→ receiver145DACA00 → настоящий derived virtual+78/145DA88D0 → base145612A90
→ phase setter145618B30. Getter окружения14560ADC0 читает source global,
getter пакета145757EA0 возвращает 206. Таблицы handler/packet/derived и exact
registration window проверяются прежним helper, сетевого dispatch нет.

Exports закреплены в runner и check:

| Экспорт | SHA256 |
| --- | --- |
| run-7650bee00bb6 | 9c583d5995e73bb8b2f8891c8c965781f1f5b44a68f445e8fe0dc73c615ddefe |
| run-eff5f37ca91c | 4e22414b4f8c1c431e4b3c417917f72aee1223df0049b08d50d121275619b43d |

Остальные три exports completion перечислены в
[его доказательстве](HEADLESS-QUEST-ENVIRONMENT-COMPLETION-11316.md).
Для legacy gate export явно добавлена missing instruction1467CDAB2 bytes
`488b4d47`. Исполняемый prefix проверяется по точным границам:
диапазон1467CD7B0..1467CDBC7 (251 instruction, последний RET1467CDBC6)
сверяется по unwind decoding и source bytes. Inline tables после RET — данные.
Непроверенная цель исполнения запрещена harness.

## 16 ветвей и сохранность состояния

Матрица: player key +8 zero/nonzero × setting byte false/true × code
0/10/0x1197/FFFFFFFF. Это synthetic stress inputs, а не рекомендации посылать
такие значения серверу. Объект player существует в каждом случае, его
отсутствие как null pointer здесь не проверялось.

| Вход | Проверенный результат |
| --- | --- |
| key0, любой code/setting: 8 случаев | Early return до диагностики/gate; phase3 и world fields сохранены |
| key nonzero, code0, оба settings: 2 случая | Receiver и completion, phase6, player world10012 |
| key nonzero, code0x1197, settingfalse: 1 случай | Сначала error presentation, затем receiver/completion и phase6 |
| Остальные key nonzero: 5 случаев | Rejected boundary, phase3 и world fields сохранены |

Следовательно, true gate не означает code0 или отсутствие ошибки. Это важная
граница будущей корреляции: сам проход handler не может подтверждать успешное
выполнение квеста. Даже принятие ID206 относится к переходу мира, не к QuestUpdate.

При key nonzero native handler сначала пишет диагностику, выполняет external
подготовку, затем вызывает настоящий gate. Accepted ветвь проходит настоящий
receiver, запись world fields и phase6 до уведомления; лишь затем вызываются
post-receiver effects. Actual refcount control+8 во всех 16 случаях возвращается
к 2. При early/rejected ни environment0x1B0, ни player world не изменяются
в пределах явно заданных boundary fixtures.

Прежние 24 receiver и 28 completion сценариев также выполняются. Всего 68
сценариев в новом составном прогоне; три отдельных unittest прошли.

## Воспроизведение и границы

Runner `replay-quest-environment-completion-11316.py` с
`with_world_finish=True, with_handler=True`; helper
`quest-world-finish-binding-11316.py`. Тест
`test_vampir_quest_world_finish_handler_11316.py`, check
`native-quest-world-finish-handler-11316`.
Артефакт:
`code-clues/quest-world-finish-handler-11316/a41c847836611fe18cf28fb98b3657be8edd65e03703df1a5488b391e7d2e8e3/manifest.json`.

External preparation145D9C220, error presentation145FD3EE0, rejected
boundary146750120, setting provider и post-receiver services/effects — fixtures.
Неточное состояние этих внешних объектов не выводится из сохранности
environment. Диагностика/UI, providers, world record missing, player arrays,
vector predicate/heading, actor lookup/create missing, derived+A0=false
сохраняют прежние fixture limits. Reader, raw wire, packet constructor целиком,
active dispatcher, непустые effects, created actor и специальные derived ветви
в новую композицию не включены. Ни игра, ни авторизация не запускались.

`native_execution=true`, `network_used=false`, `action_admitted=false`.
Связь whole handler/gate/receiver/completion закрыта в этом bounded режиме.
До action builder нужны real record+0C/name, active task и full Time lifecycle;
проверки установленной версии и одноразовый online тест остаются обязательными.
