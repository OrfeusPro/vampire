# Реальные readiness predicates в native Time lifecycle

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `befca3a5203506d8a1dce64aaee5c203e658d3eff6a3f2da3b01df6e47005677`.
Новый export run-b36956e19880 содержит два целых predicates;
полный SHA закреплён в `knowledge/native-contexts/quest-time-gates-11316.json`.
Предыдущая [Time цепочка](HEADLESS-QUEST-TIME-11316.md) использовала их как fixtures.
В новом mode они исполняются native вместе с callback/start/tick/timer/completion.

## Что проверяют функции

Обе получают модель через exact getter1455BE4B0 и ищут record по QuestInfoId
через1455BBCB0. Затем resolver14144EC00 получает объект, у которого pointer+40
должен быть ненулевым. Отсутствие любого из этих значений даёт false.

14568CAD0 читает int data+14 и сравнивает с результатом environment virtual+B8.
Смысл data+14 и enum результата не установлен. Это **не** доказанный numeric
RegionType, ServicePhase или class ID; их имена не подставляются по аналогии.

14568CA20 при environment byte+58==3 сравнивает qword environment+50 с quest key;
этот путь не вызывает data virtual+20. В остальных режимах virtual+20 вызывается
дважды, если первый результат не завершил проверку. При стабильном bool flag:
true допускается с environment byte+5A==0, false — с byte+5A!=0. Противоположные
сочетания возвращают false. Role virtual flag и byte+5A ещё не source-bound;
они не называются AutoQuest только по ожидаемому поведению.
Если callback меняет flag между вызовами, поведение нужно проверять отдельно;
здесь явная fixture возвращает стабильное значение.

## 34 совместных сценария

Source Time rows110120005/070 (seconds0.1/1), как в прежней проверке.
Native model getter, оба predicates и целая Time цепочка исполняются вместе.
Добавлены mode3 с совпавшим/другим quest, null resolved object/null data,
совпадение/несовпадение int kind и оба сочетания flag/byte для true flag;
прежний open проверяет false flag с byte+5A=1. Недостающий model теперь
останавливает таймер в predicate, раньше fixture позволяла дойти до completion.

При open/mode3-match/flag-match два завершения за пять ticks: requests
[0,0,1,1,2], states [1,FFFFFFFF,1,FFFFFFFF,1]. При state update после первого
завершения повтор прекращается. При закрытых predicates elapsed остаётся0,
state остаётся1. Недостаточный environment phase byte+30, owner state и четыре
start guards сохраняют свои прежние проверки. Phase byte здесь не объявляется
ServerServicePhase. Model getter global source-bound, но содержимое глобала
явно synthetic.

## Fixtures и оставшееся неизвестное

Model lookup, shared-record resolver, quest data+14/virtual+20 и environment
virtual+B8/fields — bounded fixtures, проверяющие receiver/поля. Это не значения
работающего клиента. Task+40 QuestTask data и predicate resolved+40 data разделены
в памяти; совпадение типов/таблиц этих объектов не предполагается.
JSON/string/other timer readiness/property bag/final request sink fixtures
сохраняются. Predicates выбирают пути сами; повтор в сети не выполняется.
Native pending mode и standalone Time mode остаются прежними отдельными checks.
`action_admitted=false`, `network_used=false`, active session не меняется.

Далее связать data+14/virtual+20 с current QuestInfo source и происхождением
выбранного environment state. Затем конкретный source-bound offer builder
с проверкой позиции, один live action и фактический ответ. Изолированный
мультиаккаунтный live запуск/движение/диалоги общей цели ещё не подтверждены.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_time_gates_11316.py
```

Tool `replay-quest-time-11316.py`, check `native-quest-time-gates-11316`.
Артефакт: `code-clues/quest-time-gates-11316/ede046f292b596cb6cc0a3dd902bd85bb2af525127f052ea987fec14763e111a/manifest.json`.
