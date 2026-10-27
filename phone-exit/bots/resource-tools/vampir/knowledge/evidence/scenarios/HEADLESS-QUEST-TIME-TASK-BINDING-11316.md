# Общий task и RunInInstance в readiness Time

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `befca3a5203506d8a1dce64aaee5c203e658d3eff6a3f2da3b01df6e47005677`.
Новый export run-b36956e19880 содержит два целых predicates;
полный SHA закреплён в `knowledge/native-contexts/quest-time-gates-11316.json`.
Предыдущая [Time цепочка](HEADLESS-QUEST-TIME-11316.md) использовала их как fixtures.
В новом mode они исполняются native вместе с callback/start/tick/timer/completion.

## Что проверяют функции

Обе получают модель через exact getter1455BE4B0 и ищут record по QuestInfoId
через1455BBCB0. Exact leaf14144EC00 (`488b4130c3`) читает record+30: это
тот же task, который исполняет Time. Task+40 указывает на QuestTask data и
должен быть ненулевым. Отсутствие любого из этих значений даёт false.

14568CAD0 читает int data+14 и сравнивает с результатом environment virtual+B8.
Смысл data+14 и enum результата не установлен. Это **не** доказанный numeric
RegionType, ServicePhase или class ID; их имена не подставляются по аналогии.

14568CA20 при environment byte+58==3 сравнивает qword environment+50 с quest key;
этот путь не вызывает data virtual+20. В остальных режимах virtual+20 вызывается
дважды, если первый результат не завершил проверку. При стабильном bool flag:
true допускается с environment byte+5A==0, false — с byte+5A!=0. Противоположные
сочетания возвращают false. В исходной data vtable1499F67F8 слот+20
указывает на1433AE360: exact leaf `0fb68189000000c3` читает byte+89.
Это поле RunInInstance по [проверенному loader](HEADLESS-QUEST-LOADER-11316.md);
AutoQuest находится рядом, в+88. Смысл environment byte+5A пока не установлен.
Чтения стабильны, поскольку тест не меняет data между вызовами.

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

Уточнение request5ee9cd1696a73789d2337c33caee07f18a097886f895e3ff4970b6e64546df31:
прежнее разделение resolved object и task заменено exact source leaf.
Теперь task/data общие для predicates и Time, resolver и getter исполняются
native без callback подстановок. Оригинальная vtable data также закреплена.
Model lookup, data+14, значения RunInInstance и environment virtual+B8/fields
остаются synthetic входами. Их фактическое состояние онлайн ещё не получено.

Обнаружена дополнительная ветвь1455CDAFA–1455CDB1F: при false predicate и
RunInInstance=true tick вызывает model virtual+30 с quest key и R8B=1, затем
выходит без продвижения таймера. Здесь вызов принимает явная fixture с проверкой
аргументов; flag-mismatch даёт пять таких вызовов за пять ticks и ноль completion.
Предыдущая отдельная data fixture возвращала false и скрывала эту ветвь.
Назначение virtual+30 и его побочные эффекты этим тестом не установлены.
JSON/string/other timer readiness/property bag/final request sink fixtures
сохраняются. Predicates выбирают пути сами; повтор в сети не выполняется.
Native pending mode и standalone Time mode остаются прежними отдельными checks.
`action_admitted=false`, `network_used=false`, active session не меняется.

Далее связать data+14 с его инициализацией и происхождением
выбранного environment state. Затем конкретный source-bound offer builder
с проверкой позиции, один live action и фактический ответ. Изолированный
мультиаккаунтный live запуск/движение/диалоги общей цели ещё не подтверждены.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_time_gates_11316.py
```

Tool `replay-quest-time-11316.py`, check `native-quest-time-gates-11316`.
Артефакт: `code-clues/quest-time-gates-11316/cf2e43dc2b9c3b7d9c03aeb00e79cf5009a7d5dbf2c86a1d1c6f346048d81324/manifest.json`.
