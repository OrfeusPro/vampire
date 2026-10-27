# Изменение поля окружения и quest readiness

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `1464287cbcb14e02dfae9f83ed7dbdfdda9dc4925404e18eccbc9864c326e9a5`.
Exports и полные SHA: `knowledge/native-contexts/quest-environment-update-11316.json`.

## Подтверждённые связи

В окружении [constructor и initializer](HEADLESS-QUEST-ENVIRONMENT-INIT-11316.md)
задают primary vtable 149909370 и начальный int+40=0.
Функция 14560F9E0 получает receiver в RCX и новое 32-битное значение в EDX.
После запроса phase=3 и преобразования строки она получает внешний объект
через 1445D2A20(0), затем проверяет его virtual+7B8.

При null объекте или false guard функция ставит environment byte+C1=1,
сохраняя прежние +40 и +44. При true guard инструкция 14560FAA5 пишет EDX
(сохранённый в R14D) в environment+40, а +44 сбрасывается в исходный 0.
Далее подготавливается callback 145606830 и передаётся в 144A78160.
Запись значения происходит до callback; успешное завершение callback не доказано.
Смысл guard и числа, записываемого в +40, пока не объявляется именованным enum.

Связь receiver с окружением подтверждает source vtable+70=14561BCA0:
при byte+C1!=0 этот метод получает пустую строку через source virtual+C8,
передаёт environment+44 в EDX и вызывает 14560F9E0 с тем же this.
В этой ветви метод возвращает 0 даже при записи нового +40.
Возвращаемый 0 нельзя объявлять отказом смены поля.
При C1=0 и byte+30 в {2,3,4} он отправляет phase=5 и возвращает 1;
при остальных проверенных фазах возвращает 0. Это запрос фазы, не её применение.

## 48 native сценариев

Исполняются целые constructor, writer, retry caller и predicate 14568CAD0;
exact leaves задают initializer, global getters, record+30, int environment+40
и пустую строку virtual+C8. Исходная vtable проверена по slots+10/+70/+B8/+C8.
Caller export run-529edd8cc6b1 содержит block coverage, но ещё не содержит
поля direct-flow coverage. Только этот legacy адрес разрешён явно; дополнительно
проверено наличие fallthrough каждой Jcc. False coverage не принимается.

36 случаев: direct/retry, внешний объект missing/deny/allow, прежнее +40=0/5,
передаваемое значение 0/1/FFFFFFFF. Это stress inputs, а не значения live enum.
Readiness до и после writer исполняется native на том же объекте окружения
и сравнивает его +40 с task data+14. При разрешённой записи predicate видит
новое значение; при отказе продолжает видеть прежнее. Проверены +44, C1,
ровно один phase=3, число callback submissions и неизменность task/record/data.

12 случаев: C1=0, прежнее +40=0/5 и фазы 0/2/3/4/5/7. Они проверяют возврат,
запрос phase=5 только для {2,3,4} и отсутствие writer/guard/callback.

Артефакт: `code-clues/quest-environment-update-11316/8e28397af75380dde86ea425ba40d75df5acc6938f749638aac13441783b978f/manifest.json`.
Tool: `replay-quest-environment-update-11316.py`;
тест: `test_vampir_quest_environment_update_11316.py`;
check: `native-quest-environment-update-11316`.

## Fixtures и ограничения

Registration base helper, model lookup, внешний объект/guard, форматирование,
пустые FString и преобразование текста, phase request и moved-callback sink —
явные fixtures с проверками аргументов. Phase handler 145618B30 и callback
145606830 не исполняются. Nonempty text/allocation paths не проверены.
Вместо сетевой команды проверяется реальное изменение локального native объекта;
`network_used=false`, `action_admitted=false`.

Кандидат 14560FE40 оказался конструктором другого объекта с vtable149908C48;
одинаковое смещение +40 не связывает его с этим окружением. Он не включён в replay.
Кандидат 145610390 не экспортирован: decompiler вышел в switch tails за unwind
ranges. Без связи с нужным store этот большой разбор не расширялся.
Метод vtable+78 145612A90 экспортирован отдельно; прямого store+40 там нет.
Эти навигационные результаты не доказывают отсутствия остальных writers.

Следом — источник pending environment+44, реальный guard и callback применения,
поздние записи task data+14. Начальное 0 не заменяет активное состояние.
Для live offer также нужны selected task и подтверждённая actor position.
Текущая онлайн-сессия сохраняется, игровые команды в этом исследовании не отправлялись.
