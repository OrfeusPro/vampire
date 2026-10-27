# Callback после записи окружения: цель, gates и ограничения результата

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `1d4190c45cdbf01f7390a9af0d03f86b150954414ccf8908e8419a8c38cf8353`.
Новый export run-f0f4b34f6f84, полный SHA закреплён в
`knowledge/native-contexts/quest-environment-update-11316.json`.
Продолжение [реального phase handler](HEADLESS-QUEST-ENVIRONMENT-PHASE-11316.md).

## Границы callback и tail

Writer 14560F9E0 передаёт адрес 145606830 в 144A78160 вместе с захваченным
строковым состоянием. Callback получает pointer аргумента в RCX, вызывает
145490870 и 143C1BAC0, затем передаёт полученный context в RCX, исходный pointer
в RDX и нули в R8D/R9D. Завершающий E9 по 145606857 ведёт в самостоятельный
unwind root 14432F950.

Первый export отказал из-за выхода декомпилятора за запрошенные ranges.
После проверки E9 обе roots запрошены явно: metadata CALL_RETURN отделила tail,
исходные инструкции не менялись. Новый export прошёл block/direct-flow coverage.
Неверная расширенная декомпиляция первого запроса доказательством не используется.

## Целевая функция при двух нулевых флагах callback

14432F950 читает внешний объект по context+158. При ненулевом объекте и false
virtual+7F8 возвращает AL=0 без изменения context. При отсутствии объекта эта
проверка обходится. Разрешённый путь пишет byte context+731=2.

Если signed count по context+740 меньше 2, получает дополнительный context
через 1442BA3A0(global14B559008, context). При byte extra+80=0 вызывает
141441D60(context+738, исходный аргумент). Если внешнего объекта нет, обнуляет
raw dword context+718; иначе передаёт pointer аргумента и byte 0 в virtual+800.
При count>=2 или extra+80!=0 копирование/virtual+800 не вызываются, но AL=1.
Поэтому AL=1 не доказывает запись новой строки, выполнение обработчика или
завершение перехода. Ненулевые R8B/R9B целевой функции в этом сценарии не проверены:
source callback всегда передаёт 0/0.

Это адреса и поля клиента; имена классов/enum и сетевой результат не предполагаются.
Virtual+7B8 первоначального writer и virtual+7F8 callback — разные проверки.

## Handoff и 97 проверок

В прежних 36 writer/retry случаях разрешённая ветвь передаёт callback pointer
и 16 байт пустого строкового capture по submission+28 в явную очередь fixture.
После возврата writer payload копируется в принадлежащий replay scratch и
выполняются whole callback и tail. Это fixture dispatch, не настоящий scheduler.
Проверены AL=1, запись context+731, один вызов processing fixture и неизменность
всего environment после callback, включая уже применённую фазу 3 и +40/+44.
При отказе исходного writer callback не ставится. Путь nonempty capture не проверен.

Прежние 12 caller phase cases, 9 getter cases и 16 phase transitions сохраняются.
Добавлены 24 callback cases: внешний объект present/absent, virtual+7F8 true/false,
count 0/1/2 и extra+80 0/1. Для count 1/2 подготовлены корректные synthetic
UTF-16 buffers/descriptor counts; heap ownership настоящего FString не исполняется.
Проверяются AL, весь context размером 0x800, число вызовов engine lookup/copy/process,
аргументы forwarding и неизменность environment размером 0x200.
Без объекта can flag игнорируется; при отказе 7F8 отсутствуют изменения и dispatch.
Даже разрешённый callback не переводит environment phase 3 в состояние выше 5.
Полный Time lifecycle после callback здесь не исполняется и не допускается.

Итого 48 + 9 + 16 + 24 = 97 bounded native сценариев прошли.
Артефакт: `code-clues/quest-environment-update-11316/83d93a209ef0fbbd409f6977e06cf1797bb911f6e0510b1e35f43f0cdcb1c644/manifest.json`.
Tool: `replay-quest-environment-update-11316.py`;
тест: `test_vampir_quest_environment_update_11316.py`;
check: `native-quest-environment-update-11316`.

## Fixtures и оставшееся неизвестное

Provider 145490870, class/fallback/context resolver, registry/model lookup,
virtual+7B8/+7F8/+800, дополнительный context1442BA3A0, строковое присваивание,
пустые diagnostics и notification sinks — явные fixtures. Synthetic context
используется совместно для getter и callback; его фактический live тип не установлен.
Assignment fixture проверяет receiver/source и заменяет пустой descriptor;
настоящие allocation/free/string ownership не доказаны. Callback submission/move
и scheduler dispatch остаются fixtures, но тело callback и tail уже исполняются.
Никакой fixture не подменяет их возврат или native byte+731 write.
`network_used=false`, `action_admitted=false`.

Далее — producer environment pending+44, реальные guard implementations и путь,
который завершает переход и снова разрешает Time. Для live offer также нужны
активные значения, selected task и actor position. Онлайн-сессия не перезапускалась;
игровых команд в этом исследовании не отправлялось.
