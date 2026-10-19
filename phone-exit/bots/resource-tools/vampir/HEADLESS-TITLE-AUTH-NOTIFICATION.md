# Manager-child routing → OnSuccessNetmarbleSDKAuth

19 октября 2026. Продолжение [success broadcast](HEADLESS-GAME-SUCCESS-BROADCAST.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-title-auth-notification.py](replay-title-auth-notification.py) →
`F:/PhoneExit Resources/Vampir/code-clues/title-auth-notification-replay.json`.
SHA256: `7a06a42906f1d41a3c6b012404436d8aec8694ed2859bfd43cbec80c1060a046`.
Report хранит upstream/source/tool SHA, полные fragments, file offsets/bytes,
bounded action/getter leaves, title vtable и diagnostic literals.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-title-auth-notification.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 4096 instructions на native функцию.

## Найденный переход

После первой рассылки slot+0x30 игровой callback вызывает manager-child
0x14560f740. При соответствующих условиях он вызывает 0x14560eef0.
У последнего одна из ветвей передаёт action 0x141423088 в broadcast
0x1445f5330 (call site 0x14560f16f). Action содержит JMP virtual slot+0x08.

Source-bound title interface vtable 0x149c4cda0 (object+0xa18, два ранее
проверенных constructor stores) содержит в slot+0x08 **0x14641d560** —
OnSuccessNetmarbleSDKAuth из [entry evidence](ENTRY-FLOW.md).
Это точный target, отличный от slot+0x30 → 0x14641dbc0.

Native manager-child/router/predicate/broadcast и virtual action выполняются
в полной silent/game callback цепочке. На входе 0x14641d560 стоит capture:
полное UI-тело этого обработчика ещё не исполняется. В report оно сохранено
статически; это не доказательство game Login или готовой сессии.

## Условия и отдельные значения

Predicate 0x14452aa80 реально проверяет module+0x88 == 100 и нулевой
возврат idp-count helper 0x1444725a0. Счётчик helper — fixture.
Если predicate true, manager-child вызывает 0x14560eef0.

Router 0x14560eef0 использует **другой** getter 0x144521af0,
точный diagnostic UNMServiceSettings::GetChannelTypeForNetmarbleId.
Его body сохранено статически, возврат в replay — явный fixture.
Внутри видны SDKZone/settings map+0x698; это значение нельзя автоматически
приравнивать к module+0x88 или credential channelCode.
Реальная согласованность/активное происхождение комбинации fixture значений
не заявляется.

При NID channel != 100 проверенная ветвь выполняет calls 0x145603e20,
0x145606660 и FString assignment capture, затем broadcast slot+0x08.
Завершающие действия 0x145644b00 и поиск записи списка тоже captures.
Поиск возвращает -1: ветка удаления совпавшей записи не исполняется.
При NID channel == 100 достигается отдельный continuation 0x14560a160.

Если начальный predicate false, manager-child уходит в 0x14560f3c0.
Native getter 0x14452b050 читает module+0x220. При byte == 1 broadcast
использует action 0x1445c018c → slot+0x18 (title target 0x146418830 capture).
Иначе fixture getter 0x14452adb0 выбирает continuation 0x145606ca0 либо
0x145619550. Их смысл и тела не интерпретируются по одним адресам.

## Семь сценариев

| Fixture | Результат проверенного маршрута |
| --- | --- |
| Predicate true, NID channel 33 | OnSuccessNetmarbleSDKAuth entry capture |
| Predicate true, NID channel 100 | Continuation 0x14560a160 |
| Module channel 33, policy+0x220=1 | Title slot+0x18 entry capture |
| Module channel 33, второй policy getter true | Continuation 0x145606ca0 |
| Module channel 33, оба policy false | Continuation 0x145619550 |
| Manager+0x38 null | Ни одного из этих уведомлений |
| Module channel 100, idp count 1, policy+0x220=1 | Title slot+0x18 entry capture |

Environment+0x1d5 остаётся нулевым fixture, его дополнительная ветвь не покрыта.
Остальные CDO/settings/context/политики и idp count — synthetic inputs.
Не было чтения активного профиля, памяти процесса, credentials, запуска игры
или HTTP. Не утверждается, что текущая реальная почта проходит выбранный маршрут.

[Три regression tests](../../test_vampir_headless_title_auth_notification.py)
проверяют source slot/calls, условность success notification, альтернативные
continuations и сохранение исходной response pair/owner count. Шесть смежных
tests прошли. Runtime не менялся; полный suite 316 из предыдущего runtime
milestone повторно не запускался.

Далее исследовать входные данные и значимые переходы OnSuccessNetmarbleSDKAuth,
сопоставить с существующей entry/packet Login цепочкой. Реальный первый вход,
полная response/session validation и активный выбор NID channel остаются открыты.
