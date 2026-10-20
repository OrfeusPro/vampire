# Game success: рассылка подписчикам и title interface slot+0x30

19 октября 2026. Продолжение [silent game dispatch](HEADLESS-SILENT-GAME-DISPATCH.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источник и воспроизведение

[replay-game-success-broadcast.py](../../../replay-game-success-broadcast.py) →
`F:/PhoneExit Resources/Vampir/code-clues/game-success-broadcast-replay.json`.
SHA256: `b58ee84778afd26c821d7ae513f6ff8681a8272a1560a2f821699e1a020b0e16`.
Report хранит source/tool/upstream SHA, native fragments, file offsets/bytes,
bounded action leaf, constructor LEA/store и title vtable bytes с SHA.
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-game-success-broadcast.py`.
Capstone 5.0.6/Unicorn 2.1.4; budget 4096 instructions на функцию.

## Уточнение назначения первого success action

В игровом callback 0x1455fbb80 pointer 0x143b8bf10 передаётся в 0x1445f5330.
Последний копирует список subscribers, проверяет object/control block/strong count,
затем вызывает переданный action для каждого живого подписчика.

Action leaf 0x143b8bf10 содержит загрузку vtable и JMP virtual slot+0x30.
Это общий механизм рассылки; адрес leaf сам по себе не является game Login.
При встрече недействительных записей native caller вызывает 0x1445ce290,
который replay только захватывает: фактическое удаление списка не заявляется.

## Source-bound title interface

Constructor roots 0x14640a5f0 и 0x14640f800 устанавливают title interface vtable
0x149c4cda0 по object+0xa18. Проверены два LEA и следующие stores:
0x14640a700 `[rbp+0xa18]`, 0x14640f885 `[rcx+0xa18]`.
Vtable slot+0x30 действительно равен **0x14641dbc0**.
Другой slot этой таблицы содержит OnSuccessNetmarbleSDKAuth 0x14641d560;
он не подменяет target slot+0x30.

Handler 0x14641dbc0 читает pointer interface+0x228. При null возвращается.
При ненулевом pointer вызывает child virtual+0x598 с EDX=2/R8B=1,
затем обнуляет interface+0x228. Дочерний virtual target остаётся capture,
его полная семантика и точный ресурс окна ещё не доказаны.
UI-клики и реальные окна этим исследованием не создаются.

Реально исполняются silent dispatcher, native delegate bridge, game callback,
broadcast loop, action JMP и title slot handler. Полный UObject/registration
не исполняется: fixture listener использует исходную vtable с минимальными
полями. Текущий настоящий список подписчиков неизвестен.

## Двенадцать сценариев

Шесть списков — empty, live, expired, null, mixed, two-live — каждый с
пустым/непустым child pointer. В mixed живые записи 1 и 3 получают вызов,
expired/null пропускаются, prune вызывается один раз. Живые подписчики с
child pointer получают точные virtual args и сохраняют null после вызова.
Поля пропущенных подписчиков не изменяются.

Strong counts в fixtures остаются прежними; это не полная проверка ownership:
array allocation/copy/destruction заменены bounded primitives/captures,
копирование raw записей не выдаётся за полную native weak-reference копию.
Prune, allocation/release, scheduler и task drain сохраняют прежние fixture
границы. Контенция atomic pin, concurrent mutation и final destruction не проверены.

Три [regression tests](../../../../../test_vampir_headless_game_success_broadcast.py)
проверяют source table/constructor связи, порядок живых вызовов, count/prune,
параметры child virtual и очистку pointer. Runtime не менялся; полный suite
316 из последнего runtime milestone повторно не запускался.

## Что остаётся до Login

Проверенный title slot handler завершает обработку дочернего объекта;
прямого packet Login в этой исполненной ветви нет. Следующие отдельные действия
game callback — child action 0x14560f740 и game-instance ветвь с getter
0x1450b11b0 → virtual slot+0x10 — пока остаются открытыми.
Не считать UI/interface cleanup доказательством сетевой готовности.
Игра не запускалась; память процесса, profile/credentials и HTTP не использованы.
