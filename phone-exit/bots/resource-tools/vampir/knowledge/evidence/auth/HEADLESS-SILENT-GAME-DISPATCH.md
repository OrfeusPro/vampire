# Auth silent result → игровой AutoSignIn callback

19 октября 2026. Продолжение [ChannelManager → Auth silent](HEADLESS-CHANNEL-SILENT-HANDOFF.md)
и [игрового callback](HEADLESS-GAME-AUTO-SIGN-IN.md).
Источник — код собранного Windows клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-silent-game-dispatch.py](../../../replay-silent-game-dispatch.py) создаёт
`F:/PhoneExit Resources/Vampir/code-clues/silent-game-dispatch-replay.json`.
SHA256: `b1f543fc3ac6f4af3ff5b1c6eabdb225c8832c2666fff16eea824308eaf8bbeb`.
Report содержит tool/source/upstream SHA, native fragments с bytes/file offsets,
полный response root, request callback instructions, bounded JMP leaf и literals.

Команда из корня проекта:
`python -X utf8 phone-exit/bots/resource-tools/vampir/replay-silent-game-dispatch.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 4096 instructions на native функцию.

## Статический маршрут HTTP-ответа

Auth::SignInSilently задаёт callback pointer на 0x1444fe503 → leaf 0x1444d8610;
request передаётся wrapper 0x14451c3f0 на 0x1444fe530. Leaf содержит JMP
в response root 0x1444cdb30. Его bytes и target проверены по EXE.

Response root содержит собственные predicates/JSON/status/errorCode/player gates.
После успешной ветви call 0x1444ce7f2 передаёт результат в 0x1444e02e0.
Точный diagnostic этого target — FAuthImpl::ExecSignInSilently.
Полный response root экспортирован статически: его validation, присваивания
session полей и error object construction в этом replay **не исполняются**.
Нельзя переносить проверки обычного SignIn на silent response по сходству кода.

## Исполненная цепочка

| Этап | Native source | Проверка |
| --- | --- | --- |
| Silent dispatcher | 0x1444e02e0 | Читает callback impl+0xa8, обнуляет count impl+0xb0 |
| Delegate copy/cleanup | 0x1414203f0 / 0x1444bee50 | Реальные wrappers, storage/allocation/destructors — fixtures |
| Queue descriptor | call 0x1444e044f → 0x141404350 | selector 1, thunk 0x1444d8410, closure с исходной response pair |
| Silent thunk | 0x1444d8410 | Вызов virtual slot+0x60 при наличии привязки |
| Native clone/invoke bridge | 0x144237840 / 0x14423aaf0 | Реальный virtual dispatch через source-bound vtable |
| Игровой function target | leaf 0x1456007b0 → 0x1455fbb80 | Получает исходную пару response object/control block |
| Игровой callback | 0x1455fbb80 | Weak owner pin и ветвление по raw response fields |

Игровой leaf pointer происходит из ранее проверенного descriptor в
0x145600460; ChannelManager handoff передаёт callback в Auth silent.
Replay конструирует конечную привязку с этим target и fixture weak-owner storage.
Он не исполняет полный startup/acquisition/copy lifecycle всей цепочки.

## Двенадцать интеграционных сценариев

Шесть профилей × два варианта storage/refcount: success, no-binding, expired,
no-owner, ordinary-error, special-429. Один вариант — inline function storage
и null response control block, второй — heap storage и refcounted response.

Во всех случаях исходный delegate count очищается до fixture task drain,
closure сохраняет исходную response pair. При control block count 4 → 5;
после thunk остаётся 5, поскольку финальный closure destructor не исполняется.
Owner count после callback совпадает с исходным.

- Без callback очередь создаётся, но игровой leaf не вызывается.
- При expired/null owner игровой callback вызывается и возвращается без log/actions.
- Success fixture достигает manager action 0x143b8bf10 и child action;
  game-instance getter возвращает null fixture, дальнейший virtual callback не исполняется.
- Ordinary error достигает capture 0x145614370.
- Special code 40040011/status 429 достигает manager action pointer 0x144569170.
  Семантика этих action pointers не присваивается по адресу.

Native bridge возвращает AL=1 также после error и expired-owner сценариев.
Это факт вызова обёртки, **не доказательство входа или готовой игровой сессии**.

## Границы и проверки

Native dispatcher, clone/invoke bridge, silent thunk, игровой JMP leaf и игровой
callback исполняются в одной цепочке. Scheduler — move/capture fixture;
очередь исполняется вручную после возврата dispatcher. Thread affinity selector 1,
гонки, final destruction, active service state и настоящая сеть не проверены.
TFunction storage clone/get-context, allocation/destructors, игровые внешние
действия — fixtures/captures. Response body в сценариях — synthetic raw object.
Не было запуска игры, чтения памяти процесса, Saved/профиля, credentials или HTTP.

[Три regression tests](../../../../../test_vampir_headless_silent_game_dispatch.py)
проверяют source-bound маршрут, deferred callback, сохранение pair/refcount,
owner lifetime и игровые ветви. Девять смежных tests прошли. Runtime не менялся;
последний полный прогон 316 тестов из runtime milestone повторно не запускался.

Далее — success manager action 0x143b8bf10 и continuation при настоящем
ненулевом game instance, затем связь с игровым Login. Silent response validation
и обычный первый вход с credential остаются отдельными открытыми задачами.
