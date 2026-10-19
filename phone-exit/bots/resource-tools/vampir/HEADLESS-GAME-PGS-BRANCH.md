# Game-instance ветвь success callback: Google PGS

19 октября 2026. Продолжение [silent game dispatch](HEADLESS-SILENT-GAME-DISPATCH.md)
и [success broadcast](HEADLESS-GAME-SUCCESS-BROADCAST.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-game-pgs-branch.py](replay-game-pgs-branch.py) →
`F:/PhoneExit Resources/Vampir/code-clues/game-pgs-branch-replay.json`.
SHA256: `34c0a65f7b2b3de0027f098be8e290639036eda5131d3a5327b6b9b157299157`.
Report хранит source/tool/upstream SHA, fragments с bytes/file offsets,
provider/storage vtables и diagnostic literals с происхождением.
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-game-pgs-branch.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 4096 instructions на native функцию.

## Точное назначение ветви

После успешного raw SDK result игровой callback вызывает game-instance getter
0x1454894b0 и getter 0x1450b11b0. Точный diagnostic второго:
Netmarble::Google::FPGSIDProvider::GetOrCreate. Сохранены также key
PGSIDProvider и constructor diagnostic FPGSIDProvider.

Getter constructor stores устанавливают vtable 0x1496de728; её slot+0x10
равен 0x1450c35e0. Точный diagnostic target — FPGSIDProvider::SignIn.
Таким образом, virtual call 0x1455fbca7 относится к Google PGS,
а не к доказанному game packet Login.

GetOrCreate и FNMGoogleModule::Initialize 0x1450b7c50 экспортированы статически.
Их body не исполняется в replay, реальные наличие сервиса/инициализация неизвестны.
Нельзя из отсутствия Android-реализации в этом EXE выводить поведение Android.

## Исполненная Windows provider ветвь

Реальные native game callback и provider SignIn выполняются вместе через
source-bound provider vtable. В Windows body после logging gate нет ветви
реального PGS network sign-in: он готовит отдельный результат с literal
`platform is not supported` и вызывает constructor 0x144510320:
EDX=400, R8D=30020000, R9D=1. Constructor — capture, эти raw arguments
доказаны исполнением caller; отображение результата в поля в harness — fixture.

Затем callback передаётся result helper 0x1445342d0, который также capture.
Function descriptor хранит logging target 0x1455f7bd0 в inline storage+8.
Это source-bound вложенный logging callback из AutoSignIn, проверенный ранее.
Storage vtable 0x14898d548 связывает clone 0x14141c170/release 0x14141c190;
сами операции заменены bounded copy/release fixtures. Helper callback не drain-ится.

Исходный SDK response и PGS result — разные fixture objects. Состояние первого
не перезаписывается ошибкой PGS. Это не подтверждение серверной сессии:
исходный response в сценариях synthetic, без origin/token/expiry validation.

## Четыре сценария и границы

- Нет game instance: getter PGS и provider SignIn не вызываются.
- Нет provider: game instance есть, virtual call пропускается.
- Provider есть: исполняется реальный Windows body с unsupported result args.
- Исходный SDK result error: PGS ветка не достигается.

Реальное acquisition game instance/weak handle/GetOrCreate — fixtures.
Provider SignIn, native game callback и внешний silent dispatch исполняются.
Allocation, FString copy, result constructor/helper и TFunction lifecycle —
fixtures/captures. Не проверены actual callback delivery/destruction, threads,
активный профиль, network readiness и Android parity. Предыдущие broadcast
и manager-child actions остаются captures этого replay.

[Три regression tests](../../test_vampir_headless_game_pgs_branch.py) проверяют
source diagnostics/vtable, optional/error gates, raw constructor args,
сохранение original result и logging callback target. Шесть смежных tests прошли.
Runtime не менялся; последний полный suite 316 из runtime milestone не повторялся.
Игра не запускалась, память процесса, Saved/profile, credentials и HTTP не использованы.

## Следующий участок основного входа

Эта PGS-ветвь исключена из кандидатов на прямой game Login. Следующий приоритет:
manager-child action 0x14560f740 и реальные уведомления title interface,
включая точный slot для OnSuccessNetmarbleSDKAuth. Затем packet Login.
Обычный первый вход с credential и полная SDK response/session validation
остаются открытыми; silent и PGS callbacks не заменяют эти требования.
