# Игровой AutoSignIn: привязка callback и ветви результата

19 октября 2026. Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Продолжение [SDK result dispatch](HEADLESS-SDK-RESULT-DISPATCH.md), но прямое
соединение этих двух callbacks пока **не доказано**.

## Источники и воспроизведение

[replay-game-auto-sign-in-result.py](../../../replay-game-auto-sign-in-result.py) →
`F:/PhoneExit Resources/Vampir/code-clues/game-auto-sign-in-result-replay.json`.
SHA256: `e24dd515d0f3defbef00768d00c2774186444cf037150832325a00feffb1b103`.
Report содержит decoded fragments с bytes/file offsets/SHA, отдельные bounded
leaf bodies, diagnostic literal с происхождением и три verified LEA xrefs.
Отсутствие unwind у jump leaf учтено отдельно.

Запуск из корня проекта:
`python -X utf8 phone-exit/bots/resource-tools/vampir/replay-game-auto-sign-in-result.py`.
Capstone 5.0.6/Unicorn 2.1.4; budget 4096 native instructions на callback.

## Статическая цепочка и различие объектов SDK

Точная diagnostic строка
`FNnNetmarbleSDKAuth::AutoSignIn::<lambda_1>::()::<lambda_1>::operator ()()`
лежит по VA 0x1498b7990, file offset 0x98b6590. LEA 0x1455f7be1
связывает её с logging-only callback root 0x1455f7bd0.

Реальный caller этой вложенной logging-функции — root 0x1455fbb80:
на 0x1455fbc8c он помещает её pointer в function descriptor перед virtual call.
Leaf 0x1456007b0 содержит JMP в root 0x1455fbb80.
Root 0x145600460 создаёт descriptor с этим leaf на 0x1456005b2/0x1456005f3;
в descriptor сохранены owner pointer и weak control block. Затем calls
0x1456005cd/0x14560060e передают его в wrapper 0x1444fea30.

Перед этим вызывается getter 0x144521550, который возвращает owner+0x170.
Wrapper читает impl pointer и вызывает 0x1444feac0. Это **отдельная цепочка**
от GetAuth 0x1445209e0 → owner+0x150 → SignIn wrapper 0x1444fb730.
Имя AutoSignIn здесь подтверждено diagnostic и callers, но оно само по себе
не связывает game callback с ранее исполненным FAuthImpl::ExecSignIn.
Точные diagnostic literals подтверждают: getter — FServiceImpl::GetChannelManager,
а target 0x1444feac0 — FChannelManagerImpl::SignInSilently.
Оба LEA/literals и полный fragment target сохранены в route_diagnostics.
Выбор провайдера внутри SignInSilently и связь с auth SignIn пока открыты.

## Исполненные gates игрового callback

| Проверка | Подтверждённое действие |
| --- | --- |
| Нет control block, strong count 0 или null owner | Возврат без внешних действий |
| Живой owner | Atomic pin, log capture с selector 9, затем ветвление по response |
| response+4 == 0 | manager action pointer 0x143b8bf10, child+0x58 call 0x14560f740, game-instance lookup |
| response+0xc равен 40040011 или 30050012 | При status 429/502 другой manager action; при 200 только log |
| response+4 == 0x1ca86f7 | status 1100/1202/1210 → call 0x145614370; остальные → error-text/action calls |
| Прочая ненулевая response+4 | call 0x145614370 |

Getter тела исполняются реально: 0x14452b040 читает +4 (zero predicate),
0x141a273d0 читает +0xc, 0x140ba0b90 читает +4,
0x1418089f0 читает qword +0x28. Их bytes сохранены в report.
Числовым значениям и manager action pointers не присвоены недоказанные имена.

15 fixtures покрывают перечисленные ветви. При живом owner strong count
после возврата совпадает с исходным 4; expired case остаётся 0.
Race contention и финальные destructor branches не покрыты.

## Границы и следующий шаг

Native callback и leaf getters исполняются. Logging, manager actions,
error-text/actions и fallback — captures. В success case game-instance getter
0x1454894b0 возвращает null fixture: дальнейший virtual callback не исполняется.
В report статически сохранён fallback root 0x145614370, но его body не исполнен.
Реальные scheduler, SDK service acquisition и wrapper startup не исполнялись.

[Три regression tests](../../../../../test_vampir_headless_game_auto_sign_in.py)
проверяют SHA-bound воспроизводимость, verified xrefs, различие +0x150/+0x170,
owner lifetime gates, raw result branches и неизменность strong count.
Общий runtime не менялся; живой вход, packet Login и Android parity не заявлены.
Игра не запускалась; память процесса, профили, credentials и HTTP не использованы.

Следующий шаг: исследовать provider selection внутри ChannelManager::SignInSilently
0x1444feac0 и continuation через success manager action/virtual callback.
Далее связать реальную credential/session цепочку с игровым Login.
