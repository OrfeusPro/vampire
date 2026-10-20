# ConnectToServer: адрес, игровой порт и дополнительная пара

19 октября 2026. Продолжение [BeginGame target](HEADLESS-BEGIN-GAME-SERVER-TARGET.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-game-connect-target.py](../../../replay-game-connect-target.py) →
`F:/PhoneExit Resources/Vampir/code-clues/game-connect-target-replay.json`.
SHA256: `d39342069085693089327cd86f125fee0c12c5fcb2a7826fc52a60286cd064bf`.
Report сохраняет source/tool/upstream SHA, fragments/leaf bytes/file offsets,
полный ConnectToServer и endpoint constructor, diagnostic literals.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-game-connect-target.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 8192 instructions на connect caller.

## Подтверждённый consumer

Root 0x144aabcc0 связан точной строкой NnPeerImpl::ConnectToServer.
Строка `Connect to GameServer[%s:%d]` и передача в endpoint constructor
подтверждают назначение выбранных host/port. Теперь fields из предыдущего этапа
имеют такую связь:

| Условие | Host FString | Port word |
| --- | --- | --- |
| Длина дополнительной строки +0x298 <= 1 | impl+0x278 | impl+0x288 |
| Длина дополнительной строки +0x298 > 1 | impl+0x290 | impl+0x2a0 |

Длина FString включает terminator. Непустой override выбирает всю пару,
включая свой порт, даже если основной адрес пуст. Активный источник/назначение
override и режим, при котором он появляется, пока неизвестны.
Field impl+0x28a из BeginGame здесь не читается; его сетевую роль не додумывать.

При global byte 0x14b520cb4 != 0 caller пропускает connect path.
Имя и инициализация flag не доказаны; его значение в replay — fixture.

## Проверки адреса и порта в native caller

После копирования FString реальный код проверяет count > 1 и port word
через `test r12w,r12w; js`. Поэтому в этом body пустой host и ports
32768..65535 не доходят до endpoint construction, а port 0 проходит.
Это **наблюдаемое native поведение**, не автоматически выбранная политика
будущего portable runtime. Никакой проверки корректности hostname/DNS/IP
этим не подтверждено.

Преобразование UTF-16 → narrow string заменено bounded ASCII fixtures.
Реальное преобразование произвольного Unicode не восстановлено. Зато native
ветви std::string inline/heap storage исполняются и передают одинаковый host.
Allocation/copy/free и логирование ограничены fixtures.

## Endpoint и нижний connect

Call 0x144aac01e → constructor 0x1445e2a50 получает narrow string и port.
Сам constructor реально исполняется: записывает source vtable, копирует
строку через fixture 0x1445d8e60, пишет word endpoint+0x28 и dword endpoint+0x2c=0.
Строковый copy fixture сохраняет descriptor, не доказывает полный ownership.

Затем call 0x144aac02c → 0x1445ea1b0 получает impl pointer, endpoint и R8D=0.
Нижний connect — **capture**, его bool return задаётся fixture. Не проверены
DNS, socket creation, TCP/UDP роль, async completion, TLS, retries или связь с Login.
В false scenario caller проходит диагностическую ветвь Failed to connect game server.
Флаг busy из BeginGame в этом harness остаётся 1; реальный rollback нижнего
слоя и последствия последующих callbacks этим не установлены.

## Тринадцать сценариев

Primary host, long primary, override, short override, disabled flag, empty
primary, empty primary+override, false lower-connect, ports 0/32767/32768/65535,
override high port. Во всех сценариях сначала реально исполняются BeginGame
selection/lookup/setters из предыдущего milestone, затем ConnectToServer
на том же fixture object. Реального lifecycle вызова между ними не исполняем.
Это связанная проверка данных, не готовое соединение с сервером.

[Три regression tests](../../../../../test_vampir_headless_game_connect_target.py)
проверяют source consumers/calls, selected pair, inline/heap paths,
точные constructor writes, guards и false result. Восемь смежных tests
прошли, включая прежний локальный loopback send-drain test; к серверу игры
ни один тест не подключается. Runtime не менялся; полный suite 316 из
предыдущего runtime milestone не повторялся.

Все endpoints synthetic и используют .invalid; внешних DNS/HTTP/socket
вызовов нового replay нет. Игра не запускалась, память процесса, Saved/profile
и реальные credentials не использованы.

Далее нижний 0x1445ea1b0 → socket creation/connect/readiness, consumer второго
word+0x28a и callback, запускающий packet Login. Не повторять уже закрытые
host/port copy исследования без изменения источника.
