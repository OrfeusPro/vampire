# Resolver result → peer recipient → socket creation

19 октября 2026. Продолжение [resolver results](HEADLESS-RESOLVER-JOB-RESULTS.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-resolved-socket-setup.py](replay-resolved-socket-setup.py) →
`F:/PhoneExit Resources/Vampir/code-clues/resolved-socket-setup-replay.json`.
SHA256: `8b74a3dc8d2444e8a997d25cfb4504c55759a5b41ff656c1a5d845080835a4dd`.
Report содержит source/tool/upstream SHA, fragments/bytes/file offsets,
virtual action leaf, peer/socket vtables и PE import/export provenance.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-resolved-socket-setup.py`.
Capstone 5.0.6/Unicorn 2.1.4, inherited resolver job budget 8192 instructions.

## Получатель callback установлен по source

Resolver completion вызывает dispatch 0x1445de9f0 с action 0x141423088.
Dispatch, action JMP virtual+0x08 и recipient теперь исполняются native.
NnPeerImpl constructor root 0x144aab540 устанавливает vtable 0x14961b8a8
в peer+0x38 (store 0x144aab5b0). Slot+0x08 равен **0x1445e8400**.
Его начало само вычитает 0x38 из this, что согласует subobject с peer.

Регистрация object/control block в replay использует этот peer+0x38.
Полное acquisition/base startup не исполнено: pair/ref block и listener snapshots
явные fixtures. Native listener loop/pin/call исполняются с живой записью;
snapshot copy/destructor и eventual prune не доказывают полный lifetime/race contract.

Recipient дополнительно уведомляет peer listeners (пустой fixture список),
затем переносит result addresses в кольцо peer+0x98. Capacity=8 задана заранее,
рост очереди не покрыт. String copies и pop головы — bounded fixtures;
native iteration/insert и выбор первого кандидата исполняются.
При смешанном resolver списке первым остаётся ранее переставленный IPv6.
Второй кандидат остаётся в очереди; retry на него в этом replay не исполняется.

## Source-bound socket object и системный вызов

Base peer constructor root 0x1445e2af0 устанавливает vtable 0x149503ac0
в peer+0x110 (store 0x1445e2c92). Slot+0x08 → **0x1445e5cb0**.
Recipient вызывает этот target через interface+0xd8, то есть peer+0x110.
Этот native creator body исполняется.

Он вызывает IAT 0x1489459d8. PE import — WS2_32.dll ordinal 23.
Имя проверено по export table локальной `C:/Windows/System32/WS2_32.dll`:
`socket`, SHA256 `b123b00c46c415d7baeaada58c29c3e6920895db836ee4c0cfee49d738af60ad`.
DLL только прочитана, ни один её export не исполнялся.

Winsock socket в эмуляторе заменён fixture. Подтверждённые native аргументы:

| Выбранный host | Family | Type | Protocol |
| --- | --- | --- | --- |
| 192.0.2.1 | 2 | 1 | 0 |
| 2001:db8::1 | 23 | 1 | 0 |

Порт приходит из peer+0x90. В endpoint для следующего вызова raw family tag
равен 0 для IPv4 и 1 для IPv6, согласно native лексическому выбору.
Это не полная IP validation и не доказательство IPv6-сессии.

При socket return -1 creator возвращает false без записи fixture handle.
При handle=42 native код пишет dword socket object+0x38 (peer+0x148) и
вызывает два engine options method capture с selector 9 и 6.
Назначение этих selector numbers пока не интерпретируется.

## Следующие вызовы и ветви отказа

После успешного создания recipient вызывает 0x1445eab70 с EDX=0.
Это capture с source body в report. Затем при peer mode+0xc0==0
virtual slot+0x10 → 0x1445e5c60 получает endpoint host/port/family tag.
Этот endpoint connect wrapper — capture, underlying 0x1445ecbb0 также
сохранён статически. Реальные connect/errno/pending/readiness не исполнялись.

Creator false и mode helper false ведут к report helper 0x1445dc650 capture.
Endpoint-connect false ведёт к continuation 0x1445eeb30 capture.
Ошибки DNS не достигают socket creator.
Положительный fixture bool не означает готовый транспорт или game Login.

## Семь сценариев и проверки

IPv4, IPv6, mixed, socket failure, mode failure, connect failure, DNS failure.
Каждый сначала проходит предыдущую fixture цепочку BeginGame → resolver job
run/completion. Затем исполняются real listener dispatch/recipient/creator.
Во всех сетевых границах стоят captures; реальных сокетов и DNS нет.

[Три regression tests](../../test_vampir_headless_resolved_socket_setup.py)
проверяют source tables/constructor stores/action/import, family/type/protocol,
переданный endpoint, оставшиеся candidates и все указанные отказы.
Шесть смежных tests прошли. Runtime не менялся; полный suite 316 из предыдущего
runtime milestone повторно не запускался.

Socket mode/options/connect, queue/string/snapshot/lifetime primitives,
scheduler и ошибки — fixtures/captures. Настоящие threads/ownership/retry,
active endpoints, Android parity и server-compatible session не проверены.
Игра не запускалась; process memory, Saved/profile и credentials не использованы.

Далее 0x1445eab70 и 0x1445e5c60 → 0x1445ecbb0: syscall connect,
pending/error обработка, readiness/job completion и запуск packet Login.
Не повторять закрытые resolver/table/creator связи без смены источника.
