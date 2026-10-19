# Socket mode job: select, state flags и completion codes

19 октября 2026. Продолжение [Winsock mapping](HEADLESS-WINSOCK-ERROR-MAPPING.md)
и [socket setup](HEADLESS-RESOLVED-SOCKET-SETUP.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-socket-readiness-job.py](replay-socket-readiness-job.py) →
`F:/PhoneExit Resources/Vampir/code-clues/socket-readiness-job-replay.json`.
SHA256: `7d92192e677db505b97864e51fd3f1f2d62b2118909db45ca699ba8ea84ff694`.
Report сохраняет source/tool/upstream SHA, code fragments/bytes/file offsets,
job/engine vtables, completion/getter/thunk spans, PE imports и local DLL exports.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-socket-readiness-job.py`.
Capstone 5.0.6/Unicorn 2.1.4; mode/completion budget 4096 instructions,
worker budget 4096 на одну исследуемую итерацию.

## Actual mode helper и job

Helper 0x1445eab70 вызывается с socket object и EDX=0, как ранее показано
в recipient. Он отклоняет handle field+0x38 == 0. Иначе вызывает engine
virtual+0x30 с selector 0 и raw value 1. Source engine vtable связывает
этот slot с **0x1445f0c60**, его body теперь реально исполняется.

Engine selector 0 выбирает raw command **0x8004667e** и вызывает ioctlsocket.
При результате != -1 записывает socket byte+0x3c как (raw value == 0).
То есть входное value 1 в проверенных fixtures даёт mode byte 0.
Syscall заменён fixture; имя ioctlsocket проверено через PE ordinal и локальный
DLL export, а не предположено по command. Полный контракт ОС не проверен.

После успеха helper записывает EDX в socket+0x48, создаёт job размера 0x28,
устанавливает vtable **0x1495042d0**, owner socket в job+0x20 и job pointer
в socket+0x40. Scheduler enqueue — capture. Если enqueue false, helper false,
но уже изменённый byte+0x3c не откатывается в этом body.

Job slots source-bound: run+0x10 = **0x1445e8080**,
completion+0x18 = **0x1445e7d80**. Harness читает targets из native созданного job,
вручную запускает run и затем completion для каждого захваченного кода.
Реальный scheduler/threads/startup/lifetime не исполняется.

## Одна native итерация select

После enqueue state+0x50, operation mode+0x48, interval+0x4c и interest+0x5c
явно задаются fixtures; это не доказанные active значения клиента.
При flag state&8 job сразу возвращается. Иначе вызывает prepare helper из
**другого global 0x14b4f39c0**, slot+0x50. Он capture; не смешивать его
с socket engine global 0x14b4f39d0. Harness выдаёт обоим globals test engine,
не утверждая совпадение реальных объектов.

Native код формирует read/write/exception fd_sets и timeval [0, interval*1000].
Для fixture handle42/interval2 захвачены nfds43 и timeval [0,2000].
Write set заполняется, когда state==2 либо interest+0x5c ненулевой.
Select import, ioctlsocket и __WSAFDIsSet проверены по local WS2_32 exports.
FDIsSet JMP thunk bytes отдельно связаны с IAT. Все три системных вызова fixtures.

Ветка operation mode 0/state2: при write-ready вызывается engine option
slot+0x60 с selector 1 и размером результата 4. Его target/системная семантика
ещё не исполнены: это raw output capture, не доказанный SO_ERROR translation.
Успех getter и нулевое output значение дают **state |= 4**, clear interest,
completion code 1. В fixture state2 → state6.

Ошибка option getter, ненулевое option значение либо exception-ready дают
completion code 2. No-ready не выдаёт code; select=-1 завершает run без code
в исследованной ветви. Эти факты не определяют всю recovery policy клиента.

При operation mode 0/state6 read-ready даёт code 4, write-ready — code 3
и очищает interest. При обоих событиях сохраняется порядок [4,3].
При operation mode 1 read-ready даёт code 0. Имена режимов/событий не выводятся
из чисел без отдельного исследования recipients.

## Native completion routing

Completion сначала проверяет owner state&8; при установленном stop flag
рассылка пропускается. В проверенных сценариях до dispatch доходят:

| Completion code | Action pointer для 0x1445de8b0 |
| --- | --- |
| 0 | 0x141423088 |
| 1 | 0x14370ae90 |
| 2 | 0x1445c018c |
| 3 | 0x14156c744 |
| 4 | 0x144569170 |

Completion leaf реально исполняется, но downstream dispatch — capture.
Одинаковый action pointer в разных интерфейсах не доказывает одинаковый
смысл события. Получатели socket callbacks и переход к Login ещё не исполнены.

## Четырнадцать сценариев и проверенные границы

Connect-ready, no-ready, option-fail/error, exception, select-error, stopped,
read-event, write-event, read-write, operation-one, ioctl-fail, enqueue-fail,
zero-handle. Проверены native scheduling/stores, ioctl body, select branch,
state writes и completion code routing.

Worker **останавливается перед второй итерацией** на 0x1445e82d2, либо
возвращается естественно по error/stop ветви. Это одна bounded iteration,
не доказательство завершения фонового worker. Capture completion выполняется
вручную после этого; race/order относительно следующего select неизвестны.

[Три regression tests](../../test_vampir_headless_socket_readiness_job.py)
проверяют code/vtable/import bindings, raw select args, state6 только после
write/option gates, альтернативные events, exact completion routes,
mode syscall/queue failures. Шесть смежных tests прошли.
Runtime не менялся; полный suite 316 из runtime milestone не повторялся.

Winsock/FD readiness, scheduler/allocation/base job ctor, prepare/option getter
и downstream notification — fixtures/captures. Нет реального времени ожидания,
сетевой сессии, thread races, удаления job или Android parity.
Игра не запускалась; process memory, Saved/profile, credentials и сеть не использованы.

Далее engine option selector 1 → настоящий syscall/translation; recipients
completion code 1/state6 → transport notification → packet Login. Client flags
и положительный select fixture не заменяют live connection/session evidence.
