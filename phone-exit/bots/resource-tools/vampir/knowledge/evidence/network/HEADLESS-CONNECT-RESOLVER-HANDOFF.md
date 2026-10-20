# Нижний connect: параметры peer и передача resolver-задания

19 октября 2026. Продолжение [ConnectToServer target](HEADLESS-GAME-CONNECT-TARGET.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-connect-resolver-handoff.py](../../../replay-connect-resolver-handoff.py) →
`F:/PhoneExit Resources/Vampir/code-clues/connect-resolver-handoff-replay.json`.
SHA256: `f284add2f55d976785d3d8585cc54fc2401d0881569525a77d8edc873f78de83`.
Report хранит source/tool/upstream SHA, полные fragments, исходные bytes/file
offsets и bounded lexical helper с двумя RET ветвями.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-connect-resolver-handoff.py`.
Capstone 5.0.6/Unicorn 2.1.4; прежний caller budget 8192 instructions.

## Нижний слой 0x1445ea1b0

Теперь этот body реально исполняется после BeginGame и ConnectToServer.
Он вызывает reset 0x1445e5a50 (capture), затем проверяет две внутренние
регистрации через 0x1445d8a50 (lookup fixture). Native insertion bodies
для колец peer+0xd0 и peer+0x118 исполняются, включая записи пар object/control
block и увеличение weak counts. Capacity=4 задаётся fixture, growth не нужен.

При отсутствии записи обе очереди растут 0 → 1, weak count 4 → 5.
В already-listed fixture обе содержат по одной записи изначально, lookup
возвращает валидный не-end iterator: вставок нет, counts остаются 1 и 5.
Это проверка native ветвления и stores, не проверка настоящего dedup поиска,
reset semantics, удаления старых listeners или полной ownership модели.

После этого native код переносит endpoint в peer:

| Поле peer | Источник |
| --- | --- |
| std::string +0x70 | endpoint string+8, copy primitive fixture |
| word +0x90 | endpoint port+0x28 |
| dword +0x94 | endpoint field+0x2c, в проверенном constructor равно 0 |
| dword +0xc0 | третий аргумент нижнего connect, здесь 0 |

Далее 0x1445ea3fb вызывает helper 0x1445e6d70 с context peer+0xc8 и строкой.
Его имя не назначается по догадке: ниже описано фактическое ветвление/задание.
Возврат helper нормализуется по AL в 0/1. Это ещё не TCP connection completion.

## Лексический выбор ветви

Helper сканирует строку: цифры и точки ведут непосредственно к ветви разбора.
Иначе вызывается leaf 0x1445e7b10: он принимает последовательности символов
0–9, a–f, A–F, двоеточия. Это **лексический фильтр**, не полноценная IPv4/IPv6
валидация. Он также принимает пустую строку, но внешний ConnectToServer
до этого отклоняет пустой host; такой полный сценарий здесь не исполнялся.

Поэтому 127.0.0.1, 999.999.999.999, 1..2, точка, ::1 и ABCDEF достигают
одной ветви. Calls 0x1445ef040 и 0x1445de9f0 в ней captures:
реальный parser/result callback не исполнен, валидность адреса не подтверждена.
Callback pointer в caller — 0x141423088; его последующий recipient ещё не связан.

## Ветка имени и объект задания

Для host.invalid, localhost, abc-def фильтр выбирает другую ветвь.
Native body создаёт объект размера 0x48, устанавливает source vtable и сохраняет:
owner context в job+0x20, std::string в job+0x28, job pointer в context+0x38.
Base constructor 0x1445d90b0 и string-copy primitives — fixtures.

Getter 0x1445da5e0 возвращает fixture scheduler; call 0x1445db8a0 захватывает
передачу job. Задание в harness не выполняется: DNS/thread/сокетов нет.
Cancel call 0x1445dc380 сохранён в source и имеет capture, но old-job replacement
не покрыт текущими профилями.

Enqueue return 0/1/2 даёт native нижний return 0/1/1. Security-cookie stub
сохраняет RAX, чтобы не подменять наблюдаемый native bool результат.
Даже return=1 доказывает лишь достигнутую ветвь с fixture enqueue/parser,
а не полученный адрес, открытый socket или готовность отправить Login.

## Двенадцать сценариев и границы

Девять строк (выше), enqueue-zero, enqueue-two, already-listed. Каждый проходит
исходную BeginGame selection/setters, реальный ConnectToServer/endpoint constructor,
нижний connect и lexical selector на одном fixture peer.
Все numeric parser/result, scheduler/enqueue, string/conversion и reset/lookup
примитивы имеют явные границы замены. Native job stores/registration inserts
и return normalization не заменены моделью.

[Три regression tests](../../../../../test_vampir_headless_connect_resolver_handoff.py)
проверяют source fields/calls, lexical branches, registrations/weak counts,
exact copied host/port и bool return. Восемь смежных tests прошли, включая
прежний local loopback send-drain. Это не подключение к серверу игры.
Runtime не менялся; полный suite 316 из runtime milestone не повторялся.

Игра не запускалась; память процесса, Saved/profile, credentials и внешняя сеть
не использованы. Actual resolver job/response, socket creation/connect/readiness,
concurrent lifecycle и game Login остаются открытыми.

Следующий шаг: source vtable resolver job → его исполняемый метод → result callback
и первый реальный socket/connect path; после completion найти запуск packet Login.
