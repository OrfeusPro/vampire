# Resolver job: Winsock results, порядок адресов и completion

19 октября 2026. Продолжение [resolver handoff](HEADLESS-CONNECT-RESOLVER-HANDOFF.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-resolver-job-results.py](../../../replay-resolver-job-results.py) →
`F:/PhoneExit Resources/Vampir/code-clues/resolver-job-results-replay.json`.
SHA256: `998bb7433f5f61629072d32862d7d96c90290f149b489846a23ee4cc0d117a7d`.
Report хранит source/tool/upstream SHA, fragments/bytes/file offsets,
job vtable, PE import descriptors/names/thunks и inet_ntop jump bytes с SHA.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-resolver-job-results.py`.
Capstone 5.0.6/Unicorn 2.1.4, job run/completion budget по 8192 instructions.

## Source-bound job методы и импорты

Ранее source store 0x1445e6ef9 установил job vtable 0x149503a80.
Slot+0x10 равен 0x1445e7e00, slot+0x18 — 0x1445e7cf0.
Harness читает эти targets из реально сформированного job и вручную исполняет
run, затем completion. Реальное расписание задач и виртуальный вызов scheduler
не исполняются; manual drain явно записан в events.

Native run вызывает WS2_32.dll!getaddrinfo через IAT 0x148945ae0
на 0x1445e7e62. Host приходит из job+0x28 std::string. Service argument null;
hints raw flags/family/socktype/protocol = [0,0,1,6].
Winsock вызов заменён fixture, настоящего DNS нет.

Переход 0x14878bc7c связан JMP bytes с IAT 0x148945b18,
PE import — WS2_32.dll!inet_ntop. Этот вызов тоже fixture: он возвращает
заданный текст, не исполняет настоящее преобразование sockaddr.

## Обход ответов и native перестановка

При getaddrinfo return 0 native код создаёт payload 0x50 bytes и обходит
linked addrinfo rows: family по row+4, sockaddr pointer row+0x20,
next pointer row+0x28. Family 2 использует address bytes sockaddr+4;
family 23 — sockaddr+8. Остальные family пропускаются.

Текст через bounded std-string fixture передаётся helper 0x1445ef040,
который здесь моделирует append в payload vector+0x38/+0x40/+0x48.
Actual address parsing/vector growth этого helper не исполняются.
Source native обход семей и перестановка в уже заполненном vector исполняются.

Далее вызывается ранее проверенный lexical hex/colon helper. Первый подходящий
непервый элемент меняется местами с первым. На заданных IPv4/IPv6 fixtures:

| Исходный порядок | Native результат |
| --- | --- |
| IPv4 | IPv4 |
| IPv6 | IPv6 |
| IPv4, IPv6 | IPv6, IPv4 |
| IPv6, IPv4 | IPv6, IPv4 |
| IPv4-A, IPv4-B, IPv6 | IPv6, IPv4-B, IPv4-A |

Это swap, а не стабильная сортировка. Таблица не доказывает настоящую успешную
IPv6-сессию или требование для portable runtime. Лексический helper сам по себе
не валидирует адрес; реальные inet_ntop/vector parsing здесь заменены fixtures.

## Completion и ошибки

Run вызывает helper 0x1445dad30 с job и payload pointer (или null при ошибке).
Он capture; harness вручную вызывает job slot+0x18 с исходными аргументами.
Completion читает owner из job+0x20 и размер vector.

- При непустом payload/vector вызывает 0x1445de9f0 с callback pointer
  0x141423088 и исходным result payload.
- При null payload или пустом vector вызывает 0x1445de8b0 с failure pointer
  0x14370ae90.
- Ненулевой payload передаётся cleanup 0x1445e3110, затем free.

Оба result/failure dispatch helpers и cleanup — captures. Получатель callback,
socket creation/readiness и полный ownership после completion не исполнены.
Result addresses в report снимаются **до** cleanup, не читаются как доказательство
жизни объекта после настоящего destructor.

## Восемь сценариев и проверки

IPv4, IPv6, оба порядка смешанного списка, два IPv4+IPv6, неподдерживаемая
family, пустой результат, DNS error 11001. Последние три проходят failure path.
Все сценарии сначала исполняют предыдущую цепочку BeginGame → ConnectToServer →
lower setup → job handoff. Затем вручную run/completion на том же fixture job.

[Три regression tests](../../../../../test_vampir_headless_resolver_job_results.py)
проверяют source vtable/import binding, hints/host, family traversal,
точный swap и callback gates/order. Шесть смежных tests прошли.
Runtime не менялся; полный suite 316 из предыдущего runtime milestone не повторялся.

Getaddrinfo/inet_ntop, string/vector primitives, base ctor, scheduler, cleanup
и downstream dispatch — fixtures/captures. Нет настоящих DNS, threads, сокетов,
проверки lifetime/races или Android parity. Игра не запускалась; память процесса,
Saved/profile и credentials не использованы. Адреса только synthetic/test ranges.

Следующий шаг — recipient callback 0x141423088 и обработка payload с адресами,
первый socket/connect/readiness callback, затем packet Login. Return job handoff
или непустой vector не считать доказательством подключённого клиента.
