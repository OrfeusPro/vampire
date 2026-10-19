# Socket endpoint connect: sockaddr, syscall result и wrapper acceptance

19 октября 2026. Продолжение [socket setup](HEADLESS-RESOLVED-SOCKET-SETUP.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-socket-connect-result.py](replay-socket-connect-result.py) →
`F:/PhoneExit Resources/Vampir/code-clues/socket-connect-result-replay.json`.
SHA256: `119f14e7a8fb27df0b15f9268d0e903e6452447828e192fca20962eed50a418a`.
Report содержит source/tool/upstream SHA, полные source fragments,
PE ordinal/import descriptors и локальные DLL export-name bytes/offsets.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-socket-connect-result.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget 4096 instructions на native wrapper.

Это изолированное исполнение endpoint-connect wrapper **0x1445e5c60** и
вызванного им body **0x1445ecbb0**. Полный предыдущий resolver/setup в этом
replay не повторяется: socket object, endpoint, handle и mode — явные fixtures.
Не объявлять изолированные результаты доказательством полной игровой сессии.

## Подтверждённые системные границы

| Source IAT | Имя |
| --- | --- |
| 0x148945a30 | WS2_32!htons |
| 0x148945a40 | WS2_32!inet_addr |
| 0x148945af8 | WS2_32!inet_pton |
| 0x148945aa0 | WS2_32!connect |

Три ordinal-вызова (htons/inet_addr/connect) разрешены по таблице
экспортов локальной DLL; inet_pton — именованный PE import. DLL SHA и export
metadata в report. Никакой DLL-код и сетевые функции Windows не исполняются.
Hooks дают ограниченное преобразование synthetic адресов через Python ipaddress.
Это тестовое преобразование, не восстановление полного native parser contract.

## Native sockaddr и connect

Endpoint family tag+0x2c == 1 выбирает sockaddr family 23, размер 28,
порт в network order и 16 IPv6 bytes с offset+8. Остальные tags в исследованном
body выбирают sockaddr family 2, размер 16, IPv4 bytes с offset+4.
Проверены только tags 0/1 с корректными fixture IPv4/IPv6.
Actual htons/inet_addr/inet_pton остаются fixtures; native layout/stores/branches
и call sites исполняются. Byte-level sockaddr snapshots сохранены в events.

Lower body пишет socket+0x50=2 и socket+0x58=30000 перед обеими ветвями.
Имена state/единицы timeout ещё не доказаны. Это значение не меняется даже
при отказе в этих fixtures; его нельзя подписывать «подключено».

При socket+0x3c == 0 body прямо вызывает connect(handle, sockaddr, size).
Любой return, отличный от -1, ведёт к lower true. При -1 — lower false.
Проверен также handle=0: native body всё ещё вызывает connect(0,...),
пропустив engine option getter. Такой fixture не доказывает доступный handle
или корректность полного предшествующего socket lifecycle.

## Ветка mode byte и ожидание

При socket+0x3c != 0 body сначала вызывает engine virtual+0x30 с raw value 1.
Отказ не достигает connect. Успех вызывает connect, затем vector/wait helper
0x1445ea840 с raw timeout 30000. В этой ветви return connect сам по себе
не определяет итог: код проверяет wait bool и непустой vector.

При успешном непустом wait повторяет engine virtual+0x30 со значением 0;
его успех ведёт к lower true. Отказы wait, пустой vector и отказ восстановления
дают lower false. Mode engine calls, vector construction и wait — fixtures.
Они не проверяют настоящее OS readiness, SO_ERROR или время ожидания.
Mode byte задаётся независимо от предыдущего helper 0x1445eab70, который
в этом replay не исполняется. Активный mode реального клиента неизвестен.

## Wrapper не равен успешному connect

Wrapper сначала вызывает lower. При true сразу возвращает true.
При false и ненулевом handle вызывает engine virtual+0x68.
Его raw return **22, 23 или 37** также дают wrapper true.
Другие проверенные коды 0/21/24/36/38 дают false.

Соответствие raw engine codes именам WSA errors **ещё не доказано**.
Не называть их WSAEWOULDBLOCK/ALREADY/INPROGRESS по предположению.
Wrapper acceptance обозначает разрешение внутреннего продолжения, а не
установленное TCP-соединение, прошедшую авторизацию или возможность farm.

## Шестнадцать сценариев и границы

IPv4/IPv6 immediate, handle zero, connect=-1 с восемью engine codes,
wait-ready, wait-false, wait-empty, mode-enter-fail и mode-restore-fail.
Native функции исполняются целиком с captures платформенных границ.
Security-cookie stub сохраняет RAX, чтобы не подменять итоговый AL.

[Три regression tests](../../test_vampir_headless_socket_connect_result.py)
проверяют source/import связи, sockaddr bytes/size/port, state markers,
lower/wrapper divergence, wait/mode sequence и error acceptance.
Шесть смежных tests прошли. Runtime не менялся; полный suite 316 из
предыдущего runtime milestone повторно не запускался.

Winsock, option/error/mode engine, vector/wait, cleanup — fixtures/captures.
Реальных DNS/сокетов/подключений нет. Игра не запускалась; process memory,
Saved/profile, credentials и active account state не использованы.
IPv6 bytes в fixtures не доказывают Android parity или реальную IPv6-сессию.

Далее source engine virtual+0x68 → raw error mapping; реальный mode helper
0x1445eab70 и его job/completion → readiness notification → packet Login.
Полноценное состояние соединения проверять отдельно от wrapper bool.
