# Проверка ошибки сокета внутри задания готовности

19 октября 2026. Продолжение [socket readiness job](HEADLESS-SOCKET-READINESS-JOB.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-socket-error-option.py](replay-socket-error-option.py) →
`F:/PhoneExit Resources/Vampir/code-clues/socket-error-option-replay.json`.
SHA256: `4652bd539d35109d97a8010831fcd3ee400bd2dbf08de654a1a6c4d67e802851`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-socket-error-option.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report хранит SHA источника, инструмента,
предыдущего report и DLL; bytes, file offsets, bounded code, отдельную
таблицу переходов, engine vtable, PE import и локальный export.

Vtable `0x149504668`, slot `+0x60` → **0x1445f0b10**. Связь таблицы
с constructor/global проверена в [WSA mapping](HEADLESS-WINSOCK-ERROR-MAPPING.md).
Тело исполняется от 0x1445f0b10 до RET 0x1445f0c09; следующие padding и
18 DWORD по **0x1445f0c0c** сохранены как данные, а не инструкции.
Вызов на **0x1445f0bf9** → IAT **0x148945b30**, WS2_32 ordinal **7**.
Локальная таблица экспортов связывает ordinal с **getsockopt**.

## Что теперь исполняется

Новый replay заменяет capture engine option из предыдущего задания
реальным target `0x1445f0b10`. Исполняется вся цепочка mode helper →
source ioctl wrapper → одна select iteration → engine option translation →
completion leaf. Только getsockopt и остальные системные вызовы остаются
fixtures. Ни один сокет ОС не создаётся.

На входе engine метода EDX содержит handle, R8D — raw level selector,
R9D — raw option selector; два stack arguments указывают output и size.
Worker передаёт level selector 0, option selector 1, размер 4.
На границе getsockopt это **handle42, level65535, option4103, size 4**.
Символьные названия констант из Windows headers здесь не заявлены;
numeric translation и имя PE import проверены независимо.

Engine возвращает AL как `(syscall result != -1)`. Затем worker отдельно
проверяет DWORD в output. Нулевой output при true даёт state2 → state6,
completion code 1. Ненулевой output либо syscall=-1 дают code 2, state остаётся 2.
В частности, raw output 10035 здесь идёт в ошибку, хотя тот же номер,
полученный другим путём через WSAGetLastError после connect, ранее допускался
connect wrapper. Не переносить правила между двумя разными call sites.

Диагностические fixtures с syscall return1 и изменённым output size 0
при output 0 тоже проходят gate: engine принимает любой result кроме -1,
а worker не перепроверяет изменённый size. Это наблюдение о коде клиента,
не утверждение, что ОС выдаёт такие ответы, и не рекомендация повторять
такую обработку в собственном клиенте.

No-write не вызывает getter и не выдаёт completion; exception-ready
без write-ready даёт code 2 без getsockopt.

## Raw selectors

95 direct native calls проверили level selectors0..4 × option selectors0..18.
Для уровня результат: 0→65535, 1→0, 2→6, 3→17, 4→0.
Значения 4 и 18 — выбранные проверки default, не полное исследование
всех 32-битных значений.

| Option selector | Значение для getsockopt |
| --- | --- |
| 0 | 32 |
| 1 | 4103 |
| 2 | 8 |
| 3 | 128 |
| 4 | 256 |
| 5 | 4098 |
| 6 | 4102 |
| 7 | 4 |
| 8 | 4097 |
| 9 | 4101 |
| 10 | 4104 |
| 11 | 12 |
| 12 | 13 |
| 13 | 9 |
| 14 | 10 |
| 15 | 4 |
| 16, 17 | 1 |
| 18 (за пределами таблицы) | 0 |

## Проверки и границы

Восемь интеграционных сценариев: ready-zero, pending-error, refused-error,
syscall-fail, positive-return, changed-output-size, no-write, exception.
[Три regression tests](../../test_vampir_headless_socket_error_option.py)
повторно строят report и проверяют source/vtable/import, все 95 mappings,
разделение syscall failure/output error и точные state/completion результаты.
Три новых и шесть смежных tests readiness job/WSA mapping прошли.
Полный runtime suite не повторялся: runtime не менялся.

State/mode/interval остаются входными fixtures. Worker ограничен одной
итерацией, completion выполняется вручную. Scheduler, allocator, prepare,
dispatch recipients и lifetime остаются captures из предыдущего исследования.
Реальных readiness, времени ожидания, потоков, Android execution и
server-compatible session нет. Игра не запускалась; profile/process memory,
credentials и сеть не использованы. Runtime бота не изменён.

Следующий шаг: completion code 1 → source-bound socket subscriber → peer
transport notification → packet Login. Проверка готовности сама по себе
не доказывает серверную авторизацию.
