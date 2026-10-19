# Winsock error → engine error → connect wrapper acceptance

19 октября 2026. Продолжение [connect result](HEADLESS-SOCKET-CONNECT-RESULT.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-winsock-error-mapping.py](replay-winsock-error-mapping.py) →
`F:/PhoneExit Resources/Vampir/code-clues/winsock-error-mapping-replay.json`.
SHA256: `6ab6e31ade4c4fd3d8e21427d6eca91351f0cdec03d1fdbac9fc1e408526748f`.
Report сохраняет source/tool/upstream SHA, mapper code, отдельную jump table,
engine vtable, constructor/global instructions и local DLL import/export bytes.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-winsock-error-mapping.py`.
Capstone 5.0.6/Unicorn 2.1.4, inherited native wrapper budget 4096 instructions.

## Реальная привязка virtual+0x68

Constructor root 0x1445ef620:
0x1445ef63b сохраняет this в global **0x14b4f39d0**;
0x1445ef642 загружает vtable **0x149504668**;
0x1445ef649 записывает её в this+0.
Slot+0x68 этой таблицы содержит **0x1445f0680**.
Это тот же global engine и slot, который connect wrapper использует после lower false.
Constructor source сохранён статически; настоящий WSAStartup/startup не исполнялся.

Mapper вызывает IAT **0x148945ad0**. PE import — WS2_32.dll ordinal 111.
Export name **WSAGetLastError** проверен по локальной DLL, её путь/SHA и
export-name offsets/bytes находятся в report. DLL только читается.
Возвращённый системный error — явный fixture, реальный thread-local last-error
и Windows API не используются.

## Switch code и данные разделены

PE unwind range 0x1445f0680 содержит и инструкции, и jump table.
Линейный decode до конца такого диапазона не является корректным code evidence.
Инструмент полностью декодирует только 0x1445f0680..0x1445f0826,
отдельно сохраняет 37 dword entries таблицы **0x1445f0828** с SHA.
Каждый target проверяется как граница исходной инструкции.

Native mapper делает 32-bit subtraction 10035 и unsigned range check 36.
В диапазоне 10035..10071 исполняется выбранная native branch; вне него
результат равен default **30**. Это поведение конкретного mapper, не общее
правило для всех OS/socket ошибок или будущего переносимого runtime.

## Подтверждённые числовые связи

| Fixture Winsock input | Native engine output | Connect wrapper после lower false |
| --- | --- | --- |
| 10035 | 37 | true |
| 10036 | 23 | true |
| 10037 | 22 | true |
| 10056 | 2 | false |
| 10057 | 19 | false |
| 10061 | 6 | false |
| 0, 10004, 10013, 10034, 10072, 11001 | 30 | false |

Точное числовое отображение теперь исполнено, а не выведено из сходства enum.
Символические имена WSA errors и причины их появления отдельно не исследовались.
Не приписывать трём accepted values полный контракт ready/connected.

В каждом сценарии действительно исполняются endpoint connect wrapper,
lower connect body, engine virtual mapper и native switch.
Winsock connect возвращает fixture -1; далее wrapper получает mapped code
через реальную цель slot+0x68, а не прежний stub engine_error.
Вызов mapper подтверждён событиями WSA fixture → mapped return → wrapper result.

## 43 сценария и границы

Все 37 значений 10035..10071 плюс шесть вне диапазона. Из этого набора
wrapper true дают только три значения 10035/10036/10037, несмотря на lower=false.
Code 0 вне range даёт default30 — не выдавать native mapper за success/error
проверку, пригодную для произвольной платформы.

[Три regression tests](../../test_vampir_headless_winsock_error_mapping.py)
проверяют воспроизводимость, code/table разделение, constructor/vtable/import,
выбранные числовые mappings, все accepted outcomes и default boundaries.
Шесть смежных tests прошли. Runtime не менялся; полный suite 316 из предыдущего
runtime milestone повторно не запускался.

Engine constructor/global acquisition, Winsock call/error source, остальные
engine slots, mode/wait и lifetime сохраняют явные fixture границы.
Полная предыдущая resolver chain не повторяется: это изолированный native
connect-result replay. Никаких real DNS/socket/network вызовов, запуска игры,
чтения process memory, Saved/profile или credentials не было.

Далее actual mode helper 0x1445eab70 и его source-bound job run/completion,
readiness notification и packet Login. Клиентский wrapper true по разрешённому
коду ошибки не должен подменять доказательство серверного входа.
