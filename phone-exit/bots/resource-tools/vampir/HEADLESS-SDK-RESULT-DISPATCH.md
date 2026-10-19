# SDK result: делегат, очередь задачи и исходный ответ

19 октября 2026. Продолжение [завершения sign-in](HEADLESS-SDK-SIGN-IN-COMPLETION.md).
Источник — код собранного Windows клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источник и воспроизведение

[replay-sdk-result-dispatch.py](replay-sdk-result-dispatch.py) →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-result-dispatch-replay.json`.
SHA256: `8fdd9f2a7c53e1c6d15e56ccc59488489857a92c429f7c46087a8cbc434a7d4d`.
Отчёт хранит instructions/bytes/file offsets/SHA, vtable bytes и ссылки SHA
на предыдущие response/request reports. Boundaries проверяются по тому же EXE.

Запуск из корня проекта:
`python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-result-dispatch.py`.
Unicorn 2.1.4/Capstone 5.0.6, budget 4096 instructions на native вызов.

## Цепочка передачи результата

| Этап | Адрес / источник | Подтверждённое действие |
| --- | --- | --- |
| SignIn сохраняет callback | 0x1444fb8b4–0x1444fb8c6 | auth+0x98 и четвёртый аргумент → binder 0x1444ba4f0 |
| Binder | 0x1444ba4f0 | Создаёт delegate object и переносит function/storage |
| Dispatcher | 0x1444dff20 | Копирует сохранённый делегат, очищает исходный, создаёт closure |
| Очередь | call 0x1444e008f → 0x141404350 | selector 1 и descriptor с function pointer 0x1444d83b0 |
| Closure thunk | 0x1444d83b0 | При наличии делегата вызывает virtual slot+0x60 с исходным response pair |
| Реальный virtual clone | 0x144237840 | Копирует function pointer и storage в новый delegate |
| Реальный virtual invoke | 0x14423aaf0 | Получает storage context, вызывает bound function и возвращает AL=1 |

Binder устанавливает vtable `0x149424db0`; slot+0x40 → `0x144237840`,
slot+0x60 → `0x14423aaf0`. Это связи из native stores и реальных table bytes,
а не подбор по сходству имён. Начальный SignIn call site экспортирован статически;
сам binder и его virtual clone/invoke исполняются в native_binding_cases.

Payload closure начинается с allocation+8: owner pointer, delegate pointer/count,
затем исходная пара response object/control block по payload+0x18/+0x20.
При non-null control block native код увеличивает strong count. Локальная копия
освобождается, queued closure сохраняет свою ссылку. В fixture count 4 → 5;
после исполнения thunk остаётся 5, так как уничтожение queued closure не выполняется.
Это граница исследования, а не доказательство утечки настоящего клиента.

Исходный delegate count auth+0xa0 обнуляется до выполнения задачи.
Пустая привязка всё равно проходит через очередь, но callback не вызывается.
Это не доказательство exactly-once поведения при гонках или повторной доставке.

## 16 сценариев и ограничения

Восемь базовых сценариев: bound/unbound × control block null/non-null ×
fixture virtual return false/true. Ещё восемь native binding сценариев:
control block × inline/heap function storage × bound function return false/true.

В native binding сценариях slot+0x60 возвращает **1 в обоих случаях**.
Это подтверждает вызов bridge, но не успешный sign-in: значение callback
не используется для результата этой обёртки. Вместе с ранее проверенным
SetSignIn это исключает оба внутренних признака из доказательств игровой сессии.

Исполняются dispatcher, общий delegate copy wrapper `0x1414203f0`, локальный
cleanup `0x1444bee50`, binder, virtual clone/invoke и queued thunk.
Allocation/release, TFunction storage clone/get-context и bound function — fixtures.
Деструкторы delegate захватываются, реальный игровой получатель ещё неизвестен.
Logging явно отключён fixture.

Scheduler `0x141404350` экспортирован статически. Он переносит descriptor+0x10;
replay моделирует move и вручную исполняет queued thunk после возврата dispatcher.
Настоящий task graph, thread affinity selector 1, гонки, финальное уничтожение
closure и переход к игровому Login **не проверены**. Не было запуска игры,
чтения памяти процесса, профиля, реальных ключей или HTTP авторизации.

## Проверки и следующий шаг

[Три regression tests](../../test_vampir_headless_sdk_result_dispatch.py)
проверяют воспроизводимость отчёта, source-bound vtable/call sites,
очистку прежней привязки, сохранение response pair, deferred execution,
пустой callback, refcount и независимость AL от результата bound function.
Также прошли три completion и четыре parser tests. Общий runtime не менялся;
последний полный прогон — 316 тестов из предыдущего milestone, не повторялся.

Далее найти реальный function/storage, передаваемые клиентом в SignIn,
и проследить его обработчик до игрового Login. Не подменять это готовой
SDK-сессией по флагу SetSignIn или значению AL bridge.
