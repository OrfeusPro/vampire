# Общий resize и transport queue, 1.13.22

Семейство `buffer-transport` / `buffer-transport-v1` подключено к обновлению и
кэшу на точном SHA
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинная запись](AUTO-BUFFER-TRANSPORT-11322.json) содержит context / proof /
check, источники, SHA инструментов, матрицу, границы и измерения. Перенос на
следующий SHA требует нового receipt и semantic результата; этот пакет
подтверждает ограниченное поведение текущего клиента.

Исполняются пять целых функций: vector.resize, vector.grow, queue.append,
transport и archive.raw, а также 4-байтовая set-count leaf. Allocation growth
включает все пять chained-unwind fragments: 326 байт / 88 инструкций.
Начальный диапазон 40 байт отдельно не принимался за целую функцию.
Raw allocator / sized-free и CRT memcpy / memmove / memset — явные providers;
их реальные source entry bytes и названные PE imports закреплены, но opaque
allocator / free implementations не исполняются. Память выделяет ограниченный
ledger, при этом prefix copy, zero range, alignment header, old-buffer free и
публикацию descriptor выполняет проверяемый код клиента.

Матрица — 65 сценариев / 95 последовательных шагов: 34 resize, 13 append,
8 transport и 10 archive.raw. Девять сценариев переиспользуют тот же объект и
буфер. Проверяются shrink / same / grow-within-capacity, initial / realloc,
коэффициент роста 1,5 для чётной и нечётной capacity, границы 4095 / 4096,
новый и прежний aligned buffer. Максимальный raw allocation request — 6183
байта. Неверные descriptors, огромные размеры, OOM / SEH и отрицательные /
переполняющие append counts исключены из completed scope.

Native reads разрешены только в явных object / stack / source-table / live
allocation / exact payload ranges; padding, guards и retired buffers не входят
в них. Native writes и fixture writes также имеют отдельные диапазоны.
После каждого entry проверяется владелец retained vector, alignment 32,
raw-pointer header и raw allocation size. Sized free должен соответствовать
реальному выделению; replaced vector и input buffers переходят в retired.
Проверяются Win64 nonvolatile GPR / XMM6–15, stack, guards и неизменность
исходных payload / соседних полей. Oracle независим от runtime и сравнивает
фактические bytes, descriptor, calls и порядок событий.

Append использует явный count и сохраняет interior NUL; последний NUL —
отдельный sentinel в vector end. Пустой append в пустую очередь создаёт этот
sentinel; повторный пустой append сохраняет размер. Старшие 32 бита count не
подменяют фактическое чтение R8D в исходном коде. Transport всегда вызывает
append; только state DWORD(+0x108)==1 и busy DWORD(+0xc0)==0 вызывают synthetic
wake slot +0x20 с receiver +0x50 и argument +0x110. Native ordinary return —
AL=1. Failure/reset, реальное планирование wake, drain и сокеты не проверялись.

Archive raw использует тот же resize. Исходный archive object задан ambient
provider по принятому constructor layout: last_count DWORD(+8), flags
DWORD(+0xc), ready BYTE(+0x10). Реальная source vtable и set-count leaf
проверяются; ctor здесь не исполняется. Конкретные flags сохраняются, последний
raw count обновляется source leaf. Packet writer, CRC/XOR и прежние suites
не исполняются в этой новой матрице.

65 native сценариев / 95 шагов и 1006 штатных тестов прошли.
Наблюдались 86 resize, 50 growth, 33 append, 12 transport и 16 archive.raw calls.
Allocator requests: 50, free: 33, aligned allocations: 6, wake: 4.
Первый проход нового семейства: 151.697099 с; последний повтор: 3.44083 с.
Последний повтор использовал 3 этапа / 1 publication из кэша, без native / JVM / PE rebuild.
Общий проход 33 drivers: 1124.546524 с; тёплый повтор: 177.023237 с.
Тёплый общий повтор использовал 99 stages / 33 publications без native / JVM / PE rebuild; SHA 32 code/context files совпали с Git checkout.
Замеры drivers не включают prepare и глобальный аудит исторического индекса.

Source-подготовка разрешила прежний resize / unwind blocker: в новый явный
набор добавлены growth root `0x1445dee20` и cleanup root `0x1445f5020`.
Для точного SHA разрешена только finite sized-free capsule
`0x141431fe0`: `e9fb100500`, один JMP / 5 байт → `0x1414830e0`.
Она служит bounded decompiler boundary, не native implementation allocation.
Сборщик не экспортирует её callee автоматически и сохраняет прежние coverage
проверки. Один missing-only batch `run-bcb6caaf0711` собрал 17 функций;
готовые exports не пересоздавались. Это один JVM source-подготовки, отдельно
от driver-прохода, которому новые экспорты уже не требовались.

В новом proof dependency — только принятый archive-wire context и его точный
check. Typed projection выводит source ABI, helper calls, vtable и import
связи из PE, проверяет все инструкции и relocation, использует ordered parent
memo в одном SourceStore. Рабочая сессия и next-profile не переключаются.
Готовые CRC/XOR 113 случаев и backend/wire 1807 случаев повторно не запускались.

Следующий общий блок — реальный backend assignment / constructor / refcount
lifetime. Для него уже сохранены source links и полные exports, включая
service+0x10 assignment, backend object на 800 байт и cleanup. Их наличие
не подтверждает native lifetime. Связь готового frame backend с новой queue,
непрерывная отправка / drain / socket errors, acquisition session key,
receive integrity и весь онлайн-вход также остаются отдельными границами.

Для следующего lifetime блока подготовлен отдельный source-план: 12 whole roots
и 21-байтовый control-dispatch capsule, 42 предполагаемых новых сценария.
Это план, не native результат. Service destructor оставляет +0x10 / +0x18
необнулёнными; новый стенд не должен приписывать ему очистку этих полей.
При assignment callback+0x2c копируется из неинициализированного stack+0x3c;
данные нужно проверять как входные bits, не подставлять нули по умолчанию.

Инфраструктурное наблюдение: новый driver меняет whole-file guard общего
publication cache и списка drivers. Поэтому unchanged semantic stages
переиспользуются, а прежние publication receipts проходят новую сверку.
Следующая versioned recipe может отделить стабильный алгоритм от registry
и учитывать только selected family declaration плюс полную lineage. Это
предложение оптимизации, не реализованное изменение текущего cache engine;
изменение алгоритма / tools / providers по-прежнему обязано менять ключ.
