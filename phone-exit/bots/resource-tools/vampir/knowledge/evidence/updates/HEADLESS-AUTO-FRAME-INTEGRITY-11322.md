# Автоматический CRC/XOR и Login frame, 1.13.22

Новое семейство `frame-integrity` / `frame-integrity-v1` подключено к обычному
обновлению и кэшу. Его первая база — точный SHA 1.13.22
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Это новое доказательство текущего клиента; фактический переход на будущий SHA
требует нового receipt и native результата. Машинная запись —
[AUTO-FRAME-INTEGRITY-11322.json](AUTO-FRAME-INTEGRITY-11322.json).

Матрица содержит 113 случаев: 3 initializer, 30 CRC, 70 XOR и 10 backend entries.
CRC проверяется на пустом входе, известном векторе, продолжении raw state,
разных размерах, смещениях и ширине R8D. XOR — с fallback / явными ключами,
в том же и отдельном буфере, unaligned, с нулевой и отрицательной EDX длиной,
с ненулевыми старшими битами аргумента и явным native home slot ключа.
Read/write windows запрещают доступ за границами primitive inputs.

Десять прямых backend entries исполняют настоящий Login writer, archive IO,
CRC initializer/update и XOR. Независимый oracle использует существующий
portable CRC/XOR и четыре разные immutable prepared projection: ordinals
8 / 5 / 0 / 16, body 91 / 807 / 173 / 173 байта. Это fixture inputs из принятого
parent report; native preparation / SDK / metadata / sender / publisher здесь
не исполняются. Final pair сохраняет те же backend и packet: native sequence
переходит 65535 → 0 → 1, ключ явно меняется между двумя доставками.

В допуск входят 16 whole roots, 9 returning capsules и 2 cleanup tails.
Три integrity leaves не имеют unwind; адреса получены из трёх E8 backend calls,
а не из поиска по Markdown. CRC leaf допускает только RIP relocation bytes
[11:15]; все 256 DWORD таблицы проверяются по polynomial 0xedb88320.
Initializer / XOR instructions, source anchors, vtable links, full exports,
selected globals и source SHA проверяются до и после обработки.

Checksum и transform исполняются native без callbacks. Transport остаётся
bounded capture: сохраняются фактические cipher bytes до cleanup. Inner buffer
после writer, prefix из 3 байт, свободная capacity и outer после capture
защищены. Общий ledger проверяет caller, owner, kind, size, guards и retirement.
Archive cleanup идёт outer → inner; input packet и FString остаются неизменными.
Packet/backend/archive extents этого стенда — 320 / 784 / 64 байта.
Реальный backend constructor требует отдельные 800 байт и сюда не включён.

113 native сценариев и 950 тестов штатного tooling набора прошли.
Наблюдались 40 CRC init, 56 CRC update, 80 XOR calls и 10 native writer calls.
Первый проход нового семейства: 1190.828964 с; последний повтор: 82.16464 с.
Последний повтор использовал 3 этапа / 1 publication из кэша, без native / JVM / PE rebuild.
Общий проход 32 drivers: 1886.189991 с; тёплый повтор: 236.979263 с.
Тёплый общий повтор использовал 96 stages / 32 publications без native / JVM / PE rebuild; SHA 60 code/context files совпали с Git checkout.
Замеры drivers не включают prepare и глобальный аудит исторического индекса.

Точные parent context / report pointers следуют принятой backend lineage;
wire и prepare не выбираются независимо. Memo принадлежит одному SourceStore,
включает ordered baseline / target, tools и полную transitive lineage;
целостность материалов проверяется до memo hit. Готовые native suites родителей,
включая прежние 1807 случаев, повторно не исполняются.

Отдельная source-подготовка assignment/lifetime/transport запросила 17 roots,
15 из них отсутствовали в индексе. Один missing-only Ghidra batch остановлен
на `0x1445e4d00`: decompiler block вышел за заявленные unwind ranges
(`run-6f3b658dde3f`). Результат сохранён как конкретный blocker; экспорт не
признан полным. Source E9 resize+0x55 ведёт в отдельный PE unwind root
`0x1445dee20`; эта машинная source-связь сохранена для следующего prepared набора.
Это один JVM исследования, не JVM native-family прохода.
Для нового integrity family все 16 whole уже покрыты пятью готовыми exports.
Source resize `0x1445e4d00` общий для archive.raw и transport.append: найдены
1 + 2 прямых вызова. Машинная запись сохраняет обоих потребителей для одного
следующего native helper пакета; allocation tail остаётся отдельной границей.

Реальные service assignment / constructor / refcount lifetime, transport queue
ownership / drain / socket errors, session key acquisition, receive integrity,
OS / SDK / engine effects, realloc / aligned / OOM / SEH и весь онлайн-вход
остаются открытыми. Native bounded proof не активирует профиль и не меняет
работающую сессию. Следующий пакет использует сохранённые source links и точный
collector blocker, затем расширяет правило; готовые сценарии заново не разбираются.
