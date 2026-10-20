# PktVersion: native writer и переносимое тело запроса

19 октября 2026. Продолжение [connected callback](HEADLESS-CONNECTED-VERSION-PACKET.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-version-packet-writer.py](../../../replay-version-packet-writer.py) →
`F:/PhoneExit Resources/Vampir/code-clues/version-packet-writer-replay.json`.
SHA256: `8d9a65c8a0dd5d6d8b52e5e8a62d174751fbcac95d27154f107fa9353e4c44be`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-version-packet-writer.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report хранит source/tool/upstream SHA,
writer/conversion/archive fragments, bounded encoder leaf, archive table
bytes/file offsets/SHA и 14 native payload vectors.

## Что исполнено

Writer **0x1456e5cf0** связан с packet table 0x1498d6990 slot+0x10 в
предыдущем report. Новый replay исполняет его целиком, включая:

- FString helper **0x144aa6a30**: проверка count, поиск UTF-16 terminator,
  преобразование в UTF-8 и создание std::string inline/heap.
- Actual UTF-8 length **0x141446a50**, converter **0x141440af0** и bounded
  scalar encoder **0x141439820..0x14143995c**. Эти преобразования не Python fixtures.
- Archive vtable **0x14961a5c0** slot+0x28 → **0x144aa5fe0** (string),
  slot+0x60 → **0x144aa6060** (uint16), slot+0xc8 → **0x144aa6090** (uint32),
  а также native raw IO и archive constructor из [Ping codec](HEADLESS-PING-CODEC.md).

Allocator/resize/free, cookie и bounded CRT memcpy — fixtures. Archive после
actual constructor получает явный buffer/capacity 8192, без проверки growth.
Instruction budget writer 200000. Native layout сравнивается с независимой
сборкой struct/UTF-8, которая не подаёт байты в эмулятор.

Это **отдельный native serialization run**, которому переданы snapshots полей
предыдущего connected callback. Оба участка проверены, но полного единого
callback → frame → socket исполнения здесь нет.

## Подтверждённый layout тела

Строка: **uint16 little-endian число UTF-8 bytes + ровно эти bytes**, без NUL.
Число — uint32 little-endian. Порядок ниже относится только к телу PktVersion:

| Порядок | Packet field | Тип |
| --- | --- | --- |
| 1 | +0x10 | String |
| 2 | +0x20 | uint32 |
| 3–9 | +0x28,+0x38,+0x48,+0x58,+0x68,+0x78,+0x88 | String ×7 |
| 10 | +0x98 | uint32 |
| 11–12 | +0xa0,+0xb0 | String ×2 |
| 13 | +0xc0 | uint32 |

Минимальное тело — 32 bytes: десять uint16 lengths и три uint32.
ID1, sequence, CRC, XOR и frame length **не входят** в этот payload.
Смысл строк и raw integers по-прежнему не присвоен без getter evidence.
В частности 207 — подтверждённый callback store, не установленная версия протокола.

14 native cases: пять snapshots callback (включая Unicode, empty,
send-false и raw enum max) плюс девять string boundaries: empty, 1/15/16/
127/128 ASCII bytes, `Ж界`, supplementary `🙂`, 160 UTF-8 bytes из `é`.
Проверены inline/heap std::string и conversion scratch, BMP/surrogate pair,
пустые поля и unsigned DWORD. Все payload bytes совпали с независимой моделью.

## Общее ядро

[version_packet.py](../../../../../vampir-shared/vampir_core/version_packet.py):
`VersionPayload(strings, integers).encode(max_payload_size=...)`.
Только stdlib, immutable tuples/model/output, строки скрыты из repr; I/O нет.
Strings — десять полей в порядке writer, integers — три поля в том же порядке.
Никаких guessed defaults, SDK token/profile getters или сетевого state.

Обязательный max_payload_size — локальный byte budget32..0xffffff, не найденный
лимит сервера. Encoder проверяет полный размер до создания output bytes;
при превышении BufferError. Перед frame encoding потребуется учесть его overhead.

Локальная политика строже покрытого native path:

- Только str и immutable tuples точной длины; integers точные int uint32, без bool.
- Не допускаются embedded NUL, surrogate code points, U+FFFE/U+FFFF.
  Native string helper ищет NUL, а scalar encoder умеет замены недопустимых
  значений; переносимый helper не имитирует неоднозначные замены/усечение.
- Каждая строка максимум 65535 UTF-8 bytes, без uint16 truncation.
  Проверка encoder на 65535 bytes — локальный boundary test; native vectors
  ограничены меньшими строками, поэтому native parity на 65535 не заявлена.
- Нет decoder, пока соответствующий reader не проверен.

[Три regression tests](../../../../../test_vampir_headless_version_packet_writer.py)
проверяют source/report reproducibility, portable bytes для всех 14 native cases,
неоднозначные/изменяемые inputs, Unicode/length/budget bounds и redacted repr.
Полный headless suite прошёл: **379 tests за 298.328s**, команда
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless*.py'`.

## Осталось до обмена с сервером

Native writer при успешном preallocated archive возвращает 1. Failure propagation,
невалидные native descriptors, allocator failures и archive overflow здесь не
проверялись. В частности string archive method содержит безусловный AL1 после
внутренних calls; это статическое наблюдение, а не выполненные failure scenarios.
Не переносить предположение об атомарном native отказе в session policy.

Wrapper send0x1467aaa10 статически передаёт packet через thunk0x144aab2f0;
его logging/metadata/full send path и связанный frame builder ещё не исполнены
с этим packet. VersionResult, Login, реальные значения weekly version/getters,
real socket/OS timing, server session и Android parity остаются открытыми.
Игра/profile/process memory/credentials/network не использованы.
