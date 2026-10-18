# Vampir — первый транспортный этап приёма

18 октября 2026, H03b.2b-transport, частичный результат.
Общий [реестр функций](../../vampir/FUNCTION-INDEX.md), предыдущая
[приёмная обёртка](HEADLESS-RECEIVE-ENVELOPE.md).

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса — VA, image base `0x140000000`. Версия Windows и соответствие Android неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-transport-stage.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_transport_stage.py -v
```

Выход: `F:/PhoneExit Resources/Vampir/code-clues/headless-transport-stage.json`.
SHA256 `f60ef311ba43cf781abd069f061be307786db10627d678678df68a3ba05f6696`.
Отчёт сохраняет source/tool hashes, 11 фрагментов / 724 инструкции,
PE import provenance внешних memory shims и 62 native сценария.

## Два уровня буферов

Точная строка `UxTcpPeer::_HandleRecvBuffer` из EXE связана LEA
`0x1445ed4cc` с root `0x1445ed3e0`. Эта функция обрабатывает raw buffer
раньше исследованного length probe `0x144aa9a90`.

В raw buffer первые три байта имеют другую трактовку:

- Биты 0–22 — полная длина транспортного кадра, включая три байта заголовка.
- Бит 23 (`0x800000`) — признак сжатия.
- Нулевая длина прекращает цикл. Недостаток байтов оставляет кадр в буфере.

Это закреплено native инструкциями: mask `0x7fffff` в `0x1445ed483`,
shift23 в `0x1445ed497`. Чтение raw начинается при наличии минимум трёх
фактических байтов: end pointer включает дополнительный NUL sentinel,
который функция вычитает при вычислении available. Не переносить sentinel
в сетевой протокол как дополнительный передаваемый байт.

Для несжатого кадра функция передаёт данные после настраиваемого смещения
`main+0x1fc` во второй буфер. Ранее исследованные constructor paths задают
этому полю 0 для peer A и 3 для peer B. Оба значения проверены отдельными
сценариями. Во время append старый NUL во втором буфере заменяется данными,
затем восстанавливается новый sentinel. Несколько полных кадров объединяются,
неполный хвост остаётся в raw buffer после native memmove.

В сжатой ветке декомпрессор `0x14141ba60` получает source+3,
compressed_size=declared−3 и output capacity `0x100000`. Output берётся из
thread-local scratch. Положительный результат добавляется во второй буфер;
неположительный ведёт в диагностическую ветку. Ошибочные compressed inputs
и полный error path пока не исполнены.

После этой стадии функция запускает отдельный цикл слушателей второго буфера.
Его связь с length probe/обёртками прослеживается отдельно. CRC в первой
исполненной стадии не вычисляется; отсутствие CRC во всём приёме этим не доказано.

## Что реально исполнено

Builder исполняет диапазон `0x1445ed403..0x1445ed562`: raw-length цикл,
native decompressor, настоящий vector append `0x1445e4a90`, resize
`0x1445de6e0` в пределах capacity и native compaction. TLS, owner и byte vectors
заданы явно; буферы заранее выделены. Growth/allocator и второй listener loop
исключены. Только внешние CRT memcpy/memmove/memset заменены ограниченными
shims, имена двух новых импортов подтверждены через PE import directory.

62 сценария покрывают:

- Разрезы до/внутри заголовка и за один байт до полного кадра.
- Несжатые и сжатые literal-only fixtures с ожидаемым output.
- Два полных кадра разных типов, остаток следующего заголовка и existing output.
- Вариант skip=0 с сохранением заголовка и skip=3 с удалением заголовка.

Literal fixtures соответствуют проверенной ветке декомпрессора. По ним не
объявляется восстановленным весь compressed format, алгоритм не именуется
по сходству инструкций, общий Python decoder не реализован.

## Общие компоненты и продолжение

`vampir-shared/vampir_core/transport_header.py` содержит:

- `inspect_transport_header(buffer, *, max_frame_size)` — size23/flag.
- `take_uncompressed_transport_frame(...)` — первый полный несжатый body и
  количество потребляемых байтов, либо None для неполного входа.

Local policy требует size≥3 и явный максимум не выше `0x7fffff`; это бюджет
приложения, не найденный серверный maximum. Полный сжатый кадр вызывает
NotImplementedError. Частичный кадр ожидается, данные не интерпретируются как
несжатые молча. Это не socket transport, не XOR/CRC parser и не весь приём.

`receive_frame.py` продолжает относиться ко **второму** уровню длины (LE24
без отдельного compressed bit в исследованной функции). Его нельзя применять
к raw stream вместо transport_header.py. Исторические записи «длина24» до
этого открытия описывают именно второй уровень, а не весь протокол.

Пять тестов сверяют source/fragment bytes, native vectors, поведение общего
parser и три дополнительных native replays смешанных/неполных кадров.
Далее: listener loop и конечные callback targets, направление/входной layout,
целостность, весь decompressor и send queue. `network_ready=false`.
Игровой клиент, аккаунты и сеть не использовались.
