# Тело QuestUpdate и очередь исходящих кадров в 1.13.16

Источник SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Packet table `149965670`, constructor leaf `145828b00`, ID getter `145834490`,
writer `145837030`, reader `14582bc60` закреплены по EXE и exports.
Writer вызывает vector `144aad280`, reader — `144aacf40`.

Output table `149670920`: float A8 → `144aac9a0`, qword 48 / B8 → `144aacac0`,
byte E8 → `144aac910`, raw 88 → `144aaca00`. Input table `1496706e8`:
float 40 → `144aac2f0`, qword 50 → `144aac4a0`, byte 80 → `144aac240`,
raw 90 → `144aac5c0`. Packet slots и полный SHA output table проверяются.
[Общие constructors / archive IO](../updates/HEADLESS-ARCHIVE-WIRE-11316.md)
использованы повторно, адреса не получены общим сдвигом старых функций.

Недостающий float output root получен в `run-c3a47a328960`. Совместная попытка
с model getter `1455be4b0` была отклонена collector: getter — 8 байт MOV RIP
global / RET без unwind root. Ему не выдумывались границы. Новое задание
исключило leaf и получило только недостающий float root; исходная неудачная
попытка сохранена, тот же request повторно не запускался.

## Целая проверка

`replay-quest-update-wire-11316.py` исполняет packet constructor / getter,
writer / mirror reader, оба vector helper, float / qword / byte primitives,
настоящие output / input constructors и raw archive IO. Восемь exports,
14 unwind roots и семь ограниченных leaf закреплены в
`knowledge/native-contexts/quest-update-wire-11316.json`.
В успешных случаях raw output не fixture: проверяются настоящий буфер,
оба счётчика, неизменный packet и guards. Выделено 128 байт, growth запрещён,
memcpy — bounded fixture. Endian swap / реальная allocation не исполняются.
Constructor не инициализирует vector, caller обязан его задать.

Подтверждены 29 байт: float32 LE x/y/z, uint64 LE TargetId,
uint64 LE QuestInfoId, uint8 QuestTaskIndex. Native object хранит координаты
double и преобразует их в float32 при записи; mirror восстанавливает double.
Имена последних полей отдельно закреплены
[producer](HEADLESS-QUEST-UPDATE-PRODUCER-11316.md).

81 случай: четыре вектора (signed zero / крайние float32 / server target),
пять qword вариантов (включая high bit / UINT64_MAX), четыре byte значения,
плюс 0 / 110120 / 0 с наблюдавшимися координатами. Последний случай — только
синтетическая проверка кодирования, не отправленная команда или активный этап.
Все 29 коротких префиксов отклонены без выхода cursor за body / изменения guards.
Шесть отказов проверены отдельным harness с raw IO fixture: writer сразу
останавливается на соответствующем primitive.

Артефакт `code-clues/quest-update-wire-11316/59381a6ead63e1f29003fdf578aac52e815c004616432ab301f2457e4ca8e984/manifest.json`.
`test_vampir_quest_update_wire_11316.py`: 2 теста прошли;
`test_vampir_quest_update.py`: 3 теста прошли, исторический native replay сохранён.

## Runtime и границы

Portable codec допускает только прежний и current полные SHA. Сохраняются
строгие finite vector / uint64 / byte проверки. Новый encode_quest_update_frame_b
и OutboundFrames.queue_quest_update используют общий B frame / CRC / XOR.
Проверены два разных owner key / sequence, wrap 65535→0, неизменная очередь /
sequence при неверном source и backpressure, отказ после close. HTTP их не вызывает.

Это допуск **codec**, а не всего действия. Wire может представлять FF, но handler
не должен считать его допустимым task index. GameConnection / pump / action API
не подключены, текущий онлайн-owner не модифицирован. Порядок / выбор task,
позиция после engine correction, HUD callback, движение, реплики / skip /
inventory и серверное выполнение ещё открыты. Живых команд не отправлялось.
