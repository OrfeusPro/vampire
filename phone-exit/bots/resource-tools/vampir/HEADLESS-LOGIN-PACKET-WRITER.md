# PktLogin: проверенный writer и переносимое тело

19 октября 2026. Продолжение [подготовки полей Login](HEADLESS-LOGIN-PACKET-FIELDS.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Сначала прочитаны Ghidra `PktLogin_Write.c`, `PktLogin_Constructor.c` и
`Archive_WriteFString.c` из общего
`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Затем actual инструкции исполнены через Capstone 5.0.6 / Unicorn 2.1.4.

[replay-login-packet-writer.py](replay-login-packet-writer.py) создаёт
`F:/PhoneExit Resources/Vampir/code-clues/login-packet-writer-replay.json`.
SHA256 отчёта: `72fb4625a02664f416f1388bfbf9c9e27b81eda0735247695d14ff0130ce6c4b`.
Отчёт содержит EXE/tool/upstream SHA, bytes/file offsets/native fragments,
архивную vtable и прямую привязку writer к PktLogin vtable+0x10.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-packet-writer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_packet_writer.py
```

Исполнен **0x1456e57c0** — writer PktLogin/ID 3, vtable **0x1498d6058**,
из [packet bindings](HEADLESS-PACKET-BINDINGS.md). Его slot+0x10 заново
проверяется по реальным байтам EXE. Исполняются FString writer **0x144aa6a30**,
native UTF-8 length/conversion и те же архивные примитивы, что у
[Version](HEADLESS-VERSION-PACKET-WRITER.md).

## Порядок тела

Смещения ниже — поля объекта клиента; это не смещения в переменном wire body.
Префикс строки — uint16 little-endian с длиной UTF-8 **в байтах**,
затем байты без завершающего NUL. Числа little-endian.

| Последовательность | Формат |
| --- | --- |
| +0x10, +0x20, +0x30, +0x40 | 4 строки |
| +0x50 | uint32 |
| +0x58, +0x68, +0x78, +0x88 | 4 строки |
| +0x98, +0x99 | 2 байта |
| +0xa0 | строка |
| +0xb0 | uint32 |
| +0xb8, +0xc8, +0xd8, +0xe8 | 4 строки |
| +0xf8 | uint32 |
| +0x100, +0x110 | 2 строки |
| +0x120 | uint32 |
| +0x124 | байт |
| +0x128 | uint64, семантика неизвестна |
| +0x130, +0x131 | 2 байта через bool slot |

Всего 15 строк, 4 uint32, 5 байтов, 1 uint64. Минимальный размер тела —
**59 bytes**. ID 3, frame, CRC/XOR и транспортный header сюда не входят.
Archive table **0x14961a5c0**: +0xb8→**0x144aa61e0**/u64,
+0xc8→**0x144aa6090**/u32, +0xe0→**0x144aa6030**/byte,
+0xf0→**0x144aa6210**/bool byte. Байты таблицы и native fragments сохранены.

Функция bool slot записывает исходный DL, без нормализации к 0/1.
Distinct-fields vector с +0x130=2/+0x131=255 сохраняет эти значения в теле.
Это поведение writer, а не доказательство допустимости таких флагов сервером.

Расширенный capture повторно исполняет 16 прежних preparation scenarios и
снимает +0x128 перед request handoff. Во всех covered fixtures поле равно 0;
конструктор в Ghidra также показывает zero assignment. Это не имя поля,
не общая политика server/profile и не основание скрыть его за default в API.
Все остальные поля совпадают с прежними snapshots. Writer запускается отдельно
с этими данными; единого constructor→handoff→frame исполнения здесь нет.

## Векторы и отказы

**25 успешных native vectors**: 16 исходных preparation cases, distinct fields
с границами uint32/uint64 и raw bool bytes, 8 строковых cases: empty, ASCII 15/16,
ASCII 127/128, кириллица+иероглиф, emoji, multibyte UTF-8. Native bytes
сверены с независимым ожидаемым layout и общим переносимым кодеком.

**40 отказов** подставлены последовательно на каждом вызове raw archive IO
**0x144aa6120** для distinct-fields packet. Подстановка возвращает 0 и
не записывает соответствующий кусок. Фактически:

- 10 скалярных отказов останавливают writer с `return 0`; остаётся префикс тела.
- 30 строковых отказов (length/data для 15 строк) игнорируются string path:
  последующие поля записываются, writer возвращает 1. В теле отсутствует
  именно отвергнутый участок. Это не корректно сформированный пакет.

Проверяются точные bytes/prefix/пропущенный диапазон, return и число вызовов.
Это доказательство propagation при данном raw-return fixture; реальный
allocator failure, заполнение archive и политика capacity/growth не проверены.
Нельзя по одному `return 1` объявлять пакет или сессию исправными.

## Общий кодек

[vampir_core.login_packet.LoginPayload](../../vampir-shared/vampir_core/login_packet.py)
использует только Python stdlib и принимает immutable ordered tuples для
строк/uint32/байтов и явный opaque `raw_128`. Все данные скрыты в repr.
Семантика неизвестных полей не выдумывается, настоящие identifiers/token
из локального профиля не подставляются.

`encode(max_payload_size=...)` требует явный локальный byte budget,
проверяет всё тело до возврата immutable bytes и отклоняет переполнение.
Локальная строгая политика отвергает NUL, суррогаты, U+FFFE/U+FFFF,
UTF-8 длину>65535, bool вместо int, mutable containers и неверные диапазоны.
Это правила API, не native-проверка malformed input и не лимиты сервера.

[Четыре tests](../../test_vampir_headless_login_packet_writer.py) заново
строят native report, проверяют source/vtable, все 25 payloads, 40 failure
cases, immutable inputs, integer ranges, repr, бюджет и uint16 string maximum.
Смежные Login fields, Version writer и Version send path также проверены.

## Что ещё не готово

Allocator/free/cookie/memcpy остаются ограниченными fixtures; native archive
имеет заранее предоставленные 8192 bytes. Не проверены native embedded NUL,
invalid UTF-16/overflow/truncation и рост буфера. Реальные SDK/profile/device
inputs, SDK freshness и серверные ограничения остаются отдельными задачами.
Игра/process memory/credentials/network не использованы.

Общий body encoder добавлен, сетевой runner не подключён. Полного Login
frame/send/request tracking/socket/ответа LoginResult и живой сессии ещё нет.
Далее: request handoff **0x144aa8020** → transport send, затем совместное
исполнение подготовки/writer/frame и разбор LoginResult с result gates.
