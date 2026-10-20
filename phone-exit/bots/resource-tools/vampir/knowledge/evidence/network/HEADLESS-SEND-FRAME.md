# Vampir — полный исходящий Ping frame, H03b.2a

18 октября 2026. [Предыдущий этап](HEADLESS-FRAME-PRIMITIVES.md),
[общие компоненты](../../../../../vampir-shared/README.md), [реестр](../../../../../vampir/FUNCTION-INDEX.md).
Подтверждена сборка исходящего Ping для send-A. Приём, сессия и подключение ещё не готовы.

## Источник и повторение

Собранный Windows EXE `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Все адреса VA с image base0x140000000. Версия Windows/Android parity unknown.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-send-frame.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_send_frame.py -v
```

Выход `F:/PhoneExit Resources/Vampir/code-clues/headless-send-frame.json`,
SHA256 `1bf470e99750c675890ee3f51ab5380a4c0b14f9fab948d8d5860902c9d3de57`.
В отчёте source/tool/upstream hashes, оригинальные bytes/offsets, bodies,
unwind fragments, исполняемый диапазон и 20 полных native frame vectors.

## Что исполнено

Builder повторно использует проверенный PingEmulator и CRT memcpy shim.
Исполняется цельный native диапазон **0x144aa9e6a..0x144aa9f45** из send root
0x144aa9da0, с настоящими calls на serializer/ID getter/primitive IO/raw IO/
CRC init/update/stream append/XOR. Выходная граница до cleanup, buffer уже собран.
Не заменяются Python-кодом ни поля кадра, ни счётчик, ни CRC, ни XOR.

Explicit environment: правильный PktPing vptr, native ctor output archives
с заранее выделенными 256 байтовыми буферами, заданное connection sequence.
Allocator/growth, cookie/prologue/cleanup, сокеты и вся остальная сессия исключены.
Первый replay показал недостающую code page ID getter 0x1414079a0 в эмуляторе;
она добавлена вместе с bounded body, не заменена stub.

## Формат исходящего кадра A

| Offset | Bytes | Поле до XOR |
|---:|---:|---|
| 0 | 3 | Общая длина кадра little-endian24, включая эти 3 байта |
| 3 | 4 | CRC32 только внутреннего блока начиная с offset 7 |
| 7 | 2 | Packet ID little-endian16, для Ping 16 |
| 9 | 2 | Счётчик соединения little-endian16 |
| 11 | 16 | Тело Ping `<QQ` из H03a |

После сборки XOR с fallback key применяется к кадру начиная с offset 3,
перезапуская key index с 0; первые 3 байта длины остаются открытыми.
В этом эксперименте Ping frame имеет 27 байт. CRC покрывает ID+счётчик+body,
а не поле длины/сам CRC. `sequence` берётся до increment из connection+228,
после чего native16bit запись даёт(sequence+1)&65535. Это наблюдение состояния
этого send root, не политика для любого соединения/другой сборки.

20 native scenarios: 4 пары raw64values ×5sequence0/1/255/256/65535.
Включены 2^53+1 и all-ones, boundary sequence wrap. Native frame целиком совпал
с независимой конструкцией длины/CRC/XOR, не только с отдельными helpers.

## Переиспользуемый код и проверки

`vampir-shared/vampir_core/send_frame.py` содержит
`encode_ping_frame(PingPayload, sequence)`. Только stdlib и общие modules.
API не ведёт глобальный счётчик: его владелец — будущая отдельная сессия.
ID и fallback path ограничены доказанным Ping send-A. Нет сетевых вызовов,
generic login frame API, send-B ключей или обещания совместимости с сервером.

5 тестов проверяют bytes/SHA/границы диапазона, все 20 полных native vectors,
layout/CRC scope/валидацию аргументов и 2 дополнительных native slice replays.
Оригинальные инструкции и proof файлы остаются вне runtime.

## Оставшееся receive/context

Проверен static pointer на Dispatch0x14679f510 в таблице 0x149d80538, slot+8;
LEA на это начало есть в factory root 0x14678ec40 и destructor root 0x14679f270.
Это ещё не доказательство, что callback receive wrappers указывает на эту таблицу.

У Dispatch ID читается из input+3, body из input+5; у исходящего полного кадра
IDoffset7, bodyoffset11. Эти слои нельзя механически объединять: направление
и преобразования до callback надо восстановить. Прямой E8-поиск CRC helper
показал только два send callsites; это не доказывает отсутствия иных checksum
implementations/indirect receive verification. Source of session key unknown.

Следом H03b.2b: receive framing/length checks/integrity, callback target,
выбор контекста/ключа и handler slot+8→OnHandler+10. Текущий результат:
send_a_layout_verified=true, receive_validation_verified=false, network_ready=false.
Игра/сеть/аккаунты не использовались.
