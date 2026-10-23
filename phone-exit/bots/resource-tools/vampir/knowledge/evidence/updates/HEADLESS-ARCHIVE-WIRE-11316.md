# Archive и полные тела Version / Login в 1.13.16

Источник — EXE 1.13.16, полный SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [полного string writer](HEADLESS-STRING-WRITER-11316.md).
Профиль runtime и baseline не переключались.

## Привязки и получение материалов

| Роль | Текущий VA | Связь |
| --- | --- | --- |
| Output constructor | `0x144aacbd0` | Устанавливает table `0x149670920` |
| Base constructor | `0x144aac6b0` | Вызывает bounded leaf `0x144aad1b0` |
| Archive string | `0x144aac8c0` | Table slot `+0x28` |
| Archive uint16 | `0x144aac940` | Slot `+0x60` |
| Archive raw IO | `0x144aaca00` | Slot `+0x88` |
| Archive uint64 | `0x144aacac0` | Slot `+0xb8` |
| Archive uint32 | `0x144aac970` | Slot `+0xc8` |
| Archive byte | `0x144aac910` | Slot `+0xe0` |
| Archive bool input | `0x144aacaf0` | Slot `+0xf0`, raw DL без normalization |
| Last-write bookkeeping | `0x1445f11f0` | Bounded leaf: сохраняет EDX в object `+8` |

Начальные 20 байт исторических archive методов дали кандидатов. У string
получились два совпадения, у output constructor — тоже два. Роли не переносились
по общему сдвигу. Table slots вместе с проверенным LEA в constructor выделили
выходную таблицу; похожая base table `0x149670788` не подставлялась вместо неё.
Это поиск кандидатов по историческому коду, не доказательство поведения.

Восемь явных unwind roots получены одним `collect`, byte method — следующим
явным заданием по slot `+0xe0`. Старые exports packet / string / UTF-8 использованы
повторно. Export SHA и bytes двух leaf без unwind root закреплены в
[контексте](../../native-contexts/archive-wire-11316.json).
Автоматического обхода дерева вызовов не было.

## Что исполнено и проверено

[Verifier](../../../verify-archive-wire-context.py) исполняет native constructors,
archive methods, оба полных packet writers, string writer и UTF-8 helpers.
Проверяет полный SHA EXE / exports, table bytes / slots, constructor callee,
прямые и косвенные archive calls, packet-table writer slots и замкнутость leaf.
Harness останавливает неизвестный исполняемый адрес.

45 отдельных archive сценариев проверяют uint8 / bool / uint16 / uint32 /
uint64, raw IO размером 0..4095 байт и inline / heap std::string, включая
встроенный NUL. Подтверждён префикс **uint16 little-endian длина UTF-8 в байтах**,
затем ровно эти bytes, без terminator. Встроенный NUL в std::string копируется
как byte: в отличие от FString helper, archive сам не сканирует NUL.
Bool input `0x80` остаётся byte `0x80`, а не становится `1`.

64 полных packet сценария: Version / Login × четыре варианта исходной памяти
× восемь строковых наборов. Исполняется непрерывная цепочка:
packet writer → FString writer → native UTF-8 → archive string / scalar → raw IO
→ настоящий output buffer. Ожидание строится отдельно по явным полям и struct /
UTF-8; в эмулятор готовые payload bytes не подаются.
Все bytes совпали, в том числе смешанные Unicode, пустые строки, переходы
15 / 16 и 127 / 128 байт, integers со старшими битами и raw bool inputs.
Login bytes дополнительно проходят переносимый decoder / encoder roundtrip.

Проверены counters `+0x34/+0x38`, canaries archive / output / allocations,
неизменность packet и raw input, освобождение временных allocations, семь
nonvolatile registers и восстановление RSP. Native output constructor
исполняется перед каждым случаем, а не заменяется fixture vptr.

Archive получает явный буфер 16 384 байта после constructor. Growth target
`0x1445e4ba0` запрещён hook: его исполнение было бы выходом за scope.
Allocator / free / memcpy / security check остаются bounded fixtures.
Не проверялись реальный allocator, allocation failure, переполнение / growth,
предельная строка 65535 байт, frame / CRC / XOR / sequence, preparation,
response readers и сеть. Успех тела запроса не подтверждает игровой вход.

[Machine report receipt](ARCHIVE-WIRE-11316.json). Прямой прогон занял около
6 секунд; три acceptance tests — 11,793 секунды. Это время участка, не всей
цепочки обновления. Negative tests отклоняют повреждённый export / leaf,
неверный source SHA, подмену table slot и перестановку полей пакета.

## Автоматизация следующего обновления

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-archive-wire-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/archive-wire-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_archive_wire_context.py
```

`native-archive-wire-context` зарегистрирован offline / on_update для обоих
игровых контрактов. Его зависимости включают context, tools, codec, exports
и версии Capstone / Unicorn; повтор без изменения входов использует кэш.
`native-archive-wire-current` в [реестре ориентиров](../../release-update-targets.json)
фиксирует constructor / slots / callees и required check. Поиск нового кандидата
и перенос проверки требуют review; автоматическое продвижение runtime запрещено.
Автоматика не объявляет найденный prefix подтверждённой ролью.

Следующий этап — текущие preparation и result readers Version / Login,
после них lobby catalog / character / world. Полные packet / string / UTF-8 /
archive exports и проверенные тела повторно не извлекать без новых входов.
