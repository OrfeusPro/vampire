# Vampir — send-B и владение байтами очереди

18 октября 2026. Продолжение [receive-B](HEADLESS-RECEIVE-B.md),
[send-A](HEADLESS-SEND-FRAME.md), [смены ключа](HEADLESS-KEY-CHANGE.md).
Общий [реестр](../../vampir/FUNCTION-INDEX.md).

## Источник и воспроизведение

Собранный клиент Windows, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA при image base `0x140000000`. Версия выпуска и Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-send-b.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_send_b.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-send-b.json`,
SHA256 `4e627e9ec4527427007e0468646d7510591f3aca85cda96ed3c62032919c0577`.
Source/tool hashes, fragments/instruction/file offsets, leaf bytes/SHA,
packet vtables, 40 входов/выходов сохранены. Зависимости анализа закреплены;
общий код использует только stdlib.

## Native сборка кадра

Исполнен slice `0x144aace6d..0x144aacf89` root `0x144aaccf0`. Он включает
native packet ID getter, archive constructors, writers, sequence update,
CRC32, XOR и возврат из очереди. На выходе Ping имеет 27 байт, KeyChanged — 19.

- Bytes0..2: полная длина LE24.
- Остальное зашифровано повторяющимся LE64 XOR из peer+0x248 (0 → fallback).
- После XOR внутри: CRC32 LE32 от ID16+sequence16+body; затем ID16,
  sequence16 и body. Plain offsets: CRC+3, ID+7, sequence+9, body+11.
- Sequence берётся из peer+0x240 на `0x144aace99` и увеличивается с wrap 16.
- Ping ID16/body16 и KeyChanged ID12/body8 используют исходные vtables
  `0x1498d66c0` / `0x1498d5e90`, настоящие ID getters и writers.
- Key читается на `0x144aacf36`, XOR вызывается на `0x144aacf63`.

Размер/CRC/ID/body совпадают с send-A, но поля состояния peer и ключ иные.
Это исходящий формат; его нельзя использовать вместо асимметричного
receive-B length 3/ID2/body. Ни Login, ни произвольный packet writer не заявляются.

## Копирование в очередь

После XOR call `0x144aacf7d` вызывает `0x1445eac20(peer, frame, size)`.
Тот синхронно вызывает append `0x1445e4a90` для peer+0x170.
Byte vector: peer+0x178 begin, +0x180 end с NUL sentinel, +0x188 capacity.
Native resize `0x1445de6e0` и настоящий append loop исполняются с заранее
выделенной capacity; внешний CRT memcpy ограничен shim.

Append заменяет старый sentinel, копирует все ciphertext bytes, пишет новый
sentinel и возвращается. Поэтому очередь владеет отдельной копией **до** возврата
send-B. После slice тест перезаписывает archive source байтами CC и меняет
peer key: очередь остаётся прежней. Это проверка ownership, не реальная смена
ключа сервером. Сам archive destructor за END не исполнен; его место
`0x144aacf89` известно по исходным инструкциям.

Если peer+0x108==1 и peer+0xc0==0, очередь вызывает virtual slot+0x20 у peer+0x50
с аргументом peer+0x110. Wake callback заменён capture/return с проверкой args.
Эта ветка и ветка без wake проверены. Значение полей не объявляется полностью
восстановленным состоянием socket. Реальный scheduling/drain/socket write неизвестны.

40 native сценариев: 4 test keys × 5 sequences (0/1/255/256/65535) × 2 packets.
Во всех перед очередью есть prefix; чередуются wake/no-wake. Дополнительный replay
проверяет pristine begin==end и последующее добавление Ping после ack/key variant.
Векторы сравниваются с независимой сборкой CRC/XOR/struct, не подменяющей native.

Preallocated archives после настоящих ctor получают explicit capacity/buffers;
archive flags заданы 1. Аллокатор growth/failure, drain и связь всего Notify handler
через handle/send virtual call с этим slice ещё не исполнены вместе. Предыдущий
handler replay доказывает send-before-key-set, этот — synchronous copied bytes.
Их совместимость не объявляется полным Notify→wire proof.

## Переносимое ядро и локальная политика

`send_frame.py` дополнен `encode_ping_frame_b` и `encode_key_changed_frame_b`:
явные sequence16/key 64, общий encoder CRC/ID/sequence/body, immutable bytes.
У ack payload содержит новый ключ, а аргумент key_bits — текущий ключ соединения.
Существующий send-A helper сохранён с прежним контрактом.

`outbound.py:OutboundFrames` — лёгкая очередь для одного владельца будущей сессии:
обязательные byte/frame budgets, immutable frames, sequence wrap, pop без копии.
`acknowledge_key_change` сначала ставит ack под старым ключом в очередь, затем
меняет ключ следующих кадров. Repr скрывает ключ. Это не сетевой transport.

При переполнении BufferError оставляет key/sequence/очередь прежними. Это явная
локальная политика строже native handler, который меняет ключ даже при false
результате send. Session owner должен обработать ошибку; автоматического retry
или продолжения соединения здесь нет. Не скрывать отличие при live интеграции.
Класс предназначен для одного event-loop owner, не thread-safe очередь.

Пять тестов сверяют provenance, все native frames, copy/wake replay,
старый ключ ack/новый ключ следующего кадра, wrap, byte/frame backpressure,
атомарность локального отказа и освобождение budget при pop.

Далее: drain/socket transport и первичная авторизация, session/key transition
end-to-end, таймауты/закрытие/error paths. Игра, аккаунты и сеть не использовались.
`network_ready=false`; live работа бота и полная сессия не заявляются.
