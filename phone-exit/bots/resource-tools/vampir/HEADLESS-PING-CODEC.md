# Vampir — реальные байты тела Ping, H03a

18 октября 2026. Продолжение [H02](HEADLESS-PACKET-BINDINGS.md).
Общий [реестр функций](../../vampir/FUNCTION-INDEX.md),
[задачи](../../vampir-headless/TASKS.md). Это offline payload codec,
не сетевой транспорт и не подтверждение живого входа.

## Источник и повторение

Windows EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Windows version unknown; Android parity не установлена. Все адреса — VA,
image base `0x140000000`. Source, offsets, hashes и байты сохраняются в JSON.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-ping-codec.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ping_codec.py -v
```

Вход: `code-clues/headless-packet-bindings.json` и `headless-network-index.json`
в `F:/PhoneExit Resources/Vampir`. Выход: `code-clues/headless-ping-codec.json`;
SHA256 `b38d335947eac5836eb59161fb3656e2f0c3b51b29e42335c808afb2c62b590a`.
Report включает tool/source/upstream hashes, 16 fragments/325 instructions,
6leaf bodies, archive slots, receive/send callsites и test vectors.

## Цепочка приёма и настоящий buffer IO

В Dispatch root `0x14679f510`:

- `14679f52e` читает ID word из входного указателя+3.
- `14679f5d7/5e2` передают body pointer+5 и входной размер−5.
- `14679f5fb` устанавливает пятый аргумент reader constructor в 0.
- `14679f600` вызывает reader ctor `144aa6260`; он через `144aa5850`
  устанавливает source/size/cursor и byte-swap flag+38, затем vptr `14961a520`.
- `14679f618` вызывает packet reader slot+20.
- После успеха `14679f6ad` вызывает handler slot+8. Это слой перед найденным
  в H02 target slot+10; весь wrapper→OnHandler здесь ещё не восстановлен.

Эти инструкции перепроверяются генератором по оригинальному EXE. Размер 5
относится к **входу dispatcher**, не объявляется размером полного wire-header.
Проверки входного размера до вызова Dispatch ещё нужно найти у caller.

| Участок | Адрес VA | Подтверждено |
|---|---|---|
| Reader u64, archive slot+50 | 0x144aa5bc0 | Raw read8; при flag+38≠0 выполняет bswap64 |
| Reader u32, archive slot+58 | 0x144aa59c0 | Raw read4; при flag+38≠0 выполняет bswap32 |
| Raw read, archive slot+90 | 0x144aa5ce0 | Копирует min(available, requested), двигает cursor, возвращает полноту чтения |
| Read bookkeeping | 0x144aa68c0 | Сохраняет фактически прочитанное количество |
| Writer constructor | 0x144aa62f0 | Через 144aa5dd0 создаёт output state, устанавливает vptr14961a5c0 |
| Writer u64, archive slot+b8 | 0x144aa61e0 | Передаёт 8 байт сырого аргумента в raw writer |
| Writer u32, archive slot+c0 | 0x144aa6090 | Передаёт 4 байта сырого аргумента в raw writer |
| Raw write, archive slot+88 | 0x144aa6120 | Проверяет capacity, копирует bytes, обновляет size/counters |
| Write bookkeeping | 0x1445ead30 | Сохраняет количество записанных байтов |
| bswap64 / bswap32 | 0x1445d9f60 / 0x1445d9f30 | Настоящие инструкции bswap в альтернативной reader-ветке |

В отличие от прежних stat experiments, primitive IO **не заменялся stubs**.
Unicorn исполняет packet serializers, constructors, primitive methods, raw
read/write, cursor/counter и swap-код. Единственная замена — внешний
`VCRUNTIME140.dll!memcpy`; импорт доказан PE import table, thunk и IAT.
Shim ограничен выделенной scratch memory и 256 байтами; остальные неизвестные
переходы запрещены, число инструкций ограничено.

Writer state имеет явный заранее выделенный buffer256: native allocation/growth
не исполнялись. Source buffers и конфигурационный аргумент 1 — explicit inputs,
не восстановленное состояние живой сессии. Это не инструкция выделять 256 байт
для всех будущих пакетов. Конструкторы исполняются настоящими инструкциями.

## Формат тела

В доказанной byte-swap=0 ветке значения сохраняются little-endian:

| Тип | Поля объекта по порядку IO | Тело |
|---|---|---|
| PktPing, ID16 | raw64[obj+10], raw64[obj+18] | 16 байт, `<QQ` |
| PktPingResult, ID17 | raw32[obj+10], raw64[obj+18] | 12 байт, `<IQ` |

Операнды не доказывают signedness/названия/epoch/единицы времени. API ядра
принимает unsigned bit patterns, не объявляет их Unix timestamps или кодами
ошибок. Для точных 64 бит не использовать JS Number при будущей передаче в UI.

Native reader принимает лишние байты и оставляет их непрочитанными. На коротком
буфере он возвращает false, но **уже сдвигает cursor и частично пишет объект**.
Переносимый decoder намеренно принимает только заранее отделённое тело точного
размера 16/12; это политика API, не утверждение об идентичной строгости клиента.
Неполное native-состояние при ошибке не превращается в объект персонажа.

## Первое переносимое ядро

`phone-exit/bots/vampir-shared/vampir_core/ping.py`:
`PingPayload(first_bits, second_bits)` и `PingResultPayload(result_bits, value_bits)`,
методы encode/decode. Только стандартная библиотека Python, без ОС/UI/Android/
эмулятора/исследовательской библиотеки. Никакого подключения или heartbeat loop
пока нет. Source SHA указан в модуле; совместимость другой сборки не заявляется.

45 native roundtrips (25Ping/20Result), 32 short/trailing cases, 4swap cases:
всего 126 native packet executions. Значения 0/1, узнаваемые byte patterns,
2^53+1,2^64−1 и u32 maximum сохраняются точно. Пять тестов сверяют все native
vectors с переносимым кодеком, source/fragment/slot bytes и import; дополнительно
повторяют 6 native boundary/failure scenarios. Без skip.

## Что ещё не готово

Найдены реальные output-archive callers: roots `144aa9da0` и `144aaccf0`,
constructor calls `144aa9e56/9e65` и `144aace83/cee3`. Оба используют тот же
output archive; пакет сериализуется через slot+10. Видны запись первых 3 байт
из размера, дополнительные поля, вызовы `1445f1230` и `144aa6ca0`.
Их полная семантика, ключи/режимы и связь с входом dispatcher ещё неизвестны.
Не называть это уже готовым encryption/framing и не отправлять payload напрямую.

Следующий H03b: проследить эти send roots, checksum/transform helpers и
receive path до dispatcher, получить проверенные complete-frame vectors.
Отдельно связать handler slot+8 с OnHandler+10. H03 остаётся частичным:
`framing_verified=false`, `network_ready=false`; игра/аккаунт/сеть не использовались.
