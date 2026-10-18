# Vampir — CRC32 и XOR внешнего слоя, H03b.1

18 октября 2026. Продолжение [Ping payload](HEADLESS-PING-CODEC.md).
Общий [реестр](../../vampir/FUNCTION-INDEX.md), [компоненты](../../vampir-shared/README.md).
Подтверждены отдельные алгоритмы кадра, не весь транспорт.

## Источник и повторение

Windows compiled client `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса — VA, base0x140000000; Windows version/Android parity unknown.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-frame-primitives.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_frame_primitives.py -v
```

Вход: `F:/PhoneExit Resources/Vampir/code-clues/headless-ping-codec.json`.
Выход: `code-clues/headless-frame-primitives.json` в общей библиотеке,
SHA256 `3dd125f16da9922e14247ba16e96c74dce6253dcb82f88b8e63ddfd92f15a8d5`.
Сохранены source/upstream/tool SHA, 8caller fragments/453 instructions,
3helper bodies, CRC table и native vectors. Helper entries подтверждены
direct E8 из полностью декодированных caller fragments, не догадкой о прологе.

## Подтверждённые алгоритмы

CRC initializer `0x1418ba360` записывает state0xffffffff. Update `0x1445f1230`
читает каждый byte, index=(state XOR byte)&255,
state=(state>>8) XOR table[index], возвращает NOT(state). Таблица
`0x1495046f0` полностью совпала с независимой генерацией 256dword по
reflected polynomial0xedb88320; настоящий LEA на table закреплён.
Это CRC32: empty→0, ASCII123456789→0xcbf43926. Native state хранится без
финального complement. Общий `payload_crc32(bytes)` пока one-shot, через zlib.

XOR helper `0x144aa6ca0`: RCX=source, EDX=signed length, R8=destination,
R9=key. При key 0 выбирается встроенная constant0x9ab378c9d02084a7;
байты ключа a7 84 20 d0 c9 78 b3 9a. Для положительной длины:
destination[i]=source[i] XOR little_endian(key)[i&7]. Возвращается EDX,
при length≤0 loop пропускается. Общий API принимает bytes/unsigned64 key,
отрицательную длину не моделирует. Повторное преобразование тем же ключом
восстанавливает bytes; это маскирование, не доказательство криптозащиты.
Встроенный fallback не является найденным секретом аккаунта/сессии.

## Callers и ограничения

| Путь | Root VA | Подтверждено |
|---|---|---|
| Send A | 0x144aa9da0 | CRC init0x144aa9ec2/update0x144aa9f00; XOR0x144aa9f40 с key 0 |
| Send B | 0x144aaccf0 | CRC update0x144aacf1c; XOR0x144aacf63 с key из[R14+248] |
| Receive A | 0x144aa9c00 | size guard≥3; XOR0x144aa9c2c с key 0; callback slot+8 |
| Receive B | 0x144aacb50 | size guard≥3; XOR0x144aacb83 с key из[RCX+48]; callback slot+8 |

Во всех четырёх путях XOR начинается с buffer+3 и длины size−3.
Receive wrappers затем передают буфер и прежний размер callback; его конечный
target ещё не связан с Dispatch. В B также читается word из buffer+3 и вызываются
 0x144aa7c40/0x144aa8120. Guard≥3 не доказывает достаточной проверки до чтения word.

Send roots показывают IDword, ещё word, packet writer, первые 3 байта размера,
4 байта CRC, внутренние данные и XOR от offset 3. Это наблюдение инструкций,
не готовый frame encoder: точный контракт length, второго word, ошибок/лимитов,
receive validation и происхождение session key ещё исследовать.
Не смешивать внешний слой с 5 байтами перед body на входе Dispatch из H03a.

## Исполнение и общий модуль

Настоящие CRC init/update и XOR исполняются в Unicorn **без shims**,
code ranges/buffer sizes/instruction budgets ограничены. Проверены 21CRC cases,
210XOR cases: 252 native executions с init. Включены selected lengths0..512,
границы 7/8/9,255/256/257, все 256 значений byte, fallback/explicit keys,
точное in-place и disjoint buffers; sentinel контролирует границу записи.
Частичное перекрытие буферов не заявляется.

Общий код: `vampir-shared/vampir_core/frame_primitives.py`, stdlib functions
payload_crc32/xor_transform. 5 tests сверяют original bytes/SHA, все vectors,
известный CRC vector, fallback/key order; дополнительно 24 native replays.
Эмулятор и proof library не входят в runtime.

Следом H03b.2: complete frame bounds/integrity/context, key source,
receive callbacks→Dispatch и handler slot+8→OnHandler+10.
`full_frame_verified=false`, `network_ready=false`; игра/сеть/аккаунты не использовались.
