# Vampir — длина входящего кадра и связь с dispatcher

18 октября 2026, H03b.2b, частичный результат. Начинать с [общего реестра](../../../../../vampir/FUNCTION-INDEX.md).
Предыдущие этапы: [send frame](HEADLESS-SEND-FRAME.md), [CRC/XOR](HEADLESS-FRAME-PRIMITIVES.md).

## Источник и повторение

Compiled Windows client `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса VA, image base0x140000000. Windows version/Android parity unknown.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-receive-envelope.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_receive_envelope.py -v
```

Выход: `F:/PhoneExit Resources/Vampir/code-clues/headless-receive-envelope.json`,
SHA256 `bb3d9ff7c93420f74fead019b52beca765b8eb43c3d98c94c34e50f5cb49a382`.
Report: source/tool hashes, 18 fragments/19152 instructions, length leaf,
vtable/constructor/setter/callback proofs, 156probe vectors и 13wrapper vectors.
Файлы общей библиотеки/инструменты не входят в runtime.

## Длина и ограничения

Leaf `0x144aa9a90` получает buffer в R8 и available в R9D.
Если signed available<5, возвращает 0 **без чтения входного буфера**.
Иначе собирает little-endian24 из bytes0..2 и возвращает его, если declared≤available,
иначе 0. Проверены 156 пар declared/available, включая 0..6,17, 255/256,
65535/65536 и 0xffffff; memory-read hook контролирует ранний выход.
Available — явный экспериментальный аргумент; реальные размеры socket-buffer
и лимиты транспортного слоя ещё не восстановлены.

Важно: при available≥5 функция допускает declared1..4, возвращая их.
Это не доказательство отсутствия проверки выше по стеку. Нулевой declared
неотличим от «ещё нет полного кадра» по одному returnvalue.
Не переносить эту неоднозначность в будущий цикл, который может зациклиться.

Общий `vampir-shared/vampir_core/receive_frame.py`:
`peek_receive_frame_size(buffer, *, max_frame_size)` возвращает None, пока
недостаточно данных, затем размер первого кадра (включая случай нескольких
кадров в buffer). Не потребляет/не изменяет bytes. Локальная политика строже:
declared<5 иdeclared>явного лимита дают ValueError. Лимит обязателен, минимум 5,
максимум 24bit; это бюджет приложения, не найденный maximum сервера.
Ни CRC, ни ключ, ни ID/body этот helper не разбирает.

## Vtable и wrapper

| Путь | Ctor root | Subobject | Vtable | Length slot+38 | Receive slot+40 |
|---|---|---|---|---|---|
| A | 0x144aa8ac0 | main+200 | 0x14961af58 | 0x144aa9a90 | 0x144aa9c00 |
| B | 0x144aab540 | main+200 | 0x14961b8f0 | 0x144aa9a90 | 0x144aacb50 |

В report сохранены LEA/store constructor и table bytes: это общая длина для
двух peer implementations, а не случайное совпадение имени. Роль slot+38 как
проверки длины следует из leaf behavior; caller транспортного цикла отдельно
не восстановлен.

WrapperA исполнен на 13 буферах длиной 0..512. При length<3 возвращает без
callback; иначе настоящий nativeXOR меняет bytes от offset 3 и готовит callback.
Исполнение останавливается на инструкции call `0x144aa9c42`, **до входа в callback**:
object/context pointers заданы синтетически. Проверены RCXcallback object,
RDXcontext, R8 исходный pointer, R9 прежняя длина. CRC в этой функции не вычисляется;
это не доказательство отсутствия integrity validation во всём transport.
Проверены также короткие frames3/4, даже хотя length probe ждёт available5.

## Статическая связь B→Dispatch

В root `0x1467aa0e0` call `0x1467aa2ae` создаёт factory `0x14678ec40`,
её result передаётся setter `0x144aab300` через call `0x1467aa2bc`.
Setter: peer=[handle+10], peer+238=dispatcher argument. Его точные 12 байт
закреплены и перепроверены; аргументы RDX/RDI и RCX/RBX подтверждены.

Factory записывает vtable `0x149d80538`; её slot+8 равен `0x14679f510` (Dispatch).
WrapperB получает subobject main+200, читает callback из subobject+38=main+238
и вызывает callback slot+8. Получается подтверждённая статическая цепочка
factory→setter→peer field→wrapper callback→Dispatch. Полный end-to-end native
replay этой цепочки ещё не выполнен, состояния и ключи живой сессии не получены.

## Что ещё неизвестно

В network-range найден setter candidate `0x144aab330`: он читает[source pointer]
и пишет peer+248 через handle+10; pointers на entry существуют в 0x14961b780 и
0x149d84e90. Прямые E8-callers не найдены. Пока **не доказано**, кто вызывает
его, как получены 64 бит и каков их lifetime. Это кандидат для продолжения,
не готовый authentication/key-exchange flow; в верифицированный runtime не включён.

Не восстановлены транспортные maximum/буферизация, весь входной layout,
CRC enforcement, caller length probe и slot+8→OnHandler+10. Связь с send header
не угадывать: Dispatch видит ID+3/body+5, send-A имеет ID+7/body+11.

6 tests прошли: native bytes/hashes/static linkage scope, все vectors,
строгая local policy и 7 дополнительных native replays. Следом — получить
caller длины/transport frame pipeline и источник ключа. `full_receive_verified=false`,
`network_ready=false`; игра/аккаунты/сеть не использовались.
