# PktVersion: wrapper → send-B → полная копия кадра в очереди

19 октября 2026. Продолжение [Version writer](HEADLESS-VERSION-PACKET-WRITER.md)
и [send-B](HEADLESS-SEND-B.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-version-send-path.py](replay-version-send-path.py) →
`F:/PhoneExit Resources/Vampir/code-clues/version-send-path-replay.json`.
SHA256: `3105bced4c52519706217c1de58d190efeb567ebbc09a6299b34306311726a0a`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-version-send-path.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report сохраняет source/tool/upstream SHA,
wrapper/send/writer fragments, byte/offset/SHA leaves (thunk, ID, UTF-8,
frame helpers), 18 scenarios и итоговые байты очереди.

## Общий native путь

В отличие от прежнего serializer-only run здесь без остановки на send capture
исполняется цепочка:

`0x1467aaa10 → 0x144aab2f0 → 0x144aaccf0 → writer0x1456e5cf0 → queue0x1445eac20`.

Wrapper вызывает actual packet name getter 0x1456e3a10. Его FString constructor
fixture принимает только source ASCII **PktVersion**, проверяет имя и выдаёт
terminated UTF-16 descriptor. Затем **0x14597e370** (lookup) и **0x141493d10**
(получение metadata pointer) заменены явными captures/fixtures. Если pointer
ненулевой, wrapper записывает byte metadata+0x18 в **packet+0x0a**.
При null pointer packet byte не изменяется. Смысл metadata/байта ещё unknown.

Wrapper заканчивается JMP0x144aab2f0. Его bounded bytes
`488b4910e9f7190000` читают peer из wrapper+0x10 и переходят в
**0x144aaccf0**. Далее реально исполняются pre-frame gates, ID getter,
Version writer/native UTF-8/archive primitives, sequence increment,
CRC32, XOR и native append в очередь. Ни Python layout, ни переносимый encoder
не снабжают этот путь сериализованными байтами.

## Gates и фиксированное окружение

До сборки кадра код проверяет byte global **0x14b520cb4**,
raw return **0x14420a250**, byte peer+0x2a5. Global ненулевой даёт false.
Raw return2 либо ненулевой special byte ведут в общую ветвь отказа.
Она вызывает **0x144aad0a0(peer,0)**, только если peer+0x300 != 1
и special byte == 0. Этот helper capture, его lifecycle/recovery смысл не заявлен.

Global **0x14b520db0** содержит pointer на block, выбранный по predicate calls
0x141489380/0x141489340. Replay явно задаёт первый predicate=true и block
из двух нулевых DWORD; packet-ID filter/logging ветвь не исследована.
Нельзя считать эту конфигурацию значением настоящего клиента или общей
политикой разрешённых пакетов. Diagnostic formatting/metadata lookup fixtures.

Archives получают capacity 4096 после native constructors. Byte queue также
preallocated4096, начинается с пустого NUL sentinel. Growth/failure/capacity
выбор настоящего allocator не проверены. Allocator/free/cookie и bounded CRT
memcpy остаются fixtures, archive cleanup0x144aa6320 — capture.

## Итоговый кадр и владение

Подтверждён формат именно PktVersion в данном send-B пути:

- LE24 total size, затем XOR от offset 3.
- До XOR: CRC32 LE32 от ID16+sequence16+Version body.
- ID1 LE16, sequence LE16, затем [проверенное тело Version](HEADLESS-VERSION-PACKET-WRITER.md).
- Sequence peer+0x240 используется до increment, wrap16.
- Key peer+0x248; fixture0 проверяет fallback, fixture0x1020304050607080 — заданный key.

В 14 успешных сценариях полный ciphertext совпал с независимой сборкой
VersionPayload/struct/zlib/XOR. Есть sequence0/65535, metadata null/present,
wake/no-wake, empty/BMP/emoji и inline/heap строки из предыдущих 14 vectors.
Metadata byte 7 действительно записывается при present fixture, но не меняет
payload в покрытом пути. Другие metadata policies этим не установлены.

Native append делает отдельную копию до возврата wrapper. Replay перезаписывает
4096 bytes временного outer archive значением CC после возврата; queued bytes
сохраняются. Это проверка независимого storage, а не исполнение destructor.
При wake fixture происходит захваченный вызов с peer+0x50 и socket peer+0x110;
фактического scheduler/drain/socket write нет.

Четыре отказа: global-disabled, raw-mode-two, mode-two-already-flag, special.
Все дают false/пустую очередь, не увеличивают sequence, не вызывают writer.
Только mode-two без already flag вызывает failure helper capture.
Отказы allocator, writer/queue failure и concurrent lifetime остаются открытыми.

## Проверки и продолжение

[Три regression tests](../../test_vampir_headless_version_send_path.py)
перестраивают report и проверяют thunk/global bindings, полный порядок native
entries, exact frame bytes, sequence wrap, metadata store, queue/wake counts,
cleanup captures и gates. Runtime не менялся; полный suite379 из предыдущего
runtime milestone не повторялся.
Три новых и шесть смежных tests writer/connected callback прошли.

Входы — snapshots полей прошлых исследований и явные keys/state fixtures.
Полный connected callback/реальные SDK getters сюда не включены. Нет real
Version negotiation, VersionResult, Login, Android parity или server session.
Игра/profile/process memory/credentials/network не использованы.

Далее VersionResult: packet reader/registration/handler → проверка версии и
следующий Login. Отдельно остаются значения weekly version inputs и настоящий
queue drain/socket transport; успешный native append не доказывает получение сервером.
