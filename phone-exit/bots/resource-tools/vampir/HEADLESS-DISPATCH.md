# Vampir — Dispatch до входа в OnHandler

18 октября 2026. Продолжение [listener loop](HEADLESS-LISTENER-LOOP.md).
Общий [реестр](../../vampir/FUNCTION-INDEX.md), [задачи](../../vampir-headless/TASKS.md).

## Источник и воспроизведение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA при image base `0x140000000`; версия Windows и Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-dispatch.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_dispatch.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-dispatch.json`:
SHA256 `d0db813874494cf8da7edb77fded572505f8e1da2554b7b24ad625296859a20b`.
Содержит source/tool hashes, Dispatch/OnHandler fragments с file offsets,
отдельные leaf bytes/SHA, handler vtable и 24 входа/выхода.

## Что исполнено

Настоящий второй receive loop и receive-A wrapper вызывают `0x14679f510`
вместо capture callback предыдущего этапа. В Dispatch задана synthetic registry
с одной bucket/node: ID17 → native PingResult object → handler object.
Регистрация ID/type/handler в настоящей game factory доказана ранее в
[packet bindings](HEADLESS-PACKET-BINDINGS.md), но сама factory здесь не исполняется.
Receive-A используется как изолированный вход в Dispatch; это не доказательство,
что живая game session использует A вместо ранее найденного B.

- Dispatch читает LE16 ID из frame+3 на `0x14679f52e`, вычисляет hash и ищет
  запись. Неизвестный ID идёт в diagnostic path, обработчик не вызывается.
- На `0x14679f600` создаёт настоящий reader archive: source=frame+5,
  size=frame_size−5, swap=0. Native PingResult constructor `0x1456d5060`
  исполнен перед каждым replay; reader `0x1456d8600` вызывается через slot+0x20.
- При успехе dispatcher+0x48 временно содержит packet pointer; TLS context
  устанавливается настоящим setter `0x144aa6240` в TLS block+0x100cc0.
- На `0x14679f6ad` вызывается handler slot+8. Vtable `0x149d810f8` содержит
  wrapper `0x141535f20`: bytes `488b0148ff6010`, то есть
  `mov rax,[rcx]; jmp qword ptr [rax+0x10]`.
- Slot+0x10 ведёт на PingResult OnHandler `0x1467670c0`. На входе проверяются
  handler/context/packet arguments, разобранные result32/value64, active pointer
  и TLS. Затем capture shim возвращает управление без игровых побочных действий.
- Исполняются возврат, native TLS reset, очистка dispatcher+0x48, reader archive
  destructor chain `0x144aa62a0→0x144aa58f0→0x144aa6560→0x144aa6520` и epilogue.

Тот же wrapper pointer статически найден в пяти уже связанных handler tables:
LoginResult, PingResult, CharacterListReadResult, CharacterSelectResult,
LobbyLoginResult. Их игровые OnHandler и payload схемы этим replay не проверены.
ID нельзя использовать как глобальный тип без lobby/game context.

## Проверки и границы

24 native сценария: 8 успешных (4 пары result/value, включая максимальные bits,
с extra bytes и без), все 12 коротких длин 0..11, неизвестные IDs 0/16/18/65535.
Ни короткое тело, ни неизвестный ID не вызывают OnHandler; принятый transport
кадр при этом потребляется. После всех сценариев active packet/TLS очищены.
Дополнительные mixed replays проверяют повторное использование после ошибки.

Snapshot/container lifecycle fixtures и CRT memory shims унаследованы из
предыдущего harness. Registry/TLS index0/archive flags0 заданы явно. Для TLS
выделена отдельная область, поскольку slot context находится после 1 MiB.
Security cookie check заменён shim с проверкой ожидаемого аргумента; unknown-ID
logger сохраняет только synthetic ID. При reader=false диагностическое создание
строк пропускается на `0x14679f61f`, исполнение возобновляется на `0x14679f694`:
реальные cleanup и return остаются. Сам diagnostic allocation/error logging
этим не проверены. Native OnHandler побочные действия исключены, не эмулируются
фиктивным обновлением мира. Это не готовая авторизация или сессия.

В исполненной успешной ветке Dispatch нет проверки CRC и нет проверки, что
reader исчерпал весь body: native допускает trailing bytes. Это наблюдение
относится к указанной ветке, не доказывает отсутствие integrity в receive-B
или других стадиях. Server→client layout не отождествляется с send-A layout.

## Общий код и продолжение

`vampir-shared/vampir_core/receive_packet.py:decode_game_ping_result` принимает
ровно один receive-A кадр ID17 и возвращает PingResultPayload. Максимальный
frame size обязателен. Короткий вход, чужой ID, extra frames и trailing body
отклоняются. Exact body12 — явная локальная политика строже native reader.
Только stdlib; нет запуска игры, sockets или дублирования ядра по ботам.
Четыре теста сверяют исходные bytes, все vectors, native mixed replay и общий decoder.

Далее: receive-B/integrity/layout, send queue и первичная авторизация; затем
настоящие изменения состояния персонажа. Полный native lifecycle/listener
concurrency и диагностические ошибки остаются отдельными непроверенными ветками.
Игра, сеть и аккаунты не использовались. `network_ready=false`.
