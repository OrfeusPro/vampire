# ID109: реальные callers, источники полей и кадр

20 октября 2026. Продолжение [ID102 body/handler](HEADLESS-CHARACTER-LIST-EXTENSIONS.md).
Два native пути теперь доведены до настоящих writer/framing/queue:
WaitingEndNotify и выбор записи по UI index. Сеть и реальная сессия не использовались.

## Происхождение и воспроизведение

Код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 109 функций, 58 warnings. Экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-bee1a57a6b1a`.
Manifest SHA256 `29f29b1dde4e4c5c4071bef35638adfae211695a86c5400af0b97fcae2ea1018`.
Имена аналитические, псевдокод не является исходным C++ проектом.

В `F:/PhoneExit Resources/Vampir/code-clues/`:

| Отчёт | SHA256 | Что проверено |
| --- | --- | --- |
| character-state-callers.json | `ffa067ef9ab0a27b1de00d222c7663b9a0decb089d5105da946562f33b56b7ee` | 105 validated E8 calls к state getter; 15 близких +f0 candidates, 0 unresolved/decode failures |
| character-state-f0-replay.json | `d8a481b03c0fb114d876348b9b2a2d92e22318e1027ace965d3eacf38606535b` | 45 ID102→handler→actual setter cases и 12 setter transitions |
| character-select-send-replay.json | `bca70b53997dd6ecb7ceeb8b54e12ff68c56cf1388e15cbb7ce0af8a4e3f567c` | 27 WaitingEnd и 34 indexed caller cases, 19 полных кадров |

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-character-state-callers.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-state-f0.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-send.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_character_select_send.py -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_character_state.py -v
```

Проверки: 24 character tests и 3 Ghidra provenance tests прошли. Новые тесты
повторяют scanner/native reports, сравнивают кадры с общим codec и проверяют
source/index/duplicate/refusal/persistence boundaries.

Scanner повторно использует существующий validated E8/unwind scanner. Он не
доказывает полный graph: indirect/tail calls и inline global accesses не покрыты.
Близкий operand +f0 может относиться к другому объекту или stack frame.
Конкретные связи ниже проверены отдельно, а не выведены из близости инструкции.

## Raw20: ID102 → state+f0 → ID109

Getter `0x145c859f0` читает global `0x14b57f180`. Это state с records+70,
count+78 и raw+f0; его нельзя отождествлять с другими globals по близким offsets.

ID102 handler `0x14675dce0` передаёт packet+40 в `0x145c930d0`.
Actual setter всегда записывает аргумент в this+f0. Если прежнее значение не0
и отличается от нового, перед store выполняется persistence path через
`0x145c860c0`/`0x1445d0530`; эти внешние действия — captures.
45 full body→handler cases теперь исполняют setter, заменяя прежний capture.
12 дополнительных переходов проверяют ноль, повтор, изменение и uint64 max.

Selection service virtual50 `0x145dc05f0` читает тот же state+f0 и записывает
его в ID109 packet+20. Это устанавливает происхождение, но не имя поля.
Дополнительный UI action caller `0x145f434a0`, case9, также вызывает setter;
он экспортирован статически, его полный UI/persistence flow не исполнен.
Поэтому rawF0 является текущим состоянием, а не неизменяемой копией ID102.

## WaitingEndNotify path

Actual handler `0x146768540`, predicate `0x145c85d90`, quick helper
`0x145d46400` и real derived table `0x1499f11f0` исполняются вместе.
Доказанные ветви при покрытых policy values:

| Peer flag | Policy | Действие |
| --- | --- | --- |
| 0 | 0 и stored raw+28 не0 | helper → service virtual50; ID109 raw10 = stored+28 |
| 0 | 0 и stored raw+28 равен0 | service virtual40 continuation (capture) |
| 0 | 1/2/4 | return, без ID109 |
| 1 | 0 | virtual40 continuation (capture) |
| 1 | 1 | actual RequestB → ID101 writer/frame/queue |
| 1 | 2/4 | service virtual50; ID109 raw10 = notify+10 |

Disabled/missing policy object возвращает native fallback4. Lookup/type objects
и policy virtual являются fixtures; значения enum не названы по догадке.
Stored+28/notify+10 здесь raw inputs; реальное получение notify после Login и
жизненный цикл сохранённого значения не доказаны.

## Выбор записи по индексу

В прежнем caller scan обнаружен tail **jmp**, а не call, в `0x145d43309`.
Root `0x145d43290` экспортирован как CharacterSelect_StoredCaller.
Он проверяет global flag, UI lookup/type metadata, читает signed UI+3f8 и
вызывает leaf `0x145c847c0`.

Leaf проверен инструкциями и native исполнением: отрицательный EDX либо
EDX>=global-state+78 дают null; иначе возвращает state+70 + index*0x170.
Он читает тот же global `0x14b57f180`, а не массив внутри UI object из RCX.
Его диапазон 34 байта включает оба RET и обе ветви signed bounds check.
Caller при nonnull результате передаёт record+8 в service virtual50.
Таким образом ID109 raw10 связан с полем записи, ранее использованным для
preferred index в ID102 handler. Название CharacterId отдельным символом не доказано.

34 сценария покрывают 0/1/3/4 записи, index -1/first/middle/out-of-range/int32 max,
нулевой/максимальный record key, отсутствие UI, type mismatch, global disable,
duplicate request и transport refusals. UI objects/type metadata/records — fixtures;
реальный UI event emitter и загрузка экрана не воспроизводились.

## Поля, handoff и кадр

Для обоих covered caller paths:

- raw10 — выбранный выше raw64; native virtual50 переносит его в packet.
- raw18 — uint32 constant `0x14961a380`, фактическое значение **0**.
  Сам virtual50 принимает произвольный raw32; это не универсальное ограничение ID109.
- raw20 — текущий state+f0; initial accepted ID102 присваивает его из packet+40.

Далее actual constructor → handoff `0x144aa8020` с kind110 → actual wrapper
`0x1467aaa10` → lower sendB → actual writer `<QIQ`/20 bytes → CRC32/XOR/queue.
Kind110 не подменяется отправляемым packet ID109. Handoff выполняет pending lookup
и duplicate/collision traversal, выбирает default timeout для переданного0,
вызывает insert/notify captures до virtual send. Duplicate110 останавливает отправку.

19 полных кадров: 11 из WaitingEnd cases (9 ID109 + 2 ID101) и 8 indexed ID109.
Проверены fallback/явный XOR key, seq65535 wrap, wake, metadata byte и owning copy.
Каждый frame побайтно совпал с переносимым body codec, CRC32 и XOR:
LE24 length + XOR(LE32 CRC32 + LE16 ID + LE16 sequence + body).
Disabled/mode2/special и duplicate cases не вызывают writer/queue и не меняют sequence.

Request insert/notify не мутируют настоящий pending store. Metadata/name/allocator/
cleanup/wake и UI/base helper действия захвачены. Queue/archive capacity4096,
без growth; drain/socket/timeout expiry/session lifecycle не входят в эти проверки.
Indexed cases используют native state snapshot предыдущего ID102 replay, а не
один непрерывный run от ID102 body до ID109 queue. Это граница интеграции.

## Общий builder

`CharacterSelectPayload.from_character_list(body,index, state_raw_f0=...)`
использует record.u64[0], constant0 и явно переданный текущий rawF0.
Первоначальный rawF0 можно взять из принятого body.tail[3]; последующие изменения
должны обновлять состояние клиента через доказанные setter/result paths.
Builder не молча подставляет старый body.tail[3] после изменения состояния.

Локальные preconditions: decoded list с code0 и существующий integer index;
bool/negative/empty/out-of-range/error list отвергаются. Session/policy/readiness
проверяет вызывающий session owner. Здесь только immutable payload, без I/O,
автоматической отправки или утверждения, что персонаж выбран на сервере.

## Продолжение

Далее ID110 nested body/handler, состояние после выбора и источник позиции;
owner slot7b0→engine lifecycle/загрузка CharacterSelect_02; real SDK/device context
и подтверждение устройства. Реальная сессия и runtime reconnect ещё открыты.
Не называть эти offline replays работающим входом на аккаунте или готовым ботом.
