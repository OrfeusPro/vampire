# Сервис выбора: derived slots и CharacterSelect handoff

19 октября 2026. Продолжение [WaitingEndNotify](HEADLESS-WAITING-END-CHARACTER-REQUEST.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

По native getter **0x1456048e0** установлен global **0x14b574a90**.
Проверенная запись global находится в constructor **0x1455f9ee0**.
Его единственный найденный direct-call candidate **0x145dc6b54** подтверждён
декодированием; caller root **0x145dc6b20** создаёт derived service.
Сначала прочитан Ghidra export обоих constructors и virtual targets.
Названия `SelectionService_*` — аналитические метки, не исходные C++ имена.

Ghidra пакет: 43 функции, 30 warnings, run `run-cf016ca2fa40`.
Общий индекс: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Warnings сохранены; типы/virtual signatures псевдокода сверяются с инструкциями.

[replay-selection-service.py](../../../replay-selection-service.py) →
`F:/PhoneExit Resources/Vampir/code-clues/selection-service-replay.json`.
SHA256: `d1ef47c49f69c2923de3afe802a19ded5d6e9187c5fb50c6c4f3dbd13681b790`.
Report сохраняет source/tool/upstream SHA, PE fragments/bytes/file offsets,
constructor/getter/ID leaves, vtables, initialization outcomes и 4 select cases.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-selection-service.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_selection_service.py
```

## Constructor → singleton → derived table

Исполнен actual prefix **0x145dc6b20..0x145dc6bfa** с остановкой до
первого owner attach helper **0x145da6850**. Он запрашивает allocator 0x1b0,
реально вызывает base constructor, ставящий global и base table **0x1498b67c0**,
затем actual инструкции меняют table на **0x1499f11f0**.
Подобъектам ставятся tables **0x1499f12c8**/+8 и **0x1499f12d0**/+0x28.
Allocator и member-init helper **0x144280630** — bounded fixtures.
Объект allocator заполнен 0xa5; не предполагается полное нулевое заполнение.

Actual getter после prefix возвращает этот service. Attach arguments сняты
до вызова: owner+8 и constructed service. Остальной большой constructor
не выполняется. В отдельном allocation-failed case attach получает null,
а global сохраняет прежний fixture pointer: prefix его не обнуляет.
Это не доказательство полного failure recovery или реального singleton lifetime.
Global находится в BSS; bytes из файла для него не выдумываются.

| Derived table slot | Actual target | Подтверждение |
| --- | --- | --- |
| +0x40 | 0x145dbba60 | Ghidra и actual table bytes, исполнение ещё не выполнено |
| +0x50 | 0x145dc05f0 | Ghidra + 4 native handoff cases |
| +0x90 | 0x145dbd4b0 | Source table binding, прежний independent requestA replay |

Таким образом function pointer **0x1499f1280** из прежнего исследования —
**slot+0x90 table 0x1499f11f0**, а не самостоятельная callback registration.
Owner-type slot установлен constructor evidence. **Caller slot+0x90 пока
не найден**; эта связь ещё не доказывает обычный Login→requestA переход.

## Virtual+0x50 → PktCharacterSelect

Actual **0x145dc05f0** получает this/raw64/raw32. Последовательность:

1. Helper **0x145610ab0** получает this, raw64 и constant **0x14961a380**.
   Backend capture; переданный helper raw32 отличается от аргумента packet.
2. Actual constructor **0x1456d4850** создаёт packet с vtable **0x1498d87d0**.
3. Native stores: raw64 argument → packet+0x10, raw32 argument → packet+0x18,
   `[getter 0x145c859f0 result+0xf0]` → packet+0x20.
4. Request-manager getter **0x144aa7c40** — fixture. Вызов
   **0x144aa8020** получает packet, kind 110, opaque raw64 из
   **0x14961a378** и float timeout 0. Handoff здесь capture.
5. Cleanup helper — capture; функция доходит до return.

ID getter из [packet bindings](../network/HEADLESS-PACKET-BINDINGS.md) реально исполнен:
**109**. Kind 110 отдельный handoff argument, не ID отправляемого пакета.
Все raw поля остаются raw: не названы CharacterId/slot/locale/session key без
отдельного consumer evidence. Семантика state+0xf0 не установлена.

4 cases: zeros, ones, unsigned maxima и distinct raw bits. Проверяются
точные arguments, packet vptr/fields, timeout/opaque argument и cleanup.
Actual prefix и actual selection выполнены последовательно, но полный
WaitingEndNotify run здесь не объединён с настоящей derived table.
Его прежние virtual captures теперь имеют source-bound implementation targets.

## Virtual+0x40: следующий участок

Ghidra **0x145dbba60** показывает SDK-dependent guard, base helper
**0x14560a6f0**, затем virtual+0xc8 и helper **0x14560a400** с raw value 2.
Это source-derived static finding; virtual+0xc8, guard backend и переход
к requestA ещё не исполнены. Не считать virtual+0x40 отправкой списка
персонажей по сходству назначения. После проверки этих звеньев искать
реальный вызов slot+0x90 либо опровергнуть предполагаемую связь.

[Три новых tests](../../../../../test_vampir_headless_selection_service.py), три смежных
WaitingEndNotify и три Ghidra tests прошли. Full suite не повторялся.
Общий runtime не менялся; network/game/profile/process memory/credentials/
Android не использованы. Writer/frame/socket/ответ ID 110 и подтверждение выбора
ещё открыты. Живой вход/session/персонаж не объявляются готовыми.
