# После LoginResult: сброс состояния и отдельный запрос персонажей

19 октября 2026. Продолжение [LoginResult handler](../network/HEADLESS-LOGIN-RESULT-HANDLER.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Ghidra сначала экспортировала constructor global-object **0x14647f9f0**,
затем virtual target **0x1464846c0** и два request entrypoints.
Общий `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md` теперь содержит
37 функций, 19 warnings. Run: `run-ae9c769e083a`. Старые exports сохранены.
Аналитические метки `LoginContinuation_*` и `CharacterList_RequestA/B`
не являются восстановленными именами исходного C++ проекта.

[replay-character-list-boundary.py](../../../replay-character-list-boundary.py) →
`F:/PhoneExit Resources/Vampir/code-clues/character-list-boundary-replay.json`.
SHA256: `e46d85a7bd725216734457d5be8e0c97b2b8773ca291ec23f43e195ed5b478c9`.
Report содержит source/tool/upstream SHA, PE fragments, bytes/file offsets,
getter/constructor/ID/writer leaves, vtable anchors и native результаты.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-boundary.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_character_list_boundary.py
```

## Virtual+0x28 после LoginResult

Handler вызывает getter **0x146486a50** и virtual+0x28. Getter реально читает
global **0x14b58b930**. Constructor **0x14647f9f0** пишет this в этот global,
сначала устанавливает base vtable **0x149c5f7f8**, затем derived
**0x149c5f828**. Derived slot+0x28 равен **0x1464846c0**.
Байты таблицы и native constructor/getter проверены. В эмуляции объект новый,
профиль и память работающей игры не читаются.

Actual virtual target сбрасывает counts/indices/flags нескольких коллекций,
выбирает clear/shrink paths, обнуляет object+0x308 и global **0x14b57ecd1**,
ставит final fields+0x338/+0x33c. Это подтверждённое действие сброса;
прямого вызова CharacterListRead constructor/send в target нет.
Backend container helpers captured, поэтому их полные эффекты не заявлены.

8 native scenarios: исходный уровень count/refcount fields 0/1/2/5 и
capacity 128/256. При level>1 соответствующие поля становятся 1, иначе
сохраняют 0/1; capacity>128 сбрасывается до 128 и вызывает shrink capture.
Indices+0x248/+0x298/+0x2e8 становятся 0xffffffff. Проверяются точные stores
и выбранные helper calls. Реальные контейнеры/allocator здесь не исполняются;
непустые массивы объектов и их destructor loops отдельно не покрыты.

Важно: это отдельный constructor→reset replay. Предыдущий LoginResult replay
достигал virtual call, но новый reset не встроен в тот же handler run.
Связь таблицы/source подтверждена статически и отдельным native исполнением.

## Два самостоятельных request entrypoints

По уже сохранённым constructor callsites из
[packet bindings](../network/HEADLESS-PACKET-BINDINGS.md) найдены и декомпилированы:

- **0x145dbd4b0**: helper **0x14560dd00**, затем packet constructor/send;
- **0x145dbfe50**: packet constructor/send без первого helper.

Обе функции реально вызывают constructor **0x1456d4780**, native singleton
getter **0x144aaa9d0** и virtual send+0x38 с построенным PktCharacterListRead.
Native ctor ставит vtable **0x1498d84d8**, byte+0xa=0. Send — capture,
проверяющий this/packet/vptr, затем native routine идёт через diagnostic/
cleanup captures до return. Helper 0x14560dd00 не переименован без отдельной
проверки его поведения.

Actual ID getter возвращает **101**. Writer slot+0x10 указывает на leaf
**0x140bb4a10**: `mov al,1; ret`. Он исполнен с packet/archive arguments;
archive не меняется. Следовательно, этот writer не добавляет bytes тела.
Это усиливает прежнюю static-only запись о совпавших reader/writer targets.
Transport header/ID/sequence/CRC/XOR в понятие тела не входят.

Request routines, reset и writer leaf проверены отдельными прогонами.
Frame/send/queue/socket для ID 101, actual response ID 102, выбор персонажа
и связь вызывающего кода с завершением Login ещё не проверены.
Одинаковый singleton transport не доказывает порядок вызовов.

## Проверки и следующий участок

[Три новых tests](../../../../../test_vampir_headless_character_list_boundary.py)
воспроизводят report, проверяют source/table/getter bindings, все 8 reset
scenarios, 2 request entries, ID 101 и unchanged archive. Четыре смежных
LoginResult handler и три Ghidra tests пройдены. Runtime не менялся,
полный suite не повторялся. Game/profile/process memory/credentials/network/
Android не использованы.

Далее искать **callers этих request entrypoints**, их регистрацию/условия
и связь с уже выполненным LoginResult. Возможный event/UI path сначала
подтвердить по данным клиента; не выдумывать автоматический вызов в runtime.
Параллельно открыты response ID 102, transport lifecycle и свежие SDK inputs.
Живая сессия и выбор персонажа не подтверждены.
