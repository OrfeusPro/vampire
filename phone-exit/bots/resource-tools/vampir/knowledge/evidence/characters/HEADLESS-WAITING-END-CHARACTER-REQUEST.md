# WaitingEndNotify → CharacterListRead: подтверждённый инициатор

19 октября 2026. Продолжение [границы запроса персонажей](HEADLESS-CHARACTER-LIST-BOUNDARY.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Проверен существующий constructor-call index PktCharacterListRead. Поиск прямых
call/jump к request entries нашёл tail jump **0x14676864f → 0x145dbfe50**.
Сначала экспортированы Ghidra caller **0x146768540** и predicate **0x145c85d90**.
Literal caller буквально **PktWaitingEndNotifyHandler::OnHandler()**;
другая diagnostic строка **SelecCharacter by QuickSelect** сохранена без исправлений.

Ghidra: 39 функций, 26 warnings. Общий индекс:
`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`; run `run-6e0d16aaecc2`.
Псевдокод показывает request routine и quick-select tail thunk внутри caller;
в native evidence сохранены их отдельные PE ranges. Это не новые исходники C++.

[replay-waiting-end-character-request.py](../../../replay-waiting-end-character-request.py) →
`F:/PhoneExit Resources/Vampir/code-clues/waiting-end-character-request-replay.json`.
SHA256: `070d3fb4d88db45994a97cc4f154a081aef058068d5978ead8d6ae60e0773019`.
Report содержит source/tool/upstream SHA, native fragments/bytes/file offsets,
tables/getter/ID/constructor leaves, registration callsites, diagnostics и 24 cases.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-waiting-end-character-request.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_waiting_end_character_request.py
```

## Привязка уведомления

Registration **0x14678f176** устанавливает handler table **0x149d811a0**,
**0x14678f197** вызывает notify constructor **0x1456d54d0**,
**0x14678f1aa** передаёт созданные объекты в registration helper **0x1467a7250**.
Actual registration backend здесь не исполняется; инструкции проверяются по EXE.
Table slot+0x10 равен handler **0x146768540**.

Constructor реально исполняется, ставит packet vtable **0x1498d6b50**,
обнуляет raw64+0x10. Slot+0x28→getter **0x1456e2100** реально возвращает **27**.
Slot+0x20→reader **0x1456b3360** статически привязан. Body поступает как fixture
raw64 `0x0102030405060708`; native receive/framing/reader здесь не исполняются.
ID 27 не следует из названия, а получен исполнением actual getter.

## Исполненная цепочка и условия

В одном run исполняются notify constructor → handler → peer flag getter →
predicate → tail jump requestB → PktCharacterListRead constructor →
singleton getter → virtual send capture → cleanup captures → return.
Packet vtable **0x1498d84d8** и byte+0xa=0 проверяются на send boundary.

Peer flag читается native leaf **0x144aaaab0** из `[wrapper+0x10]+0x2a6`.
Predicate **0x145c85d90**:

- при global **0x14b27eecb != 0** возвращает raw 4;
- иначе вызывает lookup helper **0x1445cbd50(0)**;
- ненулевой объект проверяет через type metadata index/range/pointer;
- при совпадении tail-calls object virtual+0xa18; иначе возвращает 4.

Global gates и проверки type metadata исполняются. Lookup/type objects и
virtual return — fixtures. Raw 0/1/2/4 не названы enum members: семантика
реальной policy implementation ещё неизвестна. Null/short metadata/mismatch/
disabled paths не вызывают virtual policy и приводят к actual fallback 4.

| Peer flag | Predicate | Действие handler |
| --- | --- | --- |
| 0 | 0 | При выбранном raw64 != sentinel: quick-select thunk 0x145d46400 → virtual+0x50 с этим raw64; иначе virtual+0x40 |
| 0 | nonzero | Return без запроса списка/selection virtual |
| nonzero | 1 | Tail jump 0x145dbfe50 → CharacterListRead/ID 101 → send capture |
| nonzero | 0 | Predicate вызывается второй раз, затем virtual+0x40 |
| nonzero | 2/4 | Predicate вызывается второй раз, затем virtual+0x50 с notify+0x10 |

Sentinel берётся из actual raw64 **0x14961a378**, второе raw32 selection argument
из **0x14961a380**. В первом пути selected raw64 читается из getter object+0x28;
объект — fixture. Называть его CharacterId до отдельной consumer evidence нельзя.
Selection/next virtual calls и их последствия — captures, не отправка
PktCharacterSelect. UI lookup в начале handler всегда отсутствует в fixtures;
ветка видимого UI и virtual+0x598 пока не исполнялась.

## Проверки и оставшийся разрыв

24 scenarios: 16 комбинаций peer 0/1 × policy 0/1/2/4 × selected sentinel/value,
плюс 8 native fallback cases. Две комбинации реально достигают requestB и
CharacterListRead send boundary. Проверяются exact argument source/branch,
число predicate calls, registration/ID/table/source bytes.
[Три новых tests](../../../../../test_vampir_headless_waiting_end_character_request.py),
три прежних CharacterList boundary и три Ghidra tests прошли.

Событие ID 27 подтверждает **один** путь к запросу списка; не доказано, когда
сервер отправляет его после LoginResult и обязателен ли этот путь всегда.
Другой requestA **0x145dbd4b0** пока связан только с function pointer
**0x1499f1280**; class/slot/условия вызова не установлены. Его связь с обычным
завершением Login остаётся отдельной задачей.

Send/cleanup/diagnostics/lookup/virtual policy/selection backends подставлены.
Не строился ID 101 frame/socket, не получен response 102, session/character list
не готовы. Runtime не менялся; game/profile/process memory/credentials/network/
Android не использованы, полный suite не повторялся.
Далее — requestA vtable owner и actual selection virtual+0x40/+0x50;
также открыты response 102 и стыковка network lifecycle.
