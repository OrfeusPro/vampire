# Прямой caller slot 90 → CharacterListRead

20 октября 2026. Подтверждён caller RequestA; lifecycle его владельца ещё открыт.

## Источник и инструменты

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 80 функций, 44 предупреждения.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-03284ca927be`.
Manifest SHA256: `f993107c3c3b11af459f672044a36f499e04ab517d423ce7595f148ff329e14f`.

Использован существующий PE scanner `build-entry-window-code.py`:
E8 candidates к getter `0x1456048e0` проверены по инструкциям unwind fragments.
Новый `build-selection-service-callers.py` сохраняет результаты в
`F:/PhoneExit Resources/Vampir/code-clues/selection-service-callers.json`.
SHA256: `9b498350a4131dcd49398322eac04d96d7d1f2d2443d1cd303dbcab3c8273f1b`.
505 подтверждённых calls; 16 unresolved candidates, 9 ошибок декодирования roots.
Это не полный call graph: indirect/tail calls и inline global accesses не покрыты.

## Найденная цепочка

Caller `0x1468f1d70`, аналитическое имя Ghidra `SelectionLifecycle_Request90Caller`:

| Инструкция | Действие |
| --- | --- |
| `0x1468f1e39` | Второй вызов owner virtual+a18 |
| `0x1468f1e44` | Сравнение AL с 1 |
| `0x1468f1e48` | Getter selection service `0x1456048e0` |
| `0x1468f1e4d` | Возвращённый RAX → RCX |
| `0x1468f1e50` | Чтение vtable возвращённого объекта |
| `0x1468f1e53` | Virtual+90 → RequestA `0x145dbd4b0` |

RequestA создаёт packet через `0x1456d4780`, vtable `0x1498d84d8`, ID101
по [ранее проверенной привязке](HEADLESS-CHARACTER-LIST-BOUNDARY.md).
Далее actual getter send wrapper и virtual send+38 достигают capture.
Байт packet+a равен 0 после actual constructor.

Первый owner virtual+a18 находится отдельно в `0x1468f1e0c`:
при AL2 вызывается service virtual+98 и owner virtual+a00. Затем policy читается
снова. Нельзя считать второе значение равным первому: после первой ветви
могли измениться условия. Имена enum/owner class здесь не установлены.

## Native проверка

`replay-character-list-caller.py` исполняет полный caller, actual singleton getter,
RequestA и packet constructor. Взята копия настоящей service table; только slot 98
заменён capture. Slot90 сохраняет actual target. Внешние helpers и owner policy
virtual — fixtures; отправка захватывается без сети.

32 случая: первое и второе значения независимо из 0/1/2/4, по два состояния
флага `0x14b27eecb`. При выключенном флаге lookup fixture возвращает null;
ветка с nonnull объектом и type-check здесь не проверена.

Подтверждено: send достигается ровно при втором значении 1; первая ветка
98/a00 — ровно при первом значении 2. Caller ставит helper-object byte+260
и globals `0x14b144a68`/`0x14b571319` в 1. Назначение флагов не угадано.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/character-list-caller-replay.json`.
SHA256: `90a666375b30ad2acd567d6a72a333bd49ac2ed8be8865d875159db1f23a34ec`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-selection-service-callers.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-caller.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_character_list_caller.py
```

Ghidra также экспортировала продолжение slot 78 `0x14561a8d0`, base helper
`0x14560d7b0` и delegate callback `0x145dc5ae0`. В них прямой slot 90 не найден;
это статическое наблюдение, не доказательство отсутствия косвенных путей.

## Продолжение и границы

Найти owner/vtable функции `0x1468f1d70`, источник virtual+a18 и lifecycle её вызова.
Затем связать actual owner policy 1 с загрузкой CharacterSelect_02, обработать
ответ 102 и подтвердить сетевую сессию. Native fixture не доказывает, что функция
была вызвана работающим клиентом. Frame/socket/server response, живой профиль,
память игры и Android не использовались.

Связанные результаты: [service/table](HEADLESS-SELECTION-SERVICE.md),
[World.Id2/LevelPath](HEADLESS-WORLD-STATE-LABEL.md),
[предыдущие lifecycle callbacks](HEADLESS-SELECTION-LIFECYCLE.md).
