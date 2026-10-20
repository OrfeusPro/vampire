# Selection service: state2 и отложенное действие

20 октября 2026. Продолжение [selection service](HEADLESS-SELECTION-SERVICE.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Сначала прочитан Ghidra virtual 40 **0x145dbba60**, затем экспортированы
base-reset **0x14560a6f0**, SetState **0x14560a400**, state-label virtual+c8
**0x145dc3f30**, auth guard **0x145609b00** и callback **0x145600690**.
Ghidra: 48 функций, 32 warnings, run `run-576f3c3d5267`.
Общий индекс: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Имена `SetState/StateLabel/DeferredState` — аналитические метки.

[replay-selection-state-transition.py](../../../replay-selection-state-transition.py) →
`F:/PhoneExit Resources/Vampir/code-clues/selection-state-transition-replay.json`.
SHA256: `20e9c564feabaac7348d811a82c98544481cf22921bfae6c2241399b45408ee3`.
Report содержит source/tool/upstream SHA, fragments/file offsets/bytes,
manager getter leaf, 10 preparation cases и 12 independent callback cases.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-selection-state-transition.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_selection_state_transition.py
```

## Virtual40 и guard

Actual derived constructor prefix создаёт synthetic service, затем native
virtual 40 запускается с этим this. Prefix/body bounds прежние; full owner
construction и lifetime не добавлены. Virtual40 исполняет:

1. SDK flag **0x14b520cc3**, actual manager getter **0x1456048a0**,
   проверку manager/auth context+0x38.
2. При наличии всех gates — auth guard **0x145609b00**. Он получает service
   через cached getter fixture **0x1444aacb0**, проверяет module+0x110,
   затем native tail target **0x14452afb0** читает module+0x400.
   Logging выключен явно; отсутствие module вызывает init capture и return 0.
3. Guard false завершает virtual 40 до state preparation. SDK disabled,
   manager absent или auth context absent пропускают guard и продолжают путь.

Наличие module и byte+0x400 заданы fixtures. Они не считаются настоящим SDK
session status. Cached getter/init backend не исполняются. Нельзя заменить
эти gates проверкой непустого токена или назвать helper полноценной авторизацией.

## Подготовка raw-состояния 2

Native base-reset вызывает external helpers/diagnostics, затем actual virtual+c8
получает метку для raw 2. Lookup **0x145c5d860**, weak-pointer access
**0x141482990** и text/format/copy backend — fixtures. Проверены absent/present
метки; реальное имя состояния или map package не восстанавливается из fixture.

Actual SetState получает service, raw 2, label descriptor и проверяет lookup
**0x1445cbd50(0)** / virtual+0x7b8 (оба backend fixtures).

| Готовность объекта | Native записи | Schedule |
| --- | --- | --- |
| lookup null либо virtual false | service+0xc1=1, прежние+0x40/+0x44 сохранены | Нет |
| virtual true | service+0x40=2, +0x44=constant 0x14961a380 | callback 0x145600690 |

В fixtures constant равен 0; source привязка проверяется через Ghidra/native
RIP references. Pending+0xc1 исходно 0. При успешной записи он остаётся 0,
но в коде этого пути нет доказанного сброса ранее установленного pending.
Повторный переход с pending 1 здесь не проверялся.

На schedule helper **0x144a720c0** снимается callback pointer. Планировщик
не исполняется, descriptor не перемещается fixture автоматически; actual
cleanup **0x14141c190** вызывается и captured. Это не доказательство
сохранения closure или её lifetime настоящим scheduler. Аллокаторы, string
conversion/assignment, diagnostics и UI readiness остаются fixtures.

10 preparation cases проверяют SDK accept/reject, manager/auth/module absent,
ready null/false/true и label absent/present. Actual base/state-label/SetState
исполняются вместе; запрос CharacterListRead в covered path не достигается.

## Отложенный callback

**0x145600690** получает строковый descriptor, вызывает world getter helpers
(fixtures), затем native tail target **0x144328fe0**. Его инструкции проверены
по EXE, Ghidra показывает этот body внутри callback. Synthetic client object
имеет player pointer+0x158, state+0x740, flag+0x731 и field+0x718.

- Player отсутствует либо virtual+0x7f8 возвращает true: native flag+0x731=2,
  callback return 1. Иначе return 0 и flag не меняется.
- Если дополнительно phase+0x740<2 и busy getter result+0x80=0,
  FString копируется в client+0x738 (copy fixture).
- При отсутствии player native field+0x718 становится 0; при наличии player
  вызывается virtual+0x800 со строкой и raw 0 (capture).
- При phase 2/busy 1 callback может вернуть 1 и поставить flag 2, **не выполняя**
  copy/player action. Return1 не доказывает загрузку, состояние игры или сессию.

12 callback cases перебирают player absent/present, ready false/true и
phase/busy границы. Исходные flag 127 и field 0xabcdef показывают, какие
значения изменились native store, а какие сохранились. Время/persistence,
загрузка карты и действия настоящего player backend не выполнялись.
Строка `callback-label-fixture` синтетическая, это не найденный map path.

Callback вызывается **отдельным прогоном**, а не настоящим scheduler после
SetState; связь callback pointer подтверждена, полная closure цепочка открыта.

## Проверки и следующий участок

[Три новых tests](../../../../../test_vampir_headless_selection_state_transition.py)
перестраивают report и проверяют native state writes, guards/schedule,
callback conditions/return/flag/field/captured arguments. Три смежных selection
service и три Ghidra tests прошли; полный suite не повторялся.

Slot+0x90 (requestA) остаётся source-bound к derived table, но **его вызов
после state/world перехода ещё не установлен**. Проверенные virtual 40/
callback paths непосредственно его не вызывают. Следом — фактическая state-label
lookup mapping и lifecycle/client hooks после отложенного действия, затем
доказанный dispatch slot 90. Не добавлять произвольный auto-request в runtime.

Runtime не менялся; game/profile/process memory/credentials/network/Android
не использованы. Полный SDK→Login→CharacterList flow, response 102, socket и
подтверждение выбора персонажа остаются открытыми.
