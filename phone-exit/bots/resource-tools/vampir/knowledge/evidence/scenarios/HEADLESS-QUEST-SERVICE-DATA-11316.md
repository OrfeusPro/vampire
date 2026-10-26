# Service policy: RegionType / ServicePhase текущих таблиц

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Prepare navigation request
`eccbbd8a31a4d932eb0180fe0e822adde9ee013b2c2a8b83a678d977e2654bf4`
прочитал существующие getter/policy. Затем explicit vtable roots запрошены в
`97a373304e4d2b6ee494967924b2bc06aa0ad749d660558631b75b43c7acdd69`.
Run-bf6dd46e601c, SHA
`11457b9b0e5f0af80212b44e746eb69d97e95b45b343ddfc6bf0dbfac0f1756f`,
содержит ServerServiceGroup loader `145c06600`, lifecycle loops `145bff6f0` /
`145c00d20` и lookup `145bfdcc0`. Их получение не доказывает active configuration.

## Уточнение смысла полей

[Прежний bounded policy replay](HEADLESS-QUEST-SERVICE-POLICY-11316.md) использовал
аналитическое имя «version» для сравниваемого числового значения. Текущая source
таблица и native stores уточняют min/max как **ServicePhase**, а не client version.
Прежние numeric boundary tests остаются верны как проверка инструкций; их
аналитическое имя нельзя переносить в продуктовую модель версии клиента.

Vtable secondary interface `149a11990` slot +38 → `145c06600`. Loader создаёт
records stride 38 hex (56 bytes). Exact column literals и instructions связаны:

| CSV поле | Record offset |
| --- | --- |
| GroupId | +08 |
| RegionType | +0C |
| MinServicePhase | +10 |
| MaxServicePhase | +14 |
| ExcludeServerId | +18 |
| IncludeServerId | +28 |

Эти offsets совпадают с чтением policy `145c022b0`. Таким образом, current
singleton+78 сопоставляется с RegionType записи, singleton+7C сравнивается
как строка с серверными ID списков. Кто и когда задаёт active fields singleton,
ещё не проверено. Lookup `145bfdcc0` обходит uint32-key map и возвращает record
pointer либо fallback; native ServerGroup loader/ServicePhase offset ещё нужен,
чтобы связать всё чтение result+28 с именованным полем без допущения.

## Именованные current PAK записи

Используется прежний authoritative directory manifest
`resource-config-snapshots/d2691f91f8d88d15329639bc8457bced595cef0d5ee6b4bfff3b17e98c97f523/manifest.json`.
Проверены manifest/directory/encoded entry hashes, record-index SHA, actual
PAK до/после, reader/Oodle и decoded bytes. Named path сопоставлен с record
offset; порядок runtime file precedence не установлен.

- `CSV/ServerServiceGroup.csv`, entry 3023, 104 rows, SHA
  `aaafd94076deb83d50bf38f384e8700977954b493fa2bc06d0ed5fe68275dd77`.
- `CSV/ServerGroup.csv`, entry 3016, 417 rows, SHA
  `ac87365805a7d44caf8a6fd8ed9bf5682bacaaff28cba4ade8aae37f27e6d399`.

ServerGroup.Id=256 имеет GroupId=252, ServerGroupType=103 и ServicePhase=10000.
Это значение source CSV, не чтение текущей памяти headless-сессии.
ServerServiceGroup.GroupId=10000 содержит 8 RegionType rows, списки исключений /
разрешений пусты во всех восьми:

| RegionType | MinServicePhase | MaxServicePhase | Кандидат для фазы 10000 |
| --- | --- | --- | --- |
| 0, 1, 2, 3, 4 | 10000 | 19999 | оставить |
| 5, 6, 7 | 1 | 9999 | пропустить |

Это статическая табличная проекция для явно заданных server ID/phase inputs.
Она **не устанавливает**, какой RegionType соответствует активной JP/HK сессии.
ServerGroupType=103 не приравнивается автоматически к RegionType. Имя JP,
страна аккаунта или телефонный выход сами по себе не закрывают active field.

## Воспроизведение и границы

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_data_11316.py
```

`inspect-quest-service-data-11316.py`, контекст
`knowledge/native-contexts/quest-service-data-11316.json`, offline check
`quest-service-data-11316`. Report сохраняет обе таблицы/columns/rows и восемь
candidate decisions с active_region_verified=false. Артефакт:
`code-clues/quest-service-data-11316/c0e0cc6ddd42e9d2854f7752d315fdf8b6f0b3f07b9607a4cc904b413d4d9778/manifest.json`.

Native execution этого сценария отсутствует; проверены static instructions и
фактические current data. Whole service loader / active field setup, native
ServerGroup ServicePhase layout и whole QuestTask catalog ещё открыты.
`order_admitted=false`, owner/runtime/settings/соединение не изменялись.
