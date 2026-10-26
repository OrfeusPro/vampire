# Region config: native ключ по identity и PreLogin fallback

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`b9f87fa255d7eaac853fba57abfb1c021e73e723ca29fbc3fa132cd21844208d`.
Collection run-79f96d7ea490, SHA
`06a0ba8744ea7ea26f06ab5b201641434370d422e5066ece1a21130674dcc3e8`.
Explicit roots: dynamic key `14556b740`, numeric reader `1445ceaa0`, numeric
write wrapper `1445d7220`. Этот replay выполняет только key root вместе с
[прежними lookup/getter/setter](HEADLESS-QUEST-SERVICE-REGION-11316.md).
Остальные два exports прочитаны как навигация, execution не заявлен.

## Реальный формат ключа

Key builder вызывает `14560ad80`. При null либо пустом pointer+38 выбирает
`RegionSelect_PreLogin` (literal `1498fd638`). Иначе получает FString от
`14560b900`, копирует её и проверяет длину. При count<2 также выбирается
PreLogin key. При непустой строке вызывается formatter с literal `1498fd618`
`RegionSelect_%s` и полученной identity строкой.

Происхождение identity ещё не прослежено: она не объявляется account ID,
паролем или именем персонажа. Проверено только то, как её bytes влияют на
config key. Настоящий engine/identity getter остаётся следующим шагом.

## 288 совместных native сценариев

Key root заменяет synthetic key callback внутри lookup → setter replay.
Исполняются getter leaf, dynamic key branch/copy call flow, lookup и setter.
Четыре synthetic состояния:

- Объект клиента отсутствует → `RegionSelect_PreLogin`.
- Объект есть, identity пустая → тот же PreLogin key.
- `account-a` → `RegionSelect_account-a`.
- `account-b` → `RegionSelect_account-b`.

По 72 случая на состояние: primary/legacy/missing reads, old region/server
equal/different, dirty flag и server 0/256/FFFFFFFF. Region 8 используется как
synthetic test discriminator для empty-identity ветви, не допуск реального enum.
Две identity имеют раздельные primary keys. При legacy read success вызываются
write intentions в primary key и RegionSelect_PreLogin; для PreLogin primary
это две записи в один key, что соответствует проверенному native порядку.

Config get/set всё ещё bounded fixtures с накоплением операций в памяти.
Настоящие settings/profile files не меняются. После каждого случая проверены
final service fields/dirty/ready, callback order, provider/manager guards и
string cleanup без остаточных allocations. Прежние 144/216-case режимы
сохраняются отдельными regression checks.

## Открытые границы

Engine/identity getters, FString allocation/copy/free и formatter — fixtures.
Formatter принимает только настоящий native literal `RegionSelect_%s` и
проверенную текущую synthetic identity. Native выбирает PreLogin / identity
ветвь, передаёт строки, освобождает temporaries и вызывает lookup; сам
Unreal formatter/string implementation не исполняется.

Numeric reader export вызывает lower string read `1445ceca0`, затем string
helper `141435110` с comma/empty literals и `_wtoi`. Точная string replacement
semantics / actual config path ещё не проверены. Writer `1445d7220` получает
текстовое представление числа и передаёт его lower writer `1445d70b0`; native
storage/file handling ещё не выполнялись. Само наличие этих exports не
разрешает заменять пользовательские настройки.

`active_region_verified=false`, `order_admitted=false`; текущая identity,
cache+A8, numeric region / ServerGroup phase и whole catalog остаются открыты.
Игровые команды и owner API не используются, сессия не прерывается.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_key_11316.py
```

Общий `replay-quest-service-setup-11316.py`, контекст
`knowledge/native-contexts/quest-service-key-11316.json`, offline check
`native-quest-service-key-11316`. Артефакт:
`code-clues/quest-service-key-11316/85dccec7a5ea211e412ed960c54b39eba4512951f2d963393e2ba2ac06fa6254/manifest.json`.
