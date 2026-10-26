# Region key identity: native refresh / cached fallback

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`8e1ce0664add9eb39c4e049dab41880a0cb6ebe98696cf09094ea538d023ff5c`.
Collection run-adfcb7407ea6, SHA
`f4b8eee2ccfd83a0e8869a8c396f085f50ffd6ae98ba2a1a2f00ddd68d5a2bb4`.
Explicit roots: identity getter `14560b900` и lower string config read
`1445ceca0`. Здесь выполняется только identity getter; config reader export
остаётся навигацией, не подтверждением storage behavior.

## Обновление identity

[Dynamic key builder](HEADLESS-QUEST-SERVICE-KEY-11316.md) получает объект
клиента через `14560ad80`, затем передаёт pointer+38 в `14560b900`.
Getter вызывает `1444b1550`; если returned object+110 null — `1416b0660`.
Если после этого object+110 всё ещё null, возвращается receiver+48 без замены.
Иначе `14452b620` получает temporary FString; getter освобождает старую строку
receiver+48, переносит туда descriptor и обнуляет temporary ownership.
Возвращаемый адрес — receiver+48, который далее копирует key builder.

Это доказывает путь кэширования строки, но **не** её точный продуктовый смысл.
Platform/subsystem identities ещё не связаны с реальным account ID или login.
Нельзя называть эту строку email, паролем или именем персонажа по одному getter.

## 432 совместных native сценария

Getter заменил identity fixture внутри native key/region lookup/service setter.
Шесть explicit состояний × 72 случая primary/legacy/missing lookup,
equal/different старые region/server и dirty flag:

- Отсутствует engine object — identity getter не вызывается, key PreLogin.
- Подсистема доступна, identity пустая — старый cache заменяется empty,
  key PreLogin.
- Подсистема возвращает `account-a` / `account-b` — cache обновляется,
  формируются разные primary keys.
- Подсистема null, init не помог — cache `cached-c` сохраняется,
  key `RegionSelect_cached-c`.
- Подсистема null, init создал доступный объект — cache обновляется `account-d`,
  key `RegionSelect_account-d`; повторный key lookup уже не вызывает init.

Проверены final service fields/flags, key/config callback order, ожидаемый cache,
освобождение прежней строки, temporary cleanup и отсутствие записей в другие
поля receiver. Guards manager/provider/cache object/allocations сохранены.
Конечная cached строка принадлежит synthetic объекту и освобождается тестом
после сверки; остаточных temporary allocations нет.

## Fixtures и оставшееся неизвестное

`1444b1550`, init `1416b0660`, subsystem fetch `14452b620` — bounded fixtures.
Они задают explicit object pointers/identity results. String allocation/copy/
format/free и config read/write тоже fixtures. Native getter сам выбирает
init/refresh/retain path, переносит ownership и освобождает прежний cache.
Synthetic region values 9/10 используются только для выбора тестовой ветви,
не объявляются поддержанными RegionType работающей игры.

Все config writes перехватываются в памяти. Реальные файлы настроек и профили,
owner/session не меняются. `active_region_verified=false`, `order_admitted=false`.
Нужны platform/subsystem semantics и actual numeric/string config storage до
вывода об active region и изоляции identity реальных аккаунтов.

Новый lower config read export показывает string-key guard, копирование base
section descriptor global `14b5646a0`, необязательный section suffix и вызов
`1415cb3e0`. Он не устанавливает путь файла или current value; эта ветвь ещё
не выполнялась в replay.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_identity_11316.py
```

Общий `replay-quest-service-setup-11316.py`, контекст
`knowledge/native-contexts/quest-service-identity-11316.json`, offline check
`native-quest-service-identity-11316`. Прежние modes сохраняют свои checks.
Артефакт:
`code-clues/quest-service-identity-11316/3771fd6ddb8d55302da3b72b9870422ce0a996f38c5d4945b3475d82a45584d6/manifest.json`.

Далее — actual numeric/string config reader и platform/subsystem origin;
затем active region / ServicePhase / current policy / whole catalog.
