# Совместное числовое чтение региона по ключу identity

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `fca881b7d30cce6bfd99942534059458faa32bd511e34aa8a5f34979d7469c53`.
Шесть explicit roots уже экспортированы: `145c21f20`, `14556b8b0`,
`14556b740`, `14560b900`, `1445ceaa0`, `141435110`.
Их полные SHA/export bindings закреплены в
`knowledge/native-contexts/quest-service-number-11316.json`.

## Результат

[Числовой reader](HEADLESS-QUEST-REGION-NUMBER-11316.md) подключён native
вместо callback, который сразу возвращал число. Native identity getter,
key builder, region lookup, provider leaf и service setter выполняются
вместе с numeric reader и удалением запятых. `_wtoi` вызывает реальную
локальную Windows CRT, SHA/locale проверяются до и после прогона.

1008 случаев: шесть состояний identity × семь состояний storage × три
server values × два dirty × equal/different region × equal/different server.
Identity состояния: absent engine, empty, account-a, account-b,
failed subsystem с cached-c, successful init с account-d.
Storage состояния: primary со значением своего профиля, primary empty,
primary `JP`, primary `1,000`, legacy `7`, legacy `JP`, оба ключа missing.
Проверены конечные поля региона/сервера/dirty/ready, guards, cache ownership,
вызовы и порядок reads/writes, cleanup и фактические строки перед `_wtoi`.

При найденных primary empty / `JP` результат 0, legacy не читается.
`1,000` преобразуется в 1000. При отсутствии primary читается RegionSelect;
найденный legacy `JP` даёт 0 и две migration write intentions с этим числом.
Provider+A8 во всех сценариях = 55 и отличается от найденных значений.
При отсутствии обоих ключей используется этот кэш, без writes.
Значения 55/1000 — synthetic входы для проверки переноса, не поддержанные
регионы работающего клиента.

Ключи account-a/account-b/cached-c/account-d/PreLogin одновременно находятся
в одном словаре fixture: 4/7/0/1000/1. В primary-profile варианте native key
выбирает соответствующее значение; account-a и account-b дают 4 и 7.
Для legacy/missing удалён только ключ текущего профиля, чужие ключи остаются.
Это проверяет выбор ключа в данной native цепочке, но не изоляцию реальных
аккаунтов целиком и не файлового хранилища. Каждый сценарий запускается
с явным состоянием; переключение профиля в настоящем процессе не проверено.

## Fixtures и неизвестное

Platform getter/subsystem init/fetch, FString allocation/copy/append/format/free,
нулевая длина сравнения suffix, lower storage read и numeric config writes
остаются ограниченными fixtures. Все migration writes только проверяются
в памяти; пользовательские настройки/профили и живая сессия не меняются.
Active identity semantics, путь/section/config storage, actual region и
ServicePhase, whole catalog admission ещё не доказаны.
`network_used=false`, `active_region_verified=false`, `order_admitted=false`.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_number_11316.py
```

Общий replay `replay-quest-service-setup-11316.py`, новый mode native_number;
прежние modes сохраняют свои отдельные checks. Новый check
`native-quest-service-number-11316` зависит от системной ucrtbase.dll.
Артефакт: `code-clues/quest-service-number-11316/d4557bf1fce39e7d111f0fdf3e1cfd044973b7f916b53d97e7658c77f567db0b/manifest.json`.
Далее — lower string storage read `1445ceca0` / `1415cb3e0` и section origin;
затем active configuration / phase и допуск каталога для реальных действий.
