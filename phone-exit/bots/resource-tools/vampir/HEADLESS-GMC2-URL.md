# GMC2: native сборка URL из явных значений

19 октября 2026. Исполнен участок RefreshSDKConstants `1444f3a68..1444f3d7d`,
включая native version/build getters и ASCII-view append `14175be40`.
Общий assemble_gmc2_config_url_ascii совпал с 26 native fixtures.
Сетевых запросов GMC2 и авторизации в этом этапе нет.

## Источник и воспроизведение

[build-headless-gmc2-url.py](build-headless-gmc2-url.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-gmc2-url.py`.
Source EXE тот же, что в [SDK getter evidence](HEADLESS-SDK-BOOTSTRAP-VALUES.md),
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Capstone 5.0.6/Unicorn 2.1.4, без процесса игры и файлов аккаунтов.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-gmc2-url.json`, SHA256
`0b4c7cef95d372d82c6a29673f41f4270e095eb48d3b0515fdb8284cb4a01099`.
Source instructions/file offsets/bytes/fragment SHA и все fixtures сохранены.

## Подтверждённая строка

```text
base + /template-groups/ + group + / + sdk_version
     + ?game=v5&country=G9&build= + build_label
     + &engine=unreal&market= + market
```

| Значение | Native источник |
|---|---|
| base | manager+1e8, загрузка `1444f3a68` |
| group | manager+1c8, `1444f3b35` |
| SDK version | call `1444f3bb3` → `144524390`, compiled 5.2.11 |
| Build label | settings+48, call `1444f3c70` → `14452b820`, byte1→B/2→C/elseA |
| market | settings+28, `1444f3d1e..3d2a` |

Native ASCII-view append исполняется: он расширяет байты литерала в UTF-16.
Это проверено на действительных compiled literals, а не на их UTF-16 догадке.
Первая версия fixture ошибочно читала ASCII view как UTF-16; до публикации
результата она заменена actual native append и проверена по итоговым строкам.
Общий runtime этот исследовательский shim не использует.

Обычный fixture:
`https://config.invalid/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp`.
Это искусственный адрес .invalid. Active base/group/BuildCode/market не выводятся
из fixture. Production mode/base evidence остаётся в [GMC2 graph](HEADLESS-SDK-CONFIG.md).

Слэши не нормализуются: base с завершающим / даёт //template-groups/.
Пустые base/group остаются пустыми; group с / сохраняет их. Market fixture
`a b&c=1` копируется без escaping. Это поведение сборщика строки, не разрешение
отправлять произвольную строку как запрос. HTTP/URL trust должны проверяться
отдельно. Версия SDK не подменяется game AppVersion из CDN.

## Объём исполнения и общий код

24 сочетания base/group/BuildCode и два дополнительных fixture проверяют
длинный base со сменой buffer capacity и raw query characters. Version/build
getters, compiled initializers, native pointer arithmetic/branches/копирование
вызовов и ASCII append исполнены. FString constructor/allocation/copy/free,
buffer growth, atexit и settings singleton — явные bounded shims.
Growth проверяется по вызовам и результату, native allocator не исполнялся.
Остановка перед request/callback setup: весь RefreshSDKConstants, ownership,
HTTP headers/method/TLS/response ещё не воспроизводятся этим инструментом.

Переносимый helper в `vampir-shared/vampir_core/sdk_config.py` принимает явные
base/group/sdk_version/build_code/market и возвращает строку. Нет HTTP, чтения
настроек, active defaults, escaping или URI validation. Локальный subset:
printable ASCII, каждый fragment/result максимум 4096 chars; пустые строки
сохраняются, Unicode/control chars/bool BuildCode отклоняются. Это локальные
границы, не доказанные серверные лимиты. SDK version передаётся явно.

Четыре теста сверяют source bytes/callsites/native append, повторяют 26 native
fixtures и сравнивают общий helper, проверяют growth/slashes/raw query,
локальные type/size budgets и воспроизводимость отчёта.
`active_values_verified=false`, `network_ready=false`.
Далее — RequestGMC2 headers/transport и response decode/DECKEY → auth URLs;
активный BuildCode и игровой вход остаются открыты.
