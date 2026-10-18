# Vampir — источник конфигурации SDK GMC2

18 октября 2026. H04b частично. Предыдущий этап — [авторизация SDK](HEADLESS-AUTH.md),
общий [реестр](../../vampir/FUNCTION-INDEX.md). Актуальные значения авторизации
и игровой вход пока не получены.

## Источник и воспроизведение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса — VA, image base `0x140000000`. Версия выпуска и соответствие Android неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-config.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_config.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-config.json`,
SHA256 `b6f3418f9d9bb44f2feb748c4bc662059110080c54117d9d52f6448da668799c`.
Сохранены source/tool hashes, 7 точных diagnostic literals, 8 проверенных LEA,
7 unwind roots и 48 констант с bytes/file offsets/SHA. Missing/rejected=0.
Дополнительно исполнена native ветка выбора адреса для всех 256 значений byte.
Внешних запросов, чтения Saved, памяти launcher или данных аккаунта не было.

## Найденные функции и уровни подтверждения

| Diagnostic | Root VA | Подтверждено |
|---|---|---|
| FGMC2ManagerImpl constructor | 0x1444bd970 | Запись строк ключей и четырёх базовых адресов в поля объекта |
| Start | 0x144501970 | Native выбор поля адреса по settings byte, см. ниже |
| RefreshSDKConstants | 0x1444f38e0 | Статическая сборка строки с template-groups и параметрами |
| RequestGMC2 | 0x1444f5320 | GET и application/json по исходным ссылкам |
| OnCompleteRequestGMC2 | 0x1444edbb0 | Diagnostic/root; весь callback ещё не исполнен |
| ParseConstantsTemplateGroups | 0x1444f0e80 | Diagnostic/root; обработка ответа ещё не восстановлена полностью |
| DecryptXOR | 0x1444ddf50 | Diagnostic/root; полный алгоритм ещё не проверен |

Строка DecryptXOR также встречается в root ParseConstantsTemplateGroups.
Это дополнительная ссылка, а не основание переименовать весь parser в decryptor.
Имена функций подтверждены связью точной строки с инструкциями, но не означают,
что вся функция проверена native исполнением.

## Проверенный выбор базового адреса

Constructor хранит четыре FString по offsets manager+0x150/0x160/0x170/0x180.
Start берёт settings через service+0x110, затем byte settings+0x49 на
`0x144501a11`. Slice `0x144501a11..0x144501a46` исполнен без подмены инструкций:
RCX указывает на synthetic settings, RDI — на synthetic manager.
Проверяется итоговый адрес поля в RDX. Строковое копирование за slice не исполняется.

| Mode byte | Поле manager | Строка constructor |
|---|---|---|
| 0 | +0x150 | https://alpha-apis.netmarble.com/gc2 |
| 1 | +0x160 | https://dev-apis.netmarble.com/gc2 |
| 2 | +0x170 | https://apis.netmarble.com/gc2 |
| 3 | +0x180 | https://dr-apis.netmarble.com/gc2 |
| 4–255 | +0x160 | dev, как в найденной ветке |

Поле +0x170 связано с production строкой через LEA `0x1444bdb12`, literal
`0x1444bdb19` и последующий вызов string constructor. Все 256 mode outputs
сохранены и повторно исполняются тестом. Активное значение settings+0x49,
его config source и имена enum ещё не установлены. Нельзя считать mode=2
подтверждённым режимом установленной игры только по наличию production URL.

## Статическая форма запроса конфигурации

RefreshSDKConstants использует активную base string manager+0x1e8 и добавляет:

```text
<active base>/template-groups/<manager+0x1c8>/<value from 0x144524390>
?game=v5&country=G9&build=<value from 0x14452b820>
&engine=unreal&market=<settings string +0x28>
```

Это схема по выбранным инструкциям сборки, не готовый URL для вызова.
Constructor задаёт +0x1c8 строкой `netmarbles-v5`, но последующие изменения
и входные значения getters ещё проследить. Имена query keys build/market
не доказывают семантику произвольного соседнего поля settings.
Literal anchors: `/template-groups/` на `0x1444f3afa`, `?game=v5&country=G9&build=`
на `0x1444f3c1d`, `&engine=unreal&market=` на `0x1444f3cda`.
RequestGMC2 ссылается на GET в `0x1444f5780`. Весь string builder/HTTP request
ещё не исполнен, percent encoding и актуальные значения здесь не заявляются.

Constructor также содержит ключи `encConstants`, `encSecretConstants`, `DECKEY`,
`eTag` и сведения о геолокации ответа. Это имена полей протокола конфигурации,
а не полученные секреты или доказательство готового декодера. Живой ответ не
загружался; содержимое runtime secret constants не извлекалось и не логировалось.

## Следующее продолжение

Проследить источник settings mode и getters `0x144524390` / `0x14452b820`,
вызов RequestGMC2, response/schema/decode → authTokenUrl/authAccountUrl/authUrl
и clientId. До этого не посылать token-request plan на угаданный базовый адрес.
Затем browser code/ответы/expiry → SDK session → LobbyLogin/Login и live canary.
Три теста проверяют provenance, literal/call boundaries, все mode outputs
и повторное native исполнение. `network_ready=false`; вход и бой не готовы.
