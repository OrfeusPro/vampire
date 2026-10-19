# SDK bootstrap: версия SDK и BuildCode

19 октября 2026. Getter `144524390` возвращает compiled SDK version `5.2.11`,
а `14452b820` выбирает строку build по входному байту. Проверены все 256
входов. Это уточняет два параметра [GMC2 request schema](HEADLESS-SDK-CONFIG.md).
Полный URL builder, actual BuildCode и RequestGMC2 HTTP ещё не исполнены.

## Источник и воспроизведение

[build-headless-sdk-bootstrap-values.py](build-headless-sdk-bootstrap-values.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-bootstrap-values.py`.
EXE `ProjectRED-Win64-Shipping.exe`, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Используются source-bound Image reader, Capstone 5.0.6/Unicorn 2.1.4.
Это код скомпилированного клиента, не доступный исходный C++ проект.
Нет процесса игры, файлов аккаунтов, HTTP или SDK session.

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-bootstrap-values.json`,
SHA256 `f49dad3918d00f4609b21752c72d70a16c3238dd9d300df32b0e169a618761d9`.
Сохранены instructions/file offsets/bytes/SHA, initializer literals,
native результаты, guard checks и список явных shims.

## Цепочка значений

| Участок | Подтверждённое поведение |
|---|---|
| `144524396` | LEA UTF-16 literal 5.2.11 |
| `144524390` | Getter вызывает FString constructor и возвращает destination |
| Refresh call `1444f3bb3` | Version getter после manager+1c8 и separator / |
| Initializer `1411b3220` | FString global `14b4f1658` = A |
| Initializer `1411b3250` | FString global `14b4f1668` = B |
| Initializer `1411b3280` | FString global `14b4f1678` = C |
| `14452b820` | Вход DL: 1 → B, 2 → C, остальные → A |
| Refresh `1444f3c6c` / call `1444f3c70` | Передаёт settings byte+48 в build getter |
| RequestGMC2 `1444f5671` / call `1444f5675` | Передаёт тот же settings byte+48 |

Settings+48 связан с BuildCode, +49 — с SDKZone:
[descriptor/constructor/game override](HEADLESS-SDK-SETTINGS.md).
Getter использует low byte DL, без подстановки SDKZone. CDN game AppVersion
1.12.14 и SDK version 5.2.11 — разные поля. Строки A/B/C не названы
Android/iOS/Windows без отдельного доказательства BuildCode enum.

Уточнённая статическая схема RefreshSDKConstants:

```text
<explicit active base>/template-groups/<manager+1c8>/5.2.11
?game=v5&country=G9&build=<A/B/C from explicit settings+48>
&engine=unreal&market=<explicit settings+28>
```

Это схема по callsites/getter replay, не побайтное исполнение всего builder.
Manager constructor задаёт group netmarbles-v5; поздние изменения возможны.
[Публичный CDN Zone=real](HEADLESS-PUBLIC-CDN.md) даёт вход SDKZone selector,
а не значение BuildCode. GMC2-запросов в этом этапе нет; DECKEY/auth endpoints
не получены, активные настройки не объявляются установленными.

## Native replay и общий код

Исполнены три compiled initializers, полный version getter и полный build
getter для byte 0..255. FString constructor/allocation, bounded copy и atexit
registration — явные shims. Initializers создают synthetic FString buffers;
native выбор ветки, чтение globals, управление копированием и return исполнены.
У всех build fixtures сохранены guards до/после 16-byte destination.
Late writes в globals/actual settings не исключены; startup не выполнялся.

Единственная переносимая реализация — select_sdk_build_code в
`vampir-shared/vampir_core/sdk_config.py`. Принимает явный int 0..255,
bool/другие типы отклоняются; возвращает B/C/A. Нет I/O, mutable state,
выбора active settings или скрытого default input. Отдельно от SDKZone.

Четыре теста проверяют source bytes/callsite offsets, повторяют 256 native
cases/guards/initializers/version, сравнивают общий selector, проверяют invalid
types и воспроизводимость report/отказ при изменении EXE.
`active_build_code_verified=false`, `network_ready=false`.
Далее весь GMC2 builder и request/response decode/DECKEY → auth URL values;
затем auth response/expiry и переход в игровую сессию.
