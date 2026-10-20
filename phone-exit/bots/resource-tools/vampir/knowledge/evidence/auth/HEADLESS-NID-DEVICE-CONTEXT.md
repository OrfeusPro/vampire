# NID deviceKey отличается от SDK sign-in deviceKey

19 октября 2026. Продолжение [индекса хранения](HEADLESS-SDK-STORAGE.md).
Источник — собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это данные/код клиента, не исходный C++ проект.

Инструмент `replay-nid-device-context.py` экспортирует три caller roots с
instructions/bytes/file offsets/fragment SHA и diagnostic literals; исполняет
три коротких участка подготовки key/value pairs в Unicorn.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/nid-device-context-replay.json`,
SHA256 `f2dc566864437405c3af888e27547d15ccb10317260dc68412211f2f3ce7d8ba`.
В отчёте также tool SHA и SHA переиспользованного source report.

## Подтверждённые вызовы

| Назначение | Caller/root | Getter call | Поле пары |
| --- | --- | --- | --- |
| FNetmarbleIDContent::CheckPossibleToOpen | 0x1450de4f0 | 0x1450dea50 → 0x144522b50 | deviceKey |
| FNetmarbleIDProvider::GetAccessTokenByAuthorizationCode | 0x1450e2640 | 0x1450e2c92 → 0x144522b50 | device_key |
| FNetmarbleIDProvider::GetAccessTokenByRefreshToken | 0x1450e2f50 | 0x1450e35f3 → 0x144522b50 | device_key |

Getter `0x144522b50` ранее связан с diagnostic name
GetDeviceKeyForNetmarbleId(bool), storage key DeviceKeyForNetmarbleId и
settings+`0x628`. В каждом из трёх caller передаётся bool=true.
Native slices исполняют literal construction call site, getter call site и
сохранение указателей ключа/значения в соответствующую пару.

В web caller literal `authWebViewUrl`, диагностическое имя и расположение
deviceKey рядом с nmDeviceKey/clientId подтверждены статически. Полный URL,
map/query encoding и запуск webview этим replay не исполнялись.
В [JS email contract](HEADLESS-NID-EMAIL.md) поле deviceKey уже найдено;
теперь установлен его отдельный native web-context источник. Полная передача
конкретного URL в JS/browser context остаётся отдельной границей проверки.

SDK sign-in, напротив, использует getter `0x144522820` для JSON deviceKey
([source-bound body](HEADLESS-SDK-SIGN-IN.md)), settings+`0x618`/DeviceKey.
Одинаковое имя wire field не означает одинаковое значение.

## Границы native replay

Исполнены `0x1450dea30..0x1450dea6a`, `0x1450e2c63..0x1450e2ca9`,
`0x1450e35c4..0x1450e360a`. Getter возвращает **искусственную** строку
nid-device-fixture; его body/storage/active context не исполнялись.
ASCII/wide FString constructors и соседние stack slots client-id — fixtures.
Проверены resulting pair pointers/ключи, не весь запрос или сериализация.
Реальные ключи, почта, Saved, registry, процессы и сеть не использованы.

## Постоянный реестр бота

`DeviceRegistry` schema v2 добавляет `nid_device_key` и `nid_identity_source`:
они независимы от SDK `device_key` и `nm_device_key`.
Миграция v1 → v2 атомарно добавляет пустые поля, сохраняет profile_id, прежние
ключи и статус. Не копирует SDK key в NID key и не генерирует identity.
Повторное открытие v2 не меняет данные. Миграция сериализуется BEGIN IMMEDIATE.

`record_real_nid_identity` принимает только явно наблюдённое значение и источник
для real-профиля, запрещает замену закреплённого значения. Идентификаторы и
source скрыты в repr. Идемпотентный повтор не сбрасывает подтверждение.
Первое добавление NID identity сбрасывает прежнее confirmed → unknown и очищает
его evidence: старое подтверждение не доказывает подтверждение нового поля.
Required сохраняется. Это локальная политика, не семантика серверной проверки.
Существующая identity_recorded относится к SDK паре; nid_identity_recorded —
отдельная проверка заполненности, не валидность устройства или токенов.

Локальная база основной почты мигрирована; все реальные device keys пока пустые.
Далее NID getter lifecycle, полный web-context mapping, filename/Save/load,
получение согласованной identity и штатный device confirmation protocol.

Проверки: `test_vampir_headless_nid_device_context.py` и
`test_vampir_headless_device_registry.py`: native pair/source replay,
раздельность identity, идемпотентность, запрет замены, миграция с сохранением
старых данных и сброс подтверждения при первом добавлении NID identity.
