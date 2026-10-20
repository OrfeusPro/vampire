# Load: поля устройства и filename defaults

19 октября 2026. Продолжение [storage index](HEADLESS-SDK-STORAGE.md).
Источник — собранный Windows EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Не исходный C++ проект. Источник и source offsets переиспользованы из
`F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-storage.json`, SHA256
`7d262be2ea2d283dc96dd4070dd219a319fe5906b570307359010bcf0f86bb43`.

Дополнение: [optional directory/auth gate](HEADLESS-SDK-AUTH-PATH.md) проверен
отдельным replay; источник suffix найден статически, его преобразование ещё открыто.

## Отчёты и воспроизведение

`replay-sdk-load-device-fields.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-load-device-fields-replay.json`,
SHA256 `135c64f8031272e548de1194fe0860db94b2072b7e0950e2d8ab8950d6c8b591`.
16 fixtures исполняют две field-copy slices и post-restore dispatch.

`replay-sdk-storage-filename.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-storage-filename-replay.json`,
SHA256 `ab750bb3fc2f4f06b8df5649a965e147e24856e086d391b300034b6770528f33`.
Три fixtures исполняют constructor filename defaults и Load filename join.
Экспортированы constructor/class registration fragments и leaf thunk bytes,
file offsets/SHA, literals и SHA инструмента. Полная регистрация не исполнялась.

## Восстановление разных device keys

| Поле | Save object FString offset | Service settings FString offset | Native slice |
| --- | --- | --- | --- |
| SDK deviceKey | 0x208 | 0x618 | 0x14452da12..0x14452da35 |
| NID device key | 0x5a0 | 0x628 | 0x14452de2e..0x14452de56 |

Caller читает FString count/pointer и передаёт count-1 либо 0 в assignment.
FString assignment — bounded fixture, а реальные instructions выбора полей
и вычисления длины исполнены. Искусственные source objects имеют независимые
пустые/непустые SDK и NID строки. Обе сохраняют раздельность и исходный текст.
Это не декодирование бинарного SaveGame: нужный object задан fixture.

## Post-restore dispatch

Участок `0x14452df6a..0x14452e004` проверяет global byte `0x14b4f13fd`:
если он равен fixture DIL=0, рассмотренные дополнительные вызовы пропускаются.
Если не равен, caller сравнивает qword saved object+`0x28` с `0xc41f`.
Название/окончательная семантика global и метки не установлены.

- При метке `0xc41f`: оба setter с bool=false, затем Save.
- При иной метке (fixture `0x4c9dac`): оба getter с bool=true, освобождение результатов.

Матрица 16 fixtures: SDK empty/nonempty × NID empty/nonempty × gate 0/1 ×
метка `0xc41f`/`0x4c9dac`. Getter/setter/Save — captures. Getters лишь возвращают
fixture settings, не моделируют native генерацию или registry precedence.
Все Save captures возвращают false; slice всё равно достигает конца.
Нельзя по этим fixtures обещать, что пустое значение останется пустым после
полного реального getter, или что весь Load после ошибки возвращает success.

## Constructor filenames и Load continuation

Class accessor `0x1444aacb0`: literal NMServiceSettings, `/Script/NMService`,
размер `0x7e0`; registration instruction `0x1444aad10` ссылается на thunk
`0x1444ac6c0`. При непустом объекте thunk JMP → constructor `0x1444acf40`.
Эта связь проверена статически по instructions, thunk bytes/SHA сохранены.

Native constructor slice `0x1444ad167..0x1444ad1a2` задаёт **разные** поля:

| Settings offset | Filename default |
| --- | --- |
| 0x2e8 | ServiceSettings.bin |
| 0x2f8 | ServiceSetting.bin |

Load continuation `0x14452c791..0x14452c840` берёт directory getter, учитывает
отдельный optional directory flag и дописывает filename из settings+`0x2f8`.
При R15=0 fixture получен путь
`<persistent-directory>/NetmarbleSDK/ServiceSetting.bin`.
Проверены base без завершающего слэша, Unicode base со слэшем и пустой base.
Native directory/join/slash helpers переиспользованы из
[directory replay](HEADLESS-SDK-STORAGE.md). Base getter, allocation/copy/append
и FString constructors — fixtures; optional directory gate явно выключен.

Это constructor defaults и выбранный Load path, **не активный абсолютный путь**.
Config/CDO overrides, optional directory initializer, другие варианты поиска
и использование соседнего ServiceSettings.bin ещё требуют проверки.
Реальные Saved/files/registry/device keys/токены не читались, файловых операций нет.

## Далее

Восстановить optional directory flag и suffix, источник filename overrides,
проверки Load/SaveGame parsing/type/tag, согласованную запись Save и read-back.
Параллельная зависимость авторизации — SDK sign-in response/session и штатное
подтверждение устройства. Реальная identity основной почты ещё не получена.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_load_devices.py' -v`.
Два regression tests воспроизводят оба отчёта и проверяют все 19 fixtures.
