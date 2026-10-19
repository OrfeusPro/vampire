# SDK: каталог хранения, Save/Load и третий device key

19 октября 2026. Продолжение [SetDeviceKey](HEADLESS-DEVICE-SETTER.md).
Источник — собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Воспроизведение и provenance

`build-headless-sdk-storage.py` экспортирует 26 unwind fragments: Save,
Load(bool), Initialize, path helpers и отдельные NID device getters/setters.
Initializer references проверены по decoded instruction boundaries.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-storage.json`,
SHA256 `7d262be2ea2d283dc96dd4070dd219a319fe5906b570307359010bcf0f86bb43`.
Содержит instruction bytes/file offsets/fragment SHA и tool SHA.
Это статический индекс, не исполнение Save/Load.

`replay-sdk-storage-path.py` исполняет path getter `0x144520bd0`, predicate
`0x140bb4a10`, wrapper `0x14157fce0`, join `0x14156f6b0` и slash append helper
`0x14142c9d0`. Базовый directory getter `0x1414459a0` — fixture.
FString constructor/append/allocation/copy/free — явные подстановки.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-storage-path-replay.json`,
SHA256 `df507d52bfdcf3322466a83f1fa6d2dd5e023a788acbc9146b31acfd980ca4fe`.

## Проверенный каталог

Predicate — leaf bytes `B0 01 C3` (возвращает true), а не предположение о platform.
Поэтому в данном EXE path getter выбирает wrapper `0x14157fce0`, который
получает wide base от `0x1414459a0`, затем native join добавляет `NetmarbleSDK`.
Строка suffix взята из global `0x14b4f1408`; initializer `0x1411b5900`
связывает его с literal `NetmarbleSDK` через FString constructor.

Шесть fixtures: base без слэша, с `/`, с `\`, кириллица, пустой base,
Windows base без завершающего разделителя. Native join сохраняет имеющиеся
разделители, а при необходимости вставляет `/`; нормализации пути не заявляется.
Пустой fixture base даёт `NetmarbleSDK`, не доказан реальный пустой base.

В статическом helper `0x1414459a0` виден cache object+`0x58` и fallback:
`0x14157fd60` (источники Saved и saveddirsuffix) → append `PersistentDownloadDir`.
Этот fallback не исполнялся: нельзя выдавать его за активный абсолютный путь.
Результат path getter — **каталог**, не полный путь settings-файла.
Save/Load отдельно дописывают filename из service settings+`0x2f8` и
условные значения. Их окончательный формат и active filename ещё открыты.

Дополнение: [NID web/token mapping проверен native pair replay](HEADLESS-NID-DEVICE-CONTEXT.md).
Registry v2 теперь хранит отдельный NID key; исходный static index ниже
сохраняет прежние границы исследования.

## Отдельный DeviceKeyForNetmarbleId

| Поле | Getter | Setter | Settings offset | Storage key |
| --- | --- | --- | --- | --- |
| deviceKey | 0x144522820 | 0x14454b390 | 0x618 | DeviceKey |
| NID device key | 0x144522b50 | 0x14454b5c0 | 0x628 | DeviceKeyForNetmarbleId |

Второе имя доказано diagnostic literal GetDeviceKeyForNetmarbleId(bool),
initializer global `0x14b4f1a98` и отдельными source branches. Getter использует
свой storage key, поле settings и GUID fallback. Load также восстанавливает
settings+`0x628` и вызывает соответствующий setter (`0x14452dfb9`).
Эти ветви пока только декодированы, отдельный native replay ещё не выполнен.

Нельзя объявлять этот NID key равным nmDeviceKey либо deviceKey из SDK sign-in.
Одного имени функции недостаточно для web binding. В последующем
[NID context replay](HEADLESS-NID-DEVICE-CONTEXT.md) проверены caller/getter/pair
для web и OAuth. Schema v2 теперь хранит отдельный NID key/source, без real
значений. Полный web URL → JS context и getter lifecycle ещё открыты.

## Save/Load: подтверждённые границы

Initialize заканчивается переходом `0x14452a5b9 → Load 0x14452c6e0`.
Load имеет путь поиска/LoadFileToArray и отдельные ветви восстановления данных.
Save `0x14453cdf0` создаёт SaveGame object, содержит SaveGameToMemory,
SaveArrayToFile и повтор после создания каталога. Поля/аргументы и вызовы
сохранены в отчёте, но полная сериализация и успех файловых операций не проверены.
Данные Save шире пары device keys: не читать/копировать весь профиль ради identity.
Содержимое токенов, файлов Saved, registry и память процессов не использованы.

Далее: native path/filename continuation, Save/Load field mapping,
NID getter caller → web context и active platform/SDKZone.
Реальные ключи основной почты, её game account и device confirmation не получены.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_storage.py' -v`.
Два теста воспроизводят static report и шесть native directory fixtures.
