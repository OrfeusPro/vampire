# Числовой вход Login из patch-контекста

20 октября 2026. Уточнён источник `extra_number`, DWORD Login `+0x50`.
Это преобразование строки patch-контекста после удаления первых восьми символов.
Строковый префикс в коде — `Revision`, а выбранный server ID хранится отдельно.
Фактическое значение patch-контекста в текущей headless-сессии ещё не восстановлено.

## Подтверждённый путь

`BeginGameImpl` (`0x146425730`) после выбора сервера и записи endpoint:

1. По `0x146425a7d` получает literal `Revision`, `0x14960a8c0`.
2. По `0x146425a8d` получает patch object из `title+0xb78`.
3. Передаёт descriptor `patch object+0x1b0` и длину префикса 8
   в substring helper `0x141432680` по `0x146425aac`.
4. Вызывает импорт `_wtoi` по `0x146425ac1` и сохраняет результат
   в global `0x14b520cb8` по `0x146425acb`.
5. Подготовка Login читает этот global по `0x1467a991b`
   и переносит в packet DWORD `+0x50`, как проверено ранее в
   [источниках полей Login](HEADLESS-LOGIN-PACKET-FIELDS.md).

Это patch object, а не подтверждённый текстовый контрол UI.
`Title_PatchContextSetup` (`0x146426330`) передаёт `title+0xb78`
в создание и настройку patch-контекста. Источники URL идут из CDN object
`+0xf0` / `+0x100`, уже связанных с `patchURL` / `dataURL` в
[выборе CDN-сервера](../updates/HEADLESS-CDN-SERVER-LIST.md).

В `PatchContext_LoadCallback` (`0x144aa10c0`) поле `+0x1b0` входит
во вложенную структуру от `patch object+0x198`: вызывается загрузчик
`0x144a98c50` с адресом этой структуры. Его формат и заполнение вложенного
поля `+0x18` пока не проверены. Отождествлять текст с последним числом CDN URL
или с именем установленного manifest преждевременно.

## Native-проверка

[replay-login-revision-input.py](../../../replay-login-revision-input.py) продолжает готовый
replay выбора сервера: исполняет BeginGame от входа до `0x146425adb`, после
сохранения числа и перед вызовами лобби. Выбор записи, native setters и store
global исполняются. Строка patch object и FString / substring helpers — явные
fixtures; преобразование делает настоящий системный `ucrtbase.dll!_wtoi`.
Импорт проверяется существующим PE reader, SHA DLL сохранён в отчёте.

Десять сценариев: пустая строка, `Revision`, ноль, `258269`, `258392`,
ведущие нули, отрицательное число, числовой префикс с хвостом, нечисловой хвост
и короткая строка. Например, `Revision42junk` даёт 42, `Revision-1` сохраняется
как uint32 max. Это native-поведение, а не политика принятия таких значений
в runtime. Во всех сценариях отдельный выбранный server ID остался 251.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/login-revision-input-replay.json`.
SHA256: `303633c72c3495517e86cd7a9608a6b1d31ed4872742c7283fb829997ddeef5f`.

[build-patch-revision-index.py](../../../build-patch-revision-index.py) проверил 176
unwind roots в окне `0x144a90000..0x144aa4000`, без ошибок линейного decode;
нашёл шесть references с displacement `+0x1b0`. В их число входят обращения
к стеку: совпадение смещения не считается доказательством типа объекта.
Окно поиска не является границей класса или полным списком записей поля.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/patch-revision-index.json`.
SHA256: `a94bf55b9f9b1aca88567d9cf61fe3766010a623b1f9d996b87529b133cb2e0c`.

## Источники и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-3f8963987038`: 385 функций, 181 предупреждение.
Manifest SHA256: `021a7b7b8da36daaf03a160c5a7af124c0d92ddfb84ae52a675fa7da4cb2c5aa`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-patch-revision-index.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-revision-input.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_revision_input.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_packet_fields.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

## Состояние и следующий шаг

Выбранная запись свежего публичного CDN snapshot
`22bb1b5e565a59b83d44dbbb6c268e06838cd4ac0b5f61c33f3b90ec06315f8b`
содержит `patchURL = {RemoteManifestAddress}/258392`.
В установленном каталоге `Saved/PersistentDownloadDir/Patch` есть имена
`ProjectRED_pakchunk…Revision258269.manifest`. Это разные наблюдения источников,
не доказательство текущего значения descriptor `+0x1b0`.

Далее — загрузчик структуры `0x144a98c50`, источник пути `0x144a96910`
и переход после завершения patch до BeginGame. Затем можно связать фактическую
ревизию с Login и проверить сервер. Нулевой extra_number в runner пока не менялся.
Новых сетевых попыток, запуска игры, создания персонажа или аккаунта не было.
