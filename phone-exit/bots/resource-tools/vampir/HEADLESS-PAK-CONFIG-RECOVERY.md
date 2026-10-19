# PAK: ключ callback, каталог и упакованный Game config

## Дополнение: основной архив и расхождение слоёв

Инструмент [recover-base-game-config.py](recover-base-game-config.py) отдельно
проверяет `ProjectRED/Content/Paks/ProjectRED-Windows.pak`, SHA256
`c10228ece0e1252bdd3ccf99fd4936e52d7a144f96c634080947d24c429e525b`,
420675245 байт. Он использует тот же native key callback, bounded index/config
парсеры и закреплённые reader/Oodle. Проверены plaintext SHA1 main/full directory,
получены 12425 имён. Path-hash side index не используется и не проверен.
Перед загрузкой native зависимостей проверяются источник и хеши зависимостей.

Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/recover-base-game-config.py`.
Отдельный указатель: `F:/PhoneExit Resources/Vampir/code-clues/base-game-config-recovery.json`.
Снимок: `F:/PhoneExit Resources/Vampir/resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json`.
SHA256 manifest равен имени каталога. Старый patch snapshot и его указатель
сохранены; отдельный файл ключа не создаётся, сетевых запросов нет.

Base DefaultGame.ini имеет SHA256
`7a50c4ccbdfddbf691ca4177156f4175618b9f650ac4dd40722fded013ffd792`.
WindowsGame.ini побайтно совпал с patch-слоем, NetworkSetting в нём нет.
В manifest сохранены source offsets, header ciphertext SHA1, payload SHA256,
исходные строки параметров и сравнение с проверенным patch snapshot.

| NetworkSetting | Основной архив | pakchunk0 обновления |
|---|---|---|
| AppVersion | 1.12.14 | 0.1.1 |
| ConfigPrefix | real | dev |
| CdnConfig | True | False |
| CdnConfigEd | False | False |
| CdnConfigUrl / QA | Те же базы без scheme | Те же базы без scheme |

Нельзя выбирать слой по похожему на production значению. Порядок mount,
момент заполнения GConfig cache и поздние overrides ещё не доказаны.
`1.12.14` — значение в конкретном INI, не установленный номер всего релиза.
`config_precedence_verified=false`, `active_runtime_settings_verified=false`,
`network_ready=false`. Следующий шаг — доказать startup/config precedence.
Три теста воспроизводят snapshot/различия и проверяют ранний отказ при
изменении архива либо patch reference до загрузки native зависимостей.

## Предыдущее извлечение pakchunk0

19 октября 2026. Найден compiled key callback, с результатом которого совпали
SHA1 основного и полного файлового каталогов свежего pakchunk0. Получены
подтверждённые имена 7067 файлов и два Game INI слоя. Активное состояние
GConfig/command-line/late overrides и сеть этим ещё не проверены.

## Источник и воспроизведение

Код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это EXE/cooked data, не исходный C++ проект.

Архив: `ProjectRED/Saved/PersistentDownloadDir/Patch/Install/pakchunk0-Windows.pak`
в той же установке. SHA256
`7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179`.
Источник сверяется с [release index](CLIENT-RELEASE-INDEX.md), SHA256
`8bf5db1a115f85b4eb7fbd2027620f459433b59450cdc62e06073ed0a2a9834e`.

Инструмент: [recover-pak-game-config.py](recover-pak-game-config.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/recover-pak-game-config.py`.
Используются закреплённые Capstone 5.0.6/Unicorn 2.1.4, optional cryptography
48.0.0 и прежний Oodle DLL с SHA256
`cba19529d0a3b5ec9c630e95652af01e123ae29a34a8a5f7507f5bcf23d9e82b`.
Reader code и DLL хешируются **до загрузки DLL**. Нет процесса игры, чтения
его памяти, файлов аккаунтов или сетевых запросов.

Указатель: `F:/PhoneExit Resources/Vampir/code-clues/pak-config-recovery.json`.
Неизменяемый снимок:
`F:/PhoneExit Resources/Vampir/resource-config-snapshots/fa7cf1b9ef8a76bab748ef8b63bd64463dba08eca5dcd261f3f164127f241a66/manifest.json`.
SHA256 манифеста равен имени каталога. Рядом DefaultGame.ini, WindowsGame.ini,
directory.json; их SHA256 включены в manifest. Старые кеши не изменяются.
Повторный результат сверяется побайтно; повреждённый снимок не перезаписывается.

## Цепочка до ключа

| Участок | Подтверждение |
|---|---|
| Diagnostic missing key | Литерал Failed to find requested encryption key в root `0x142518910` |
| Registry и zero GUID fallback | `0x14251899a` → registry; при нулевом GUID `0x1425189b4/9d1` → getter `0x141553580` |
| Delegate consumer | Проверяет bound через virtual slot+0x30, получает 32-byte output через slot+0x58 |
| Generated initializer | `0x141291600` загружает callback `0x1468e62d0` и tail-jumps в binder `0x14155fd00` |
| Binder | Обращается к тому же getter и сохраняет callback в delegate object+0x18 |
| Key callback | `0x1468e62d0` записывает 32 байта в переданный буфер |

Регистрация/consumer — статическая цепочка; полный startup не исполнялся.
Сам callback исполнен native в четырёх guard/offset fixtures; результат одинаков,
границы 32-byte output сохранены. Memory copy/cookie helpers — bounded shims.
С результатом callback AES-256-ECB расшифровал index с **точным полным SHA1**.
Crypto выполняет отдельный backend, не native AES core.

Дополнительно найден NkPatch callback `0x144a96810`, который декодирует Base64
global FString. Его регистрация в `0x144a97f60` условна по flag bit 2; ctor
`0x144a8ed10` задаёт отдельный default Base64. Подтверждённая расшифровка
использует generated callback, а не предположение об активном NkPatch default.
Код этих roots сохранён в manifest. Runtime overrides ещё не исключены.

Отдельного файла с 32 байтами ключа нет. Manifest содержит source instructions
callback с compiled constants; это данные установленного клиента, не секреты
аккаунта/сопряжения. Ключ воспроизводимо извлекается при проверке источника.

## Проверка каталогов и файлов

Footer v11: encrypted index, GUID нулевой. Основной index: offset 334634156,
size 137680; full-directory index: offset 334948620, size 219184. Оба SHA1
совпали после расшифровки. Неиспользуемый path-hash side index не проверялся.
Full directory содержит 593 каталога и 7067 имён. Это directory-backed paths
именно этого SHA архива, в отличие от строк/record-scan гипотез прежних индексов.

Парсер проверяет FString/count/range/trailer budgets. Encoded entry decoder
поддерживает выбранный small config профиль method 0/1, максимум один block;
его поля сверяются с actual file header. Он не объявляется полным PAK reader
для всех записей. Логические mount/path strings не используются как filesystem
destination: допускаются только три фиксированных имени файлов снимка.

| Архивный путь | Offset | Получено | SHA256 payload |
|---|---:|---:|---|
| ProjectRED/Config/DefaultGame.ini | 153323520 | 12045 байт | `a07ef646c637af3884c7b71a6f5dc52c97f44ecdbe726269b798d59f8cb88255` |
| ProjectRED/Config/Windows/WindowsGame.ini | 153333989 | 96 байт | `25c84ba6856a682575c5161f19e55553ac70f329ab8efd5668c9c2ccf9720ae3` |

До decrypt/decompress проверяется header SHA1 **stored ciphertext** (до
FPakEntry.Size). Только затем вызывается bounded Oodle, проверяется точный
выходной размер и UTF-8. Проверка ciphertext SHA1 сама по себе не проверяет ключ;
его подтверждают plaintext SHA1 двух каталогов. Это исправляет границу
[предыдущего candidate probe](HEADLESS-CDN-SOURCE-PROBE.md).

## Найденные packed defaults

В DefaultGame.ini, раздел NetworkSetting:

| Key | Значение | Строка |
|---|---|---:|
| CdnConfigUrl | red.gcdn.netmarble.com/red/config/ | 14 |
| CdnConfigUrlQA | thered-qa-rzs8uww4.gcdn.netmarble.com/thered/config/ | 15 |
| AppVersion | 0.1.1 | 16 |
| CdnConfig | False | 17 |
| CdnConfigEd | False | 18 |
| ConfigPrefix | dev | 19 |

WindowsGame.ini содержит только packaging setting, без NetworkSetting override.
Это два упакованных слоя, не доказанный итог GConfig. AppVersion из этого INI
не выдаётся за версию всего установленного релиза. Базы без scheme не получают
автоматически https://; существующий строгий offline draft их отклоняет.
Значения dev/False и debug lobby defaults не выдаются за production endpoints.

В DefaultGame.ini также есть NkPatchRuntimeSettings с RemoteAddress и QA,
но они относятся к patch_root. Их семантика не подменяет CDN config URL.
Никакие найденные адреса ещё не запрашивались.

Пять новых тестов проверяют source/registration/callback replay, повтор полного
recovery/snapshot, bounded index models, отказ до native decompression при
ciphertext hash mismatch, неизменяемость snapshot и output path allowlist.

Далее: проследить NetworkSetting parameter/command-line/late overrides,
фактический выбор prefix/base/scheme и включение CdnConfig, затем связать
подтверждённую конфигурацию с SDK/session startup. `network_ready=false`.
