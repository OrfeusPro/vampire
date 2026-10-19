# Выбор базы CDN и конфигурация Game

19 октября 2026. Продолжение [источника CDN config](HEADLESS-CDN-CONFIG.md).
Разделены два разных правила: CDN ConfigPrefix использует поиск подстроки,
а SDK Zone — точное сравнение. Реальные CDN URLs пока неизвестны.

## Источник и воспроизведение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base `0x140000000`, адреса ниже — VA; версия Android неизвестна.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-selection.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_selection.py -v
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-selection.json`.
SHA256 `6550ba9156fe7d998b1cf584ac24de0cda2d71abaf219969358c1fce698dbc77`.
Он содержит source/tool/prior-report SHA, 6 unwind roots в 10 fragments,
2011 инструкций, литералы, таблицу ASCII comparison и 16 native сценариев.
Также сохранён результат ограниченного поиска в новом архиве после обновления.
Capstone 5.0.6 / Unicorn 2.1.4 закреплены существующим analysis runtime.
Игра/аккаунты/память процессов/сеть не использовались.

## ConfigPrefix выбирает CDN, Zone выбирает SDK

Initialize `0x14563f080` подготавливает поиск literal real в ConfigPrefix.
Call `0x14563f3d3` → `0x141428640` задаёт forward direction=0,
ignore-case=1, start=-1. В данном пути native Find выполняет ASCII folding,
сканирует все позиции UTF-16 и возвращает индекс или -1.
`0x1414599a0` исполняется как настоящий comparator, без shim.

Затем slice `0x14563f3e9..0x14563f424` выбирает pointer/length:

| ConfigPrefix | Выбранный источник |
|---|---|
| Содержит real без учёта ASCII-регистра | CdnConfigUrl, global 0x14b520cf0 |
| Не содержит real | CdnConfigUrlQA, global 0x14b520d00 |

В 16 native сценариях подтверждены real/REAL, пустая строка, dev, пробелы,
вхождения в начале/середине/конце, Unicode и внешне похожие буквы.
`unreal`, `pre_real_post`, `real `, `😀real` выбирают обычную базу.
Для `😀real` индекс равен 2 UTF-16 units, а не 1 Unicode code point.
`réal`, `reál`, подмена латинской буквы кириллицей не дают совпадения.
Адреса `https://normal.invalid/config` и `https://qa.invalid/config` искусственные.
Исполнены Find и ветвление; присваивание FString после branch и полный URL builder
не исполнялись. Иные режимы Find не проверялись и не реализуются общим helper.

Это отличается от [game SDK override](HEADLESS-SDK-SETTINGS.md): там строка
NetmarbleS.Zone должна целиком равняться real без учёта ASCII-регистра.
Например, unreal выбирает обычную базу CDN, но как Zone даёт SDK Dev.
Не объединять эти правила в один environment classifier.

Общий `vampir_core.sdk_config.select_cdn_config_base(prefix=..., normal=..., qa=...)`
повторяет только выбор строки. Все три значения обязательны; нет доступа к файлам,
URL validation, HTTP, fallback-адресов или предположения об активной конфигурации.
NUL отклоняется; prefix128/base4096 UTF-16 units — локальные ограничения.
Пустые базы допускаются как строки, но не означают рабочий адрес для запроса.

## Логическое имя конфигурации

Helper `0x1445bc080` передаёт global string `0x14b2743f8` в config virtual slot 0x58.
Root `0x14152ca00` создаёт для этого global строку Game: literal на
`0x14152ca91`, constructor на `0x14152ca9c`, move в global на `0x14152cac4`.
Это подтверждает связь с логической конфигурацией Game, но не конкретный
физический путь Game.ini или готовый результат объединения platform overrides.
В этом же root есть строки ConfigCacheIni.cpp; это данные собранного EXE,
а не наличие исходного C++ проекта на текущем компьютере.

После чтения строки loader вызывает `0x1445bb3a0`. В изученном коде создаётся
map entry: имя параметра, callback/контекст, ASCII hash и bucket linkage.
Полный lifecycle регистрации/изменения параметров не исполнен. Следует проверить
дальнейшие обращения к этой карте, прежде чем исключать поздние overrides.

Открытый каталог `ProjectRED/Config` отсутствует, доступный
`Engine/Config/StagedBuild_ProjectRED.ini` имеет размер 0. Именованный Game.ini
в установленном Saved/Config не найден; другие файлы профиля не читались.
Отсутствие этих loose-файлов не исключает cooked/embedded config.

## Проверка нового pakchunk0

Использован свежий [record index](CLIENT-RELEASE-INDEX.md), не старые offsets.
Archive SHA256 `7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179`.
Index SHA256 `8bf5db1a115f85b4eb7fbd2027620f459433b59450cdc62e06073ed0a2a9834e`.
Полные archive/index hashes и reader/Oodle dependencies проверены до чтения;
размер/mtime источника проверены после прохода.

В 6912 декодированных записях искались точные NetworkSetting, CdnConfigUrl,
CdnConfigUrlQA, ConfigPrefix в ASCII/UTF-16LE. Совпадений и decode errors нет.
75 encrypted records и 10 записей больше 16 МиБ пропущены; промежутки и каталог
PAK не исследованы, остальные архивы этим поиском не охвачены.
Это ограниченное отрицательное наблюдение, а не доказательство отсутствия config.
Предыдущие ресурсы не перезаписываются; отчёт не сохраняет содержимое аккаунтов.

Продолжение: [native сборка CDN URL из готовых фрагментов](HEADLESS-CDN-URL.md).
Она не подтверждает реальные bases/prefix/version или получение конфигурации.

## Продолжение

Новый результат: [bounded key/source probe](HEADLESS-CDN-SOURCE-PROBE.md).

Нужно установить физический источник Game config/актуальные URLs и prefix,
дальнейшие parameter overrides, полный builder адреса и порядок загрузки
CDN → InitSetting → GMC2 Start. Затем запросить подтверждённую публичную
конфигурацию и проверить NetmarbleS.Zone. H04b и весь вход по почте/паролю
остаются частичными; network_ready=false.
