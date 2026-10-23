# Пол: Male 0 → M, Female 1 → F

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [пресетов Carnage](HEADLESS-CREATE-CURRENT-PRESETS.md).

## Источник и уточнение прежнего вывода

Getter `0x144aabaf0` использует builder `0x144aabff0` и params
`0x14b197320`. Params содержат имя / C++ type `EGenderType`, три записи
из `0x1496703b8` и CppForm 2. В каждой записи pointer на ASCII-имя и int64:

| Имя | Значение |
| --- | --- |
| EGenderType::Male | 0 |
| EGenderType::Female | 1 |
| EGenderType::Max | 2 |

`replay-release-gender-paths.py` проверяет эти pointers, имена, значения,
число записей и поле params по полному SHA EXE. FName tokens и UEnum object
для replay — явные fixtures, построенные из проверенных записей.
Полный runtime builder UEnum здесь не исполнялся.

В прежнем [разборе entry helper](HEADLESS-CREATE-APPEARANCE-ENTRY.md) было
неверно указано «удаляет начальный символ». Новая проверка уточняет этот
вывод: `0x141434a50` — удаление диапазона. При аргументах start 1 и
count `length-1` он удаляет хвост, **сохраняя первый символ**.
Старый документ сохранён как evidence прежнего этапа с его исходным SHA;
для текущей семантики использовать этот результат.

## Что исполняется

Целые path helpers `0x145671130` (preset) и `0x14566c5e0` (BoneGroup)
вызывают native `0x1416dd790`, который ищет enum по int64 value.
Затем `0x1416dd6b0` получает имя и для scoped enum отделяет namespace;
native `0x141438260` вычисляет substring после `::`.
Далее native `0x141434a50` оставляет первую букву перед форматированием.

| Value | Имя после namespace | Суффикс | Основание для создания |
| --- | --- | --- | --- |
| 0 | Male | M | Значение пола |
| 1 | Female | F | Значение пола |
| 2 | Max | M | Sentinel, не допустимый пол |
| 3–255 | пусто | пусто | Нет enum-записи |

При недоступном enum оба helper также формируют путь без суффикса.
Ни M для Max, ни отсутствие ошибки не доказывают допустимость значения.
В runtime перед созданием нужно разрешать только подтверждённые значения пола.

1024 bounded native случая: два целых helper × enum present / absent ×
все 256 byte-значений. Проверены порядок lookup, суффикс, форматирующий
literal, возвращаемая FString и guards результата.
Для valid gender получаются пути `Customize/DT_CustomizePresetM/F`
и `Customize/DT_CustomizeBoneGroupM/F`.

FName-to-string, поиск `::`, выделение / копирование / освобождение строк,
форматирование и CRT memmove — ограниченные fixtures / captures.
У memmove отдельно проверены import thunk и `vcruntime140.dll!memmove`.
Native-код сам выбирает индекс / имя, рассчитывает substring и диапазон
удаления; форматирующий fixture получает уже вычисленный суффикс.
Выход форматирования не является исполнением полного engine printf.

Ранее текущий ClassInfo подтвердил DefaultGender 1 для Gunner / Carnage.
Поэтому эта цепочка связывает его с **F**, preset ID 3 и ресурсом
DA_PresetDarkMage3_F. Ссылки и ограничения активного cache приведены в
[разборе пресетов](HEADLESS-CREATE-CURRENT-PRESETS.md); загрузка engine-ресурса
целиком этой проверкой не подтверждается.

## Оставшиеся defaults и проверки

Исследованный base constructor `0x143b5fa80` вызывает UObject constructor
`0x1417cbc10` и задаёт базовый pointer `+0x28`. Тот устанавливает vptr и
контекст инициализации. Прямой записи отсутствующих preset int32
`+0x30`–`+0x50` в этих двух функциях не найдено. Это не доказывает значения
всего CDO: ещё требуется его allocation / zero initialization / default copy.
Не заменять отсутствующие int32 нулями по результатам этой ветки.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gender_paths.py
```

Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-gender-paths/f76bedd20e3f358e3d02a163d349152fd38264771401b7d5656be9e5532c2c6d/manifest.json`.
SHA256 совпадает с именем каталога. Comparison:
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details:

| Run | SHA256 details.json |
| --- | --- |
| run-29d6ad1c7c55 | 4310f3e2818acc70b48594790eea46aa9f996529ceaf782fce06ba36cd60d2e2 |
| run-c1cdaeaa2d5d | 91313b2e519a3672685d7895ec3525cf7c61dd5b0446c38733ba8dbf817b4941 |
| run-a765429bb389 | 17d731903385244bf3ebe84b5f537b4e21ca2a43cabc888bde4cedd4594baa49 |

Далее — actual CDO int32 defaults и scale / min / max ползунков, затем
actual key conversion / JSON output, целый producer и handler ID 104.
Сеть, авторизация и создание персонажа не выполнялись.
