# Текущие BoneGroup F / M: группы и ID внешности

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [поиска definitions](HEADLESS-CREATE-APPEARANCE-ENTRY.md).

## Источники и извлечение

Полный SHA установленного `Patch/Install/pakchunk100-Windows.pak`:
`58eb7e06e05d1dae843d4f7c2e0021b311ffcaff3f26da9dd5b80783c6258ac3`.
Свежий record index получен существующим `index-release-archives.py` с этим
явным SHA и release snapshot `2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08`.
Record manifest SHA256:
`3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc`.
Декодированы 3432 записи; отсутствие ошибок не доказывает полный directory index.

Новый `extract-release-appearance-resources.py` читает только две точные
ссылки BoneGroup F / M и по одному соседнему record. Проверяются полный SHA
PAK до / после, хеши декодированных записей, закреплённые reader / Oodle,
package self path, тип DataTable, row struct reference, границы и полный размер
export body. Соседние тела проходят структурную проверку, но их filename pairing
через аутентифицированный directory index ещё не доказан. Это явно сохранено
как `archive_directory_pair_verified=false`, без переноса старых offsets.

## Схема текущего EXE

Type registration `0x145452bb0` ссылается на
`NnDataTableRowForBoneCustomizeGroup` и constructor `0x145457040`.
Последний использует struct params `0x14b1b2e30`; property array находится
по `0x14984b218`. Четыре descriptors: GroupName / ID / BoneNameIDs inner /
BoneNameIDs array. Inner descriptor не является отдельным сериализованным полем.

| Поле | Gen flags | Object offset | Чтение |
| --- | --- | --- | --- |
| GroupName | 20 | 8 | FName |
| ID | 3 | 16 | int32 |
| BoneNameIDs inner | 21 | — | FString |
| BoneNameIDs | 22 | 24 | массив FString |

Инструмент сверяет точные descriptor pointers, имена, flags и offsets с
SHA-проверенным EXE. DataTable prefix связывает row struct import; каждая строка
имеет три explicit unversioned поля. Поддержаны только наблюдённые заголовки,
bounded ASCII/UTF-8 FString и FName number 0. Прочитаны все export bytes;
неизвестный layout, хвост, дубли ID / row names и усечения отклоняются.

## Содержимое

Обе таблицы имеют семь групп:

| ID | GroupName | BoneNameIDs F | BoneNameIDs M |
| --- | --- | --- | --- |
| 1 | Height | 1 | 1 |
| 2 | Chest | 3 | 5 |
| 3 | Pelvis | 2 | 7 |
| 4 | Shape | 21 | 23 |
| 5 | Waist | 2 | 2 |
| 6 | Thigh | 6 | 6 |
| 7 | Head | 1 | 1 |

Примеры: Height → Root; Head → Bip001-Head.
Полные списки костей и исходное написание сохранены в report, без исправления
опечаток ресурса. ID по row `+0x10` согласуется с полем, используемым entry
helper для JSON key. Это ещё не исполнение реального lookup на загруженном
engine cache и не проверка окончательного преобразования ID в строку JSON.
В BoneGroup нет диапазонов или начальных float-значений; приписывать группе
нулевое значение по отсутствию поля нельзя.

## Проверки и следующий шаг

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_appearance_resources
```

Три теста проверяют текущие F/M и повторяемость снимка, все короткие префиксы
одной synthetic строки, неправильный FName, лишний байт и повреждённый индекс.
Проверка `release-appearance-resources` подключена к workflow вместе с source PAK.
Report:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-resources/ce2664522f32a0d4ebff1098be83f77716e25bc5828a1f520239582b65827003/manifest.json`.
SHA256 совпадает с именем каталога; blobs сохранены вне Git.
Ghidra details текущего comparison: `run-f5abfef626ea` и `run-378c1d7706a7`.

Следом подтвердить directory pairing, источник диапазонов / default float и
заполнение owner map; затем actual lookup / key converter, JSON output,
whole producer и handler ID 104. В игре создание ещё не выполнялось.
