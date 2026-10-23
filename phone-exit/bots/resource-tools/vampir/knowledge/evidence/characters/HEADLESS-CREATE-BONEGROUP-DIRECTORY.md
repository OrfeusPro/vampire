# BoneGroup F / M: точные имена файлов текущего PAK

23 октября 2026. Продолжение [разбора групп](HEADLESS-CREATE-BONEGROUP-RESOURCES.md).
EXE SHA256: `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Полный SHA256 `pakchunk100-Windows.pak`:
`58eb7e06e05d1dae843d4f7c2e0021b311ffcaff3f26da9dd5b80783c6258ac3`.
Release manifest: `2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08`.

## Проверенная связь

`recover-release-game-config.py --directory-only` повторно использует существующее
восстановление кандидата ключа из исторического EXE. Основной индекс и полный
каталог текущего PAK расшифрованы; их SHA1 совпали с записанными в архиве.
Проверены все 3432 имени. Это подтверждает чтение данного каталога, но не привязку
исторического key callback в текущем EXE. Ключ не выводится и не сохраняется.
Path-hash side index отдельно не проверялся.

Путь в каталоге начинается с
`ProjectRED/Content/RED/Blueprint/DataTable/Customize/`.

| Имя файла | Encoded entry offset | Record | Смещение в PAK |
| --- | --- | --- | --- |
| DT_CustomizeBoneGroupF.uasset | 12696 | 1018 | 948224 |
| DT_CustomizeBoneGroupF.uexp | 12708 | 1019 | 949252 |
| DT_CustomizeBoneGroupM.uasset | 12720 | 1020 | 950272 |
| DT_CustomizeBoneGroupM.uexp | 12732 | 1021 | 951300 |

Encoded entries сопоставлены с физическими смещениями свежего record index.
Размеры, метод сжатия и флаг шифрования совпали. Извлечение теперь выбирает обе
части по точному имени; соседство записей не используется. Затем сохраняются
прежние проверки source / decoded SHA, package identity, схемы и всех export bytes.
`archive_directory_pair_verified=true` относится только к этим двум пакетам.
Обе таблицы вновь дали по семь групп с ID 1–7 и теми же списками костей.

## Материалы и повторение

Внешняя библиотека: `F:/PhoneExit Resources/Vampir/`.
Каталог и encoded entries сохранены в
`resource-config-snapshots/3c1151930e190baf7fb7093c976222e4c2e053bef816c077e689c8a4b1de44a3/`.
Новый результат извлечения:
`code-clues/release-appearance-resources/d9cb15b5ad9152c141faf09ac202ae2924f1f5340a0de8675746efbf5fa3fbe8/manifest.json`.
SHA256 каждого manifest совпадает с именем его каталога. Предыдущие снимки
и тела `.uexp-candidate` сохранены; подтверждённые тела записаны как `.uexp`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/recover-release-game-config.py '<release manifest.json>' --archive '<pakchunk100-Windows.pak>' --directory-only
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-release-appearance-resources.py '<record manifest.json>' --directory '<directory manifest.json>'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_appearance_resources.py
```

Пять тестов охватывают текущие F/M, повторяемость снимка, усечения и недопустимые
поля строки, повреждение manifest / каталога / encoded entries, чужой SHA PAK,
дубли смещений, отсутствующую запись и несовпадение размера. Перестановка записей
и несмежные искусственные номера подтверждают отсутствие зависимости от соседства.
Три теста прежнего recovery и 12 тестов research workflow также прошли.
Workflow учитывает directory manifest, оба файла каталога и фактический полный
SHA исходного PAK перед использованием кэша и после проверки.

## Что ещё неизвестно

В BoneGroup нет диапазонов и начальных float-значений. Следующий шаг — найти
их источник и заполнение owner map, затем проверить реальный lookup, преобразование
ID в JSON key, JSON output, целый producer и handler ID 104. Сеть, авторизация
и создание персонажа этой проверкой не запускались.
