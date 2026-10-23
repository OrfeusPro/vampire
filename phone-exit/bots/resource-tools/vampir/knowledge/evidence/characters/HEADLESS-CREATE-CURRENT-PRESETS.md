# Текущие пресеты Carnage: ссылки, значения и неполные defaults

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [фильтра по классу](HEADLESS-CREATE-APPEARANCE-MAP.md).

## Источники

Установленный `pakchunk100-Windows.pak`, полный SHA256:
`58eb7e06e05d1dae843d4f7c2e0021b311ffcaff3f26da9dd5b80783c6258ac3`.
Release manifest:
`2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08`.
Record index:
`3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc`.
Имена `.uasset` / `.uexp` берутся из [проверенного каталога](HEADLESS-CREATE-BONEGROUP-DIRECTORY.md),
а не из соседства записей. Проверяются полные source / decoded SHA, reader /
Oodle, package identity, export class и все export bytes. Blobs остаются вне Git.

## Схемы текущего EXE

`RdDataTableRowForCustomizePreset`: registration `0x145c86320`, params builder
`0x145c8c9d0`, params `0x14b1cc1c8`, property array `0x149a25788`.
Собственные поля: `RecommandClassType` (byte enum, offset `0x48`) и `Memo`
(FString, `0x50`). `UnderlyingType` — внутренний descriptor enum, не отдельное
сериализуемое поле. Super getter `0x14545dd00` использует params `0x14b1b3060`,
array `0x149858498`: ID `+8`, PresetDataAsset `+0x10`, IconTexture `+0x18`,
Order `+0x40`. Базовый row type имеет размер `0x48`, производный — `0x60`.

Наблюдённый unversioned порядок включает сначала собственные, затем базовые
поля: class type, memo, ID, object reference, soft icon path, order.
Decoder поддерживает только этот полный набор из шести полей с zero mask.
Icon path содержит два FName и FString subpath; ненулевой FName number
учитывается при восстановлении имени.
Полное исполнение engine schema builder / UObject deserializer не заявляется.

`NnDataAssetForCustomizePreset`: registration `0x1454d06a0`, constructor
`0x1454d6800`, размер `0x78`, property array `0x1498b5ff0`.
Девять int32 `HairIndex`–`EyeTexIndex` идут по offsets `0x30`–`0x50`;
семь float — `0x54`–`0x6c`; VoiceType byte enum — `0x70`.
Инструмент сверяет pointers, имена, gen flags и offsets descriptors с EXE.
Имя `Cheat` сохранено буквально из descriptor; не исправлять его на Chest.

## Связь с Carnage / Gunner type 3

Таблицы DT_CustomizePresetF / M содержат 16 / 13 строк. В каждой ровно одна
строка с `RecommandClassType=3`:

| Таблица | Row | ID | Ссылка на DataAsset |
| --- | --- | --- | --- |
| F | 3 | 3 | DA_PresetDarkMage3_F |
| M | 2 | 2 | DA_PresetDarkMage3_M |

Package prefix: `/Game/RED/Blueprint/DataAsset/Customize/`.
Именно ссылки таблиц, а не сходство имени файла, связывают эти assets с type 3.
Существующие DA_PresetGunner1_F/M не выбраны этими строками.
Уникальность совпадения устраняет зависимость от порядка строк в данном наборе;
активный engine cache и соответствие byte пола suffix F/M здесь не исполнялись.

## Значения связанных assets

Числа float в таблице округлены для чтения. Report хранит точный результат
float32 и источник каждого поля (`serialized`, `serialized_zero`, constructor
либо unresolved). Знак `?` означает неустановленный CDO default, не ноль.

| Поле | F | M |
| --- | --- | --- |
| HairIndex | 8 | 6 |
| HeadIndex | 9 | 3 |
| HairColorIndex | 16 | 16 |
| SkinColorIndex | 2 | 4 |
| DecalIndex | ? | ? |
| DecalColorIndex | ? | 1 |
| EyeColorLeftIndex | 2 | 4 |
| EyeColorRightIndex | 2 | 4 |
| EyeTexIndex | 9 | ? |
| Shape | 0.4 | 0.3 |
| Cheat | 0.3 | 0.2 |
| Height | 0.4 | 0.4 |
| Pelvis | 0.5 | 0.4 |
| Waist | 0.5 | 0.4 |
| Thigh | 0.5 | 0.4 |
| Head | 0.5 | 0.5 |
| VoiceType | 0 | 1 |

Целый native constructor исполнен на памяти с poison 0 / `0xa5` / `0xff`:
семь float явно становятся `0.5`, VoiceType — 0, guards сохраняются.
Все девять int32 остаются прежними. Base constructor и type lookup — fixtures.
Следовательно, отсутствие int32 в resource нельзя разрешить этим constructor;
нужно проверить actual CDO / порядок zero initialization и копирования defaults.
На основании этих результатов полный CreateData ещё не формируется.

## Воспроизведение и проверки

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-release-creation-presets.py '<record manifest.json>' --directory '<directory manifest.json>'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_presets.py
```

Четыре теста проверяют все текущие связи, повторяемость снимка, native defaults,
неразрешённые int32, каждый короткий префикс четырёх exports, лишние байты и
повреждённый index до доступа к ресурсам. Unknown layout / ref отклоняется.
Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-creation-presets/7310df60f0e364eb3625c6d5817390bc02edb920f2b262bcdae86c1caa2e8112/manifest.json`.
SHA256 совпадает с именем каталога. Ghidra comparison:
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details:

| Run | SHA256 details.json |
| --- | --- |
| run-0c0270dde1c5 | 1da2dc05fa509742f80ba09cd93d32c324c40a577eb16632c151244570e32187 |
| run-2e4ce3671ec8 | 227beefd32196b24cbf89f2d81e6195bac686005d67f6fff97e77c2ecc0998cf |
| run-3cb7258f777e | 0c71553f62ed00205bca5ae915df559afdba04a2a2002fd8893ed323d0b454b8 |

Следом — CDO defaults отсутствующих int32, byte пола → F/M и реальные
scale / min / max ползунков. Затем actual key conversion / JSON output,
целый producer и handler ID 104. Сеть и создание персонажа не запускались.
