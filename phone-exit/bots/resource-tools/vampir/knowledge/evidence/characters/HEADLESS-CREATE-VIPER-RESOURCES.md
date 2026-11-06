# Ресурсы Viper: выбор по классу, пресету и полу

6 ноября 2026 года. Это извлечение ресурсов установленного архива по исторически
проверенной схеме, отдельно от native consumer и допуска Create текущего EXE.
Игровой вход и создание персонажа не выполнялись.

## Источники и выбор

Installed `Patch/Install/pakchunk100-Windows.pak` имеет полный SHA256
`58eb7e06e05d1dae843d4f7c2e0021b311ffcaff3f26da9dd5b80783c6258ac3`.
Он совпадает с прежним источником именованных ресурсов; до и после извлечения
проверяется полный SHA. Используются проверенные record / directory manifests
из [пакета исходных пресетов](HEADLESS-CREATE-CURRENT-PRESETS.md).

Происхождение схемы и root конструктора `0x1454d6800` — EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Проверены полные тела, descriptor bytes этого сохранённого EXE, package identity,
native class / CDO import references, export ranges и decoded SHA. Такое чтение
не подтверждает native layout другого EXE или его текущие defaults.

`extract-release-creation-presets.py` принимает `--class-type`, `--preset-id`
и `--gender F|M`. Выбор выполняется по полям строк таблицы, а не по похожему
названию DataAsset. Несколько совпадений без явного ID, отсутствие, чужая ссылка
и дублированная таблица отклоняются.

Для DarkMage / Viper `class_type=1` найдено по одной строке: ID 1 в обеих
DT_CustomizePresetF / M. Ссылки:

| Пол | DataAsset | uasset SHA256 | uexp SHA256 |
| --- | --- | --- | --- |
| F | DA_PresetDarkMage1_F | `0bab3fbefd2564b05cd9cbcbdb39e6a462c68a013956757e497f58fb7d8c3691` | `17131e9662fbbf8e612985c170c68108ed4067e610a690f4220f6dc77e2135f1` |
| M | DA_PresetDarkMage1_M | `213a083e1f09b603a68bae71a8328b16840f16f3f279a33d334f85b4063b41f2` | `f4c30a65179a7e9734f37418815e88c5c5bc67227deae84a0848880d73379f0a` |

Общий package prefix — `/Game/RED/Blueprint/DataAsset/Customize/`.
Раздельная [таблица классов](HEADLESS-CREATE-CURRENT-CLASSES.md) исторического
пакета связывает DarkMage с raw ID 1 / DefaultGender 1. Восстановление этого
native ClassInfo consumer на новом EXE ещё требуется.

## Значения и неизвестные defaults

В `--resource-only` native сценарии не запускаются. Значения, отсутствующие в
serialized properties, остаются `null`; ни constructor defaults, ни модельные
нулевые int32 из старого EXE не подставляются. Явный serialized zero остаётся 0.
Обычный прежний режим Carnage сохраняет свои прежние границы проекции defaults.

В обоих Viper assets явно записаны HairIndex=1, HeadIndex=1,
DecalColorIndex=1, EyeColorLeftIndex=1 и EyeColorRightIndex=1.
У F также SkinColorIndex=2 и VoiceType=1. HairColorIndex, DecalIndex, EyeTexIndex
и семь float отсутствуют. У M дополнительно отсутствуют SkinColorIndex и
VoiceType. Поэтому полноценный Viper payload из этих данных пока не формируется;
внешность Carnage и её VoiceType=0 нельзя просто перенести с заменой class ID.

## Проверки и автоматическое обновление

Новый узкий вопрос `character-creation-resource-selection` и source check
`creation-resource-selection` закрепляют parser / selection и старую схему.
Отдельный immutable resource report передаётся scoped workflow как `--context`.
Сам extractor проверяет полный SHA installed PAK до / после извлечения.
Scoped allowlist не включает этот installed путь: source check не делает из
сохранённого отчёта новую проверку свежести архива при каждом последующем запуске.
Для runtime publication нужен отдельный resource guard / admission; его здесь нет.
Это не повтор всей очереди исторических native creation checks: её старые
installed archives уже изменились. Новый fixture-модуль
`test_vampir_creation_resource_selection` зарегистрирован в MODULES и отдельной
tooling-группе с зависимостями extractor / decoder. Он проверяет выбор,
неоднозначность, неполные таблицы, неверные опции, unknown / serialized zero,
каждый короткий префикс synthetic тела и запрет чужих ссылок.

Воспроизведение: исходные `record_index` / `directory` из прежнего пакета,
параметры `--class-type 1 --preset-id 1 --resource-only`; отсутствие `--gender`
разбирает F и M. Повтор использует те же bytes / SHAs, не запускает JVM / native.
Report: `F:/PhoneExit Resources/Vampir/code-clues/release-creation-presets/51c6b5099131164882fc7cbb69b24cf5e0a7a64710954ee7bd7fa26f1c7f8c8f/manifest.json`.

Следующий блокер: native defaults Viper на текущем EXE, ClassInfo / preset consumer,
перенос Create 103 / Result 104 и producer, затем один живой контроль с новым
списком персонажей. Runtime guard и сетевой Carnage-only adapter этим пакетом
не расширяются. Новый SHA / layout / несколько совпадений должны оставлять
конкретный blocker, а не подставлять прежнюю внешность или адрес.
