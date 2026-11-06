# Явный кандидат внешности Viper для 1.13.22

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Пакет `viper-appearance-current-v1` подготавливает полную явно выбранную
внешность для проверки producer. Возможность использовать такой кандидат
при незаданной пользователем внешности описана в
[прежнем решении по preset object](HEADLESS-CREATE-PRESET-OBJECT.md).

Скрипт повторно разбирает сохранённые bytes двух DT_CustomizePreset и
двух связанных DA_PresetDarkMage1. Проверяются исходные references,
единственный export, его полный SHA и потребление body. Выбор выполняется
по `class_type=1` и `preset_id=1` в таблице. Полные SHA установленного
PAK и сохранённых blobs проверяются до и после сборки.
Историческая схема ресурса совпала с текущими семнадцатью native
descriptors по имени, типу и смещению. [Исходные ресурсы](HEADLESS-CREATE-VIPER-RESOURCES.md).

Для отсутствующих свойств явно выбраны значения из
[текущей ограниченной модели холодного CDO](HEADLESS-VIPER-COLD-CDO-CURRENT.md).
Сериализованные значения и их origins сохранены. Исходный
`decoded.values` продолжает содержать `null` для отсутствующих полей.
Отдельный `candidate.values` заполнен полностью.

| Поля | F | M |
| --- | --- | --- |
| HairIndex, HeadIndex, DecalColorIndex, EyeColorLeftIndex, EyeColorRightIndex | 1 | 1 |
| HairColorIndex, DecalIndex, EyeTexIndex | 0 | 0 |
| SkinColorIndex | 2 | 0 |
| Shape, Cheat, Height, Pelvis, Waist, Thigh, Head | 0.5 | 0.5 |
| VoiceType | 1 | 0 |

Каждый вариант помечен `model_only=true`,
`verified_loaded_asset=false` и `runtime_admitted=false`.
Названия F и M обозначают suffix исходного asset. Связь suffix с byte
пола, runtime Class_ tag, actual ClassInfo row ID, JSON keys, producer
и сетевой Create этим пакетом не подтверждаются.
Фактическая загрузка asset и поздние engine overrides остаются отдельным
вопросом. Текущий пакет не заявляет воспроизведение внешности экрана игры.

Новые native сценарии и JVM не запускались. Использованы готовые
source-bound proofs. Четыре теста проверяют кэш без повторного разбора,
сохранение raw unknown и serialized значений, отказ изменённых defaults,
запрет ложной loaded-asset пометки и повреждение входов.

Report имеет SHA256
`eb40161637a7ef7c96011ba011cd964812d0679e99c440f15921432b1339d6e8`
и хранится в
`F:/PhoneExit Resources/Vampir/code-clues/viper-appearance-current-v1/<SHA>/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-viper-appearance-current.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_viper_appearance_current.py
```

Для штатного обновления предусмотрена проверка
`viper-appearance-current` вопроса `viper-native-defaults-current`.
Она подключена к `on_update` через derived-proof guard с проверкой всех
`definition.inputs`. Новое native исполнение этот source check не заявляет.

## Текущая Class CSV

Готовый автоматический resource baseline уже содержит Class CSV из нового
`pakchunk1-Windows.pak`. Полный SHA установленного архива проверен повторно
и совпал с `2f2517ff83865ac13021f96d9babd8407e4fbee512ff29806106844e5d7d7ed3`.
Baseline находится в `knowledge/resource-named-baselines-v1/`
`43204e85a3d2c4f5bb11581264688ca7f1b1502206f59d36f70fd1145a55cc2d/manifest.json`
в корне ресурсов. Его `source` закрепляет этот архив, таблица имеет
`state=verified_payload` и путь `ProjectRED/Content/RED/Data/CSV/Class.csv`.

Полный SHA CSV равен
`620725b3322e37b612107286ca60d72908cccfdb32449b6a2e135e4ad3c4c8bc`.
Сохранённый blob с этим SHA проверен. Пять строк совпадают с прежней CSV,
включая `Resource=DarkMage`, `Id=1`, `Type=1`, `DefaultGender=1`.
Повторное извлечение всего архива не требуется. Эти данные не подтверждают
сами по себе native Class tag, байт пола в Create или producer.
