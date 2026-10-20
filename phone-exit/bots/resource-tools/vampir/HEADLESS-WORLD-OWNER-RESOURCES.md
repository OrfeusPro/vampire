# Классы владельцев загрузки и данные GameMode

20 октября 2026. Продолжение [вызова владельца](HEADLESS-WORLD-OWNER-DISPATCH.md).
В текущем PAK проверено наследование восьми GameMode Blueprint. Для четырёх
native-классов подтверждена цепочка регистрация → конструктор → таблица →
слот `+0x7b0`. Это связывает ранее проверенные владельцы с именами классов,
но ещё не доказывает выбор класса конкретным уровнем после ID110.

## Источники и воспроизведение

Код клиента: `ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe` в
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект.

Текущий архив: `ProjectRED/Saved/PersistentDownloadDir/Patch/Install/pakchunk100-Windows.pak`
в той же установке; размер 5 520 744 байта.
SHA256: `0d919ea09eea374fa17e4e8145a70570adb8ca9c48743926b1ee6938c46b3669`.
Старый `pak-extracted/pakchunk100-Windows/source.json` относится к другому
содержимому; его смещения не использовались.

Использован существующий снимок свежего поиска записей в `release-snapshots`.
SHA256 его `manifest.json`:
`a6660a69d4b045fd19b8880aae3d6bab9a30e087a0cac2a7da07f73f3566de34`.
Зашифрованный каталог PAK не разобран. Пары записей проверены существующими
`inspect-ui.py` и `decode-package-references.py`: полные границы экспортов,
имя пакета, generated class, его CDO и ссылка superclass. Смежность записей
сама по себе не принимается за доказательство пары.

Ghidra 12.1.4: 207 функций, 86 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-ee78b53c77bd`.
SHA256 манифеста:
`b62feb6e2778002be5e28a397b785dcbc4dbe49ce3bc75105ee4d2e5a4fb532e`.
SHA256 `functions.json`:
`73ab223628f050993652f7e9c478c2d4dd9ae349c44883a22bf5f858f035838a`.
Регистрации прочитаны в Ghidra и сверены с машинными инструкциями.

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-world-owner-resources.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/world-owner-resources.json`.
SHA256: `ea85196cbc14de76b1579ff1047d1e40da04f8e94031208e54d6f791bc8bc418`.
Он хранит SHA декодеров, смещения записей, хеши распакованных частей, исходные
байты ссылок superclass и инструкции регистрации / записи таблицы / слота.
Данные и инструменты исследования не добавляются в runtime бота.

## Наследование из cooked-пакетов

Все пакеты находятся в `/Game/RED/Blueprint/GameMode/`.
Имена ниже получены из таблиц экспортов и импортов, не из сходства строк.

| Запись asset | Blueprint | Native superclass |
| --- | --- | --- |
| 1456 | `BP_GM_Arena` | `/Script/ProjectRED.RdGameModeInArena` |
| 1458 | `BP_GM_CharacterCreate` | `/Script/ProjectRED.RdGameModeCharacterCreate` |
| 1460 | `BP_GM_CharacterSelect` | `/Script/ProjectRED.RdGameModeCharacterSelect` |
| 1462 | `BP_GM_ConquestOccupation` | `/Script/ProjectRED.RdGameModeInConquest` |
| 1464 | `BP_GM_ConquestRaid` | `/Script/ProjectRED.RdGameModeInConquest` |
| 1466 | `BP_GM_InGame` | `/Script/ProjectRED.RdGameModeInGame` |
| 1468 | `BP_GM_Temp` | `/Script/ModularGameplayActors.ModularGameMode` |
| 1470 | `BP_GM_Title` | `/Script/ProjectRED.RdGameModeTitle` |

Тела свойств CDO не декодированы. Наличие ссылки на класс в уровне не считается
значением активного GameMode без проверки соответствующего свойства.

## Регистрация и таблицы методов

| Native-класс ProjectRED | Регистрация | Конструктор | Таблица | Цель слота `+0x7b0` |
| --- | --- | --- | --- | --- |
| `RdGameModeCharacterSelect` | `0x1468e0810` | `0x1468e29a0` | `0x149e0e7c8` | `0x1468f1d70` |
| `RdGameModeInGame` | `0x1468de1b0` | `0x1468e2aa0` | `0x149e0f1f0` | `0x1468f1e90` |
| `RdGameModeInArena` | `0x1468de400` | `0x1468e2a20` | `0x149e0fc10` | `0x1468f1e90` |
| `RdGameModeInConquest` | `0x1468de8f0` | `0x1468e2a60` | `0x149e10630` | `0x1468f1e90` |

Регистрация передаёт имя класса, `/Script/ProjectRED` и указатель конструктора
в `0x1416a5d60`. Конструктор получает объект через `[RCX]`, вызывает общий
базовый конструктор и записывает проверенную таблицу в начало объекта.
Для Arena / Conquest между загрузкой адреса таблицы и её записью находится
обнуление `+0x3e0`; регистр адреса таблицы сохраняется.

Путь слота выбора к ID101 и игровых слотов к подготовке ID205 был проверен
ранее в native replay. Новый отчёт добавляет статическую связь с регистрацией
и cooked-наследованием; повторного исполнения этих сценариев он не выполняет.

## Записи указателя владельца

В уже экспортированном `OwnerDispatch_CandidateD` / `0x14432beb0` найдены:

- `0x14432c7b4`: `mov [rbx+0x158], r13`. Получатель загружается из
  `[rsi+0x78]`; сохраняется объект, оставшийся после обхода прежних объектов.
- `0x14432cdab`: `mov [r14+0x158], rbx`. Сохраняется результат вызова
  `0x14432cd90: call rbx`; цель перед этим взята из таблицы объекта
  `[new_world+0x1d8]`, слот `+0x3d0`.

Между фабричным вызовом и сохранением возможен вызов `0x1416dceb0`;
результат заранее сохранён в RBX. Обе записи подтверждены статически и не
исполнены. Исходные имена функции, provider и его фабрики не восстановлены.

Следующий шаг — установить тип provider и выбор класса в слоте `+0x3d0`,
затем связать его с данными нужного уровня. Полное исполнение движка не является
требованием runtime: боту нужны подтверждённые условия продолжения протокола.
Реальный вход, подтверждение устройства и мировая позиция остаются открытыми.
