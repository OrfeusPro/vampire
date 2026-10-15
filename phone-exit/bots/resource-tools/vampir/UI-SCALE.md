# Пресеты UI Scale, настройка и границы восстановления DPI

15 октября 2026. Основной указатель: [README бота](../../vampir/README.md).
Размеры и иерархия: [UI-CATALOG.md](UI-CATALOG.md).

## Подтверждённая цепочка

`build-ui-scale-reference.py` проверяет SHA256 EXE и всех CSV, затем соединяет:

1. Native **EOptionType::DisplayUIScale = 137** с исходным дескриптором.
2. CSV pakchunk1 entry **1429**, логическая запись **81**, OptionType=137.
3. OptionGroupInfoId **32300** → OptionGroup entry1430 → OptionSubTabInfoId
   **32000**, entry1433 → OptionMainTabInfoId **30000**, entry1431.
4. Английские подписи entry **488**, запись **67**, OptionType=DisplayUIScale:
   `Very Small`, `Small`, `Normal`, `Large`, `Very Large` в исходном порядке.
5. Константы entry **68**, записи **329–353**, Key/ValueType/Value:
   25 коэффициентов, пять уровней для каждого профиля.

Три связи Option→OptionGroup→OptionSubTab→OptionMainTab отдельно подтверждены
нативными диагностическими строками проверки ссылок в EXE: смещения
161071746, 161069378, 161075314. Исходные тексты сохранены в
`declared_table_links` отчёта, не заменены интерпретацией имени колонки.
Parent=205 соответствует **EOptionType::Max**; это имя enum, не проверка
снятой блокировки и не доказательство произвольной семантики Parent.

Результат: `F:/PhoneExit Resources/Vampir/ui-geometry/ui-scale-reference.json`.
В каждой строке — исходный CSV/запись и хеш; для native enum — смещения и значение.

| Профиль из Key | VerySmall | Small | Normal | Large | VeryLarge |
|---|---:|---:|---:|---:|---:|
| PC | 0.6 | 0.7 | 0.8 | 0.9 | 1.0 |
| IOS | 0.6 | 0.7 | 0.8 | 0.9 | 1.0 |
| AOS | 0.6 | 0.7 | 0.8 | 0.9 | 1.0 |
| IOSTablet | 0.7 | 0.75 | 0.8 | 0.85 | 0.9 |
| AOSTablet | 0.7 | 0.75 | 0.8 | 0.85 | 0.9 |

В Option137 записаны DefaultValueForAOS=**4**, ForIOS=**4**, ForWin=**2**.
При предполагаемой нумерации подписей с нуля это VeryLarge/1.0 для AOS/IOS
и Normal/0.8 для PC. Это **кандидатная интерпретация**, а не восстановленный
нативный обработчик индекса. Активное сохранённое значение телефона не прочитано;
оно может отличаться от исходного default.

WidgetType=0, SaveDB=0, SaveTargetType=3 сохранены без догадок о типе контрола
или месте хранения. В таблице пресетов качества entry1432 нет строки Type137:
это проверено только для этой таблицы и не исключает изменений во время игры.
В отчёте есть 30 вариантов ресурсных кандидатов WBP_OptionUI, OptionGroup и
OptionSetting из общего каталога. Прямая связь WidgetType0→конкретный WBP
ещё не доказана; не считать его автоматически Dropdown или Tab.

## Пресет не равен DPI

Нативный enum **EUIScalingRule** восстановлен: ShortestSide0, LongestSide1,
Horizontal2, Vertical3, ScaleToFit4, Custom5. Имена GetViewportScale,
ApplicationScale, UIScaleRule, CustomScalingRuleClass, UIScaleCurve есть в EXE;
точные смещения сохранены в native_literals. Это подтверждает наличие понятий
и имён в клиенте, но не активное правило/кривую и не способ их комбинирования.

`find-ui-scale-config.py` проверил пять startup/data PAK: ProjectRED-Windows,
pakchunk0-Windows, pakchunk0_s1-Windows, pakchunk0_s2-Windows, pakchunk100-Windows.
Просмотрено **20477** подходящих незашифрованных записей до 4 MiB, ошибок 0.
**150 зашифрованных записей пропущены**. Единственный результат — уже известная
таблица констант ProjectRED entry6080; параметров DPI-кривой в проверенном
наборе не найдено. Это не полный поиск всех архивов и не исследование Android APK.
Отчёт: `code-clues/ui-scale-config/index.json`, найденный файл сохранён с хешем.

Системные ResolutionSizeX/Y в локальном Windows GameUserSettings.ini не являются
данными экрана телефона или доказательством коэффициента UI. Они не используются
для Android. Нельзя просто принять 720/1080 или коэффициент Normal за DPI.

## Воспроизведение и следующий шаг

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/find-ui-scale-config.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-scale-reference.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ui-links.py
```

Проверить native handler Option137/WidgetType0 и активную настройку/viewport
Android; затем сопоставить минимум несколько независимых якорей с ресурсной
геометрией на свежем кадре. Сохранённые кадры пока не доказывают единую формулу
для HUD и всех попапов. В бот не добавлены предположительные координаты,
новый глобальный коэффициент или дорогостоящий перебор всех пресетов.
