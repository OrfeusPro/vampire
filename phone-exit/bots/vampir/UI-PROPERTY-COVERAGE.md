# Полнота характеристик: объявления и значения

Это часть [сканера автосборщика](UI-PROPERTY-SCANNER.md). Наблюдаемое поле,
объявление свойства, поддержка декодера и проверенное применение учитываются
раздельно. [Чеклист 47 объявлений](UI-NATIVE-PROPERTY-TASKS.md).

## Проверка 25 октября 2026

`audit-ui-property-coverage.py` сопоставил сохранённую схему
`code-clues/ui-properties.json` с набором наблюдений
`ae23e2f540c216777073fb621b03e668312022f9441a913bc3cb458890a24e60`.
Отчёт вне Git: `ui-property-scans/native-declaration-coverage-02.json`, ID
`e8276364ff446a4a3f83f7a52843db5098d78567c32c1593afe990f82be98abf`.

Получено 23 самостоятельных свойства Widget, 4 WidgetTransform,
16 SizeBox и 4 ScaleBox. Пять вложенных дескрипторов Widget не считаются
самостоятельными полями. У 21 объявления нет наблюдаемых значений в каталоге.
Совпадения с именами метаданных экспортов исключены из сопоставления.

Схема относится к EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Текущий файл имеет SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Совместимость не подтверждена; старые адреса в текущем EXE не читались.

Существующий декодер Widget проверен на ограниченных fixtures:
23 нулевых и 17 ненулевых значений приняты; шесть ненулевых полей пока
не поддержаны: bIsEnabledDelegate, ToolTipTextDelegate, ToolTipText,
ToolTipWidgetDelegate, VisibilityDelegate и NativeBindings.
Пустой NativeBindings принят, непустой отклонён. Это проверка ветвей декодера,
не проверка событий игры. Семейства контейнеров здесь отдельно не испытывались.

## Первый частичный разбор: прозрачность

Widget.RenderOpacity связан с `UI-23.P-265b3b280beb`:
`pakchunk500-Windows-2059.json`, export 40 / SizeBox_0 — 0.5;
`pakchunk500-Windows-47.json`, exports 66 и 67 / SizeBox_1 и SizeBox_2 —
0.4000000059604645. Полные SHA контролов и ссылки на набор есть в JSON аудита.
Применение, наследование, dynamic binding и актуальность ещё не проверены.

Отсутствующее значение не означает default. Serialized zero RenderTransform
сохраняется маркером, не превращается автоматически в единичную трансформацию.
RenderOpacity родителя, tint и alpha ребёнка требуют отдельных правил, чтобы
не применить прозрачность дважды. Чекбоксы применения пока открыты.

Повтор аудита создаёт новый файл, прежний отчёт не перезаписывается:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-ui-property-coverage.py 'F:/PhoneExit Resources/Vampir/ui-property-scans/ae23e2f540c216777073fb621b03e668312022f9441a913bc3cb458890a24e60' --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/native-declaration-coverage-next.json'
```
