# Каталог окон и интерфейса Vampir

Настройка масштаба и границы восстановления DPI: [UI-SCALE.md](UI-SCALE.md).
Найденные пресеты не подменяют активный DPI или геометрию окна.

15 октября 2026. Правило разработки: сначала источник и связи, затем кадр телефона.
Главный указатель: [README бота](../../vampir/README.md).

## Полный найденный набор WidgetBlueprint

Команды из корня проекта:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-ui.py --tutorial-controls --all-widgets
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-canvas-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-panel-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-topology.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-ui-properties.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-size-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-scale-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-catalog.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-window-bindings.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ui-links.py
```

Библиотека `F:/PhoneExit Resources/Vampir`:

- `ui-layout-study/index.json`: 2534 разобранных пакета по найденным ссылкам
  `/UI/.../WBP_*`, ошибок разбора 0. Ссылка в пакете может указывать на зависимость,
  поэтому её нельзя автоматически считать именем корневого окна.
- `ui-catalog/index.json`: 2376 записей WidgetBlueprintGeneratedClass,
  1764 уникальных ресурсных пути. Варианты архивов сохранены отдельно;
  активный вариант Android автоматически не выбирается.
- 363 уникальных пути попапов/сообщений, 534 варианта с учётом архивов.
  117916 записей контролов относятся к вариантам, а не к уникальным кнопкам.
  160 записей не стали корневыми окнами: причина хранится в `ignored`.
- `ui-geometry`: 37025 Canvas-слотов и 34960 других принятых слотов.
  Исходный порядок 71985 дочерних ссылок найден у 35632 родителей.
  Неоднозначных массивов среди принятых групп нет. Неподдержанные слоты
  не включаются в число доказанных связей; причины остаются в `failures`.

Для поиска открыть `resource_variants` по полному пути ресурса; затем JSON
варианта в `ui-catalog/`. Там находятся исходный PAK/entry/хеши, экспорт класса,
имена/типы контролов, смещения и SHA256 экспортов, локальные слоты и цепочки
родителей. Разные классы в одном пакете имеют разные `-root-<id>.json`.
Пользоваться файлами из index.json, а не старыми файлами по маске каталога.

## Какие размеры доказаны

В слотах доступны Canvas Offsets/Anchors/Alignment, AutoSize, ZOrder,
padding, выравнивания и SizeRule/Value контейнеров там, где поля записаны.
Схема выведена из cooked-данных и проверок ссылок/полноты байтов, не получена
из доступных C++ деклараций. Оговорки: архетипы и значения отсутствующих полей
не разрешены полностью; desired size, runtime DPI, видимость и анимации неизвестны.

`size` у экспорта — длина сериализованных байтов, **не ширина/высота виджета**.
SizeBoxSlot — размещение ребёнка, **не WidthOverride/HeightOverride самого SizeBox**.
Свойства самого контейнера теперь извлекаются отдельно; см. раздел ниже.
Цепочка заканчивается `no_further_decoded_slot`, если следующего принятого слота
нет: это не доказательство достижения viewport. Циклы и несколько родителей
явно отмечаются, а не выбираются произвольно.

Пример `WBP_MessageBoxConfirmPopup`, pakchunk500 entry 559:
SizeBox_0 → CanvasPanelSlot 10 → CanvasPanel_1. В слоте Offsets=600×400,
Anchors=(0.5,0.5), Alignment=(0.5,0.5), AutoSize=1. Следовательно, 600×400
нельзя объявить окончательным экранным размером: AutoSize/desired size и масштаб
ещё участвуют в расчёте. ButtonOk связан с HorizontalBox_0, padding left=5;
TextMessage — с VerticalBox_1, SizeRule Fill и вертикальным Center.

## Собственные размеры SizeBox и флаги применения

`extract-ui-properties.py` нашёл единственный полный массив из 16 указателей
на нативные дескрипторы свойств. Массив в EXE начинается со смещения **150476368**.
Для каждого свойства сохраняются указатель, смещение имени, начало дескриптора
и GenFlags. Имена расположены в файле в ином порядке, поэтому порядок схемы
берётся именно из массива указателей, а не из строкового поиска.
Хеш EXE совпадает с native-enums.json; при изменении EXE декодирование запрещено.

`code-clues/ui-properties.json` содержит порядок:
WidthOverride, HeightOverride, MinDesiredWidth, MinDesiredHeight,
MaxDesiredWidth, MaxDesiredHeight, MinAspectRatio, MaxAspectRatio,
затем восемь соответствующих bOverride-флагов. Связь семейства свойств с
SizeBox проверяется по cooked-типу и полному разбору байтов, не по наличию C++.

`decode-size-boxes.py` читает эти явные значения и флаги, массив слотов и
входящий слот. Проверяет конечность/границы чисел, bool, число детей 0/1,
ссылки и Parent/Content дочернего SizeBoxSlot, хеши и отсутствие лишних байтов.
Первый результат был 2644 контейнера и 299 исключений из-за наследуемых свойств.
После восстановления их нативной схемы результат `ui-geometry/size-boxes.json`:
**2943 контейнера, исключений 0**. Остальные классы не декодируются как SizeBox
только по похожим именам.

В `ui-catalog/<вариант>.json` у соответствующего контрола появились
`container_geometry` и `size_constraints`. Статусы:

- `explicitly_enabled`: записаны и значение, и включённый bOverride-флаг;
- `explicitly_disabled`: флаг явно выключен, сохранённое число не применяется;
- `unresolved_default_or_archetype`: значение или флаг не записаны; наследуемые
  значения ещё неизвестны, поэтому включение не предполагается автоматически.

Пример окна подтверждения entry559: SizeBox_0 содержит **MinDesiredHeight=400**
и **bOverride_MinDesiredHeight=true**. Это подтверждённая минимальная локальная
высота; не экранные 400 пикселей и не подтверждённая ширина 600.
В магазине entry2637 SizeBox_0 имеет HeightOverride=120 и включённый флаг;
SizeBoxPrice — HeightOverride=100 и включённый флаг. Эти ограничения уже
соединены с цепочками родителей и слотами кнопок в каталоге и привязках окна.

## Наследуемые свойства и масштабирование

Нативный массив общих свойств виджета найден по смещению **150571360**.
В нём 28 дескрипторов: 23 самостоятельных поля и 5 дескрипторов вложенных
типов (UnderlyingType enum и внутренний элемент NativeBindings). Вложенные
дескрипторы не считаются отдельными индексами unversioned-полей.
`ui-properties.json` хранит исходный массив и отфильтрованный порядок
`widget.serialized_properties`, включая индекс каждого поля и GenFlags.

Отдельно подтверждён массив WidgetTransform по смещению **150377256**:
Translation, Scale, Shear, Angle. Имена и порядок из массива указателей,
а не из наблюдения похожего движения. `decode-widget-properties.py` читает
явные векторы, угол, pivot, bool, enum-байты, ссылки и прозрачность.
Неизвестные явные поля/непустые NativeBindings не пропускаются по догадке:
декодирование отклоняется. Существующие SizeBox/ScaleBox таких ошибок не дали.
Отсутствующие члены трансформации не подставляются как identity по умолчанию.

В SizeBox явно встретились RenderTransform (187), Visibility (60), Clipping (18),
bIsVariable (57), RenderOpacity (3). Эти данные сохранены в
`container_geometry.decoded.inherited_properties`. Обнаруженная прозрачность или
видимость в ресурсе не доказывает текущее состояние окна: код игры может его менять.

Нативный массив ScaleBox — **150500464**: Stretch, StretchDirection,
UserSpecifiedScale, IgnoreInheritedScale. У последнего GenFlags=76 (native bool),
а не 12, как у битовых bOverride в SizeBox. `decode-scale-boxes.py` разобрал
**203 ScaleBox, исключений 0**, включая их слоты и наследуемые поля.
Результат — `ui-geometry/scale-boxes.json`, привязан к контролам общего каталога.
Значения Stretch/StretchDirection проверяются по извлечённым EStretch и
EStretchDirection, значения UserSpecifiedScale не применяются без учёта режима.

Это даёт исходные ограничения и трансформации, но пока не полное вычисление
координат на Android. Остаются значения архетипов, desired size, viewport DPI,
runtime-анимации/видимость и обход всей родительской иерархии.

`verify-ui-links.py` повторно проверяет 52 нативных дескриптора: указатель в
массиве → дескриптор → имя, исходные GenFlags и SHA256 EXE. Также сверяет все
2943 SizeBox и 203 ScaleBox с контролами и хешами авторитетных вариантов каталога.
При отсутствии связи, изменённом источнике или исключениях завершается ошибкой.
Не читать старые JSON по маске вместо index.json: пакет с несколькими корневыми
классами имеет отдельные `-root-<id>` записи, а прежний JSON может оставаться
в библиотеке как результат предыдущего извлечения.

## Сообщение об отключении сессии

Наблюдавшийся текст: `Connection terminated for safe gameplay.`
**Подтверждён ключ `KICKOUT_FOR_INSPECT`** в pakchunk1 entry 405,
логическая CSV-запись 3612. Физическая строка файла отличается из-за многострочных
значений: не подменять csv_record результатом `rg -n`.
SHA256 CSV: `32956f16902bdd8f7507d000143dee29ad457e7fa1ea09194c3632a2d1f4179e`.
Дублирующий английский текст есть также в ProjectRED entry 6099.

`build-window-bindings.py` проверяет хеш, точный ключ/текст и отсутствие дубликатов,
создаёт в модуле `ui-window-reference.json`. Привязка шаблона содержит исходный
кадр, crop и хеши. В `vision.json` — manual_screen_sources, в статусе —
`reason=source_text:KICKOUT_FOR_INSPECT`. Реакция: пауза без закрытия сообщения
или автоматического переподключения.

Ресурсные кандидаты: WBP_MessageBoxConfirmPopup (одна ButtonOk + TextMessage),
WBP_MessageBoxPopup и WBP_SystemMessageBoxPopup (также ButtonCancel).
Для них сохранены контролы, геометрия и версии архивов. **Прямая связь нативного
вызывающего кода этого ключа с конкретным WBP ещё не доказана**:
`widget_binding_proven=false`. Сходство формы — зацепка, не доказательство.
Динамический текст не обязан находиться внутри самого WBP.

Для остальных сообщений каталог уже предоставляет ресурсные связи и геометрию.
Текст→вызывающий код→конкретное окно ещё требует восстановления; наличие общего
каталога не означает, что все попапы автоматически распознаются или закрываются.
