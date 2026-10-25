# Исходные рамки HP / MP и вложенный портрет

Источник EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Метод static; native не исполнялся. Использованы явные prepare / collect roots,
существующий Ghidra проект, полные unwind boundaries и raw descriptor bytes.

## Struct getter цепочки

| Getter | Metadata | Тип и проверенный состав |
|---|---|---|
| 1418d9130 | 14b0cedb0 | SlateBrush, 13 descriptor rows |
| 141887510 | 14b0ce1a8 | DeprecateSlateVector2D, 0 собственных полей, размер 8, super getter 141621e60 |
| 141887570 | 14b0cde40 | Margin: Left / Top / Right / Bottom, float flags 10 |
| 141621e60 | 14b0c9a20 | Vector2f: X / Y, float flags 10, размер 8 |

Getters проверяют кеш, передают metadata в 1417d2560 и возвращают кеш.
Сам registration helper и native serializers не исполнены. SlateBrush array:
TintColor, DrawAs, Tiling, Mirroring, ImageType, ImageSize, Margin,
ResourceObject, OutlineSettings, UVRegion, bIsDynamicallyLoaded, bHasUObject,
ResourceName. Image.Brush descriptor 148fdf4f0 ссылается на getter 1418d9130;
ассоциация класса Image отдельно установлена в [предыдущем исследовании](UI-WIDGET-ROOTS-IMAGE-11316.md).

Requests: `0b2b2ad3760d40bdcf24857fdcdc6a8a661fdb3714f2357054debcaf95e3bd94`,
`6c79ab7fd65d32b8ee0c1f64a7f898282f5c88de6e621db566b3c23a07f21bb7`,
`5ac6c9f1375d26d2027bcdd60dbd13d255fa2edd4209080203ada6239fd9321f`.

## HP / MP source binding

В pakchunk500-Windows-1747, WBP_PCStatusProgressBarT, Image_224 export 48
и Image export 47 имеют первый explicit Brush. Прочитан только ограниченный
prefix: DrawAs 1, ImageType 1, ImageSize 98 × 18, четыре Margin по 0.5,
ResourceObject -74. Таблица imports разрешает -74 в
`/Game/RED/UI/Resource/Texture/GameUI/ProgressBG_HP.ProgressBG_HP`.
Дальнейший inherited payload сохраняется непрочитанным, не объявляется успешно
разобранным. Иные формы prefix отклоняются; defaults не подставляются.

Рамки имеют исходные прямоугольники 299 × 22; внутренние полосы — 291 × 14,
с отступами по 4. Прежняя проекция пропускала рамки, оставляя CSS border.

Texture2D находится в pakchunk500-Windows entries 4004 / 4005. Pixel format
PF_FloatRGBA не поддерживался прежним PNG exporter. Ограниченный reader проверяет
format marker, размеры 180 × 22 / slices 1, границы 31680 bytes half RGBA.
RGB переводится из linear half в sRGB8; alpha остаётся линейной. Nonfinite / HDR
каналы вне 0–1 отклоняются вместо скрытого clamp. Текстура и PNG имеют полные SHA.
Это явная web color projection, не доказательство идентичности native shaders.

## NkImage и портрет

Getter 144a34fa0: прямой LEA 144a34fe6 к UTF16 NkImage 149648632,
пакет /Script/NkUMG, callback родительского Image 14357fc60.
Metadata 149648810 → array 1496487a0. Четыре descriptor rows:
DeferredResourceObject (flags 16), UnderlyingType (0, вложенный enum child),
CachePolicy (30), AsyncLoad (76). Самостоятельных полей три; inherited Image.Brush
в наблюдаемом cooked header начинается с index 3.
Request `8b7e8b643d2fe043ff328c8de22998037b5a7b171a95c8ccd1c9ef531a7128f7`.

В pakchunk500-Windows-2793, WBP_PortraitSmallT, первым explicit полем NkImage
прочитан DeferredResourceObject: два FName и пустой subpath. Значения разрешены
через фактическую таблицу имён, не по сходству имён текстур:

- ImageBG → IMG_PortraitCommon.
- ImageFrame → IMG_PortraitFrame_Noble_01.
- ImagePortrait → IMG_Portrait_80002_F.

В Brush ImageFrame записан отдельный fallback Noble_05. Эти записи не объединены.
Для offline preview явно выбраны deferred source paths; приоритет runtime loader,
CachePolicy / AsyncLoad и динамические замены персонажа пока не подтверждены.
Прочий payload сохраняется, а FName numbers / непустые subpaths отклоняются.

Внешний PortraitSmallT выделен source slot 18 размером 118 × 118: он расширяет
CanvasPanel_0 размером 84 × 84 отступами −17. ButtonPortraitMove — отдельный
80 × 80 input control. Прежняя реализация вставляла art внутрь кнопки; теперь
визуальная ветвь, nested schema и input control раздельны. Web layers заданы
явно как preview policy, а не как подтверждённые inherited ZOrder.

## Результат и границы

`ui_status_skin.py` сохраняет source bytes / SHA, metadata / arrays / fragments,
Brush и deferred prefix, непроверенные хвосты и PNG вне Git. Набор:
`F:/PhoneExit Resources/Vampir/ui-status-skin/f1b534435df7d190e686676cc530a6228ef48dcd66763153308e5c3dd6c9a001/index.json`.
SHA256 `b5d5fb855816307c400a49103feb74cb7430eb139b72ba29979375db6ad41656`.

29 Python tests с прежними builder проверками и 5 renderer tests проходят.
В браузере проверены HUD / коллекции / магазин на 1280 × 720, 1920 × 1080,
3440 × 1440; временный viewport сброшен. По две рамки / три portrait images
на компонент; отдельная кнопка открыла персонажа. В демомодели HP изменился
10576 → 11776, MP 2453 → 2413; текст и заполнение используют одну модель.

Не закрыты: активный вариант клиента, native DPI, inherited defaults / tint /
visibility / ZOrder, shaders и dynamic bindings, реальный выбор портрета / ранга
и рамки, полный прототип статуса с эффектами / adrenaline / barrier. Статический
WBP preview не выдаётся за состояние персонажа на сервере; игровые команды не отправлялись.
