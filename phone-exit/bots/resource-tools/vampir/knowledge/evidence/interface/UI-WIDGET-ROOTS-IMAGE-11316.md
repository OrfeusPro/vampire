# WidgetTree RootWidget и объявления Image

## Источник и метод

Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Статический анализ, native не исполнялся. Вопрос `ui-shared-shortcut-properties-11316`.
После bounded просмотра UMG rdata подготовлен явный request
`7dc3d7b0a03afafed6f82c362776d8ecda440e1eeaf3e564a8303bd49299ba47`.
Получены два недостающих getter export через collect; существующий Ghidra проект
переиспользован. Выгрузка: `ghidra/request-exports/<SHA>/run-f7c9ec7903b7` библиотеки.
Псевдокод и инструкции двух полных unwind roots проверены; общий helper не исполнен.

## Native association

| Класс | Getter | Metadata | Property array |
|---|---|---|---|
| WidgetTree | 1435f6360 | 149010380 | 1490101f0 |
| Image | 14357fc60 | 148fdfbe0 | 148fdf820 |

Первые указатели metadata совпадают с getter, metadata + 40 — с property array.
Getter WidgetTree ссылается на UTF16 WidgetTree по 14900ffea и /Script/UMG;
Image — на Image по 148fdf49a и /Script/UMG. В нулевой ветви оба вызывают
1416ab8d0 и возвращают кеш. Это статическая ассоциация, не исполнение регистрации.

WidgetTree array содержит RootWidget (flags low byte 82), NamedSlotBindings value
(82), NamedSlotBindings_Key (20), NamedSlotBindings map (23). Вложенные map rows
не объявляются самостоятельными сериализованными свойствами. RootWidget — первая
самостоятельная строка, descriptor 149010000, class getter pointer 14357ea70.

Image array: Brush (25), BrushDelegate (26), ColorAndOpacity (25),
ColorAndOpacityDelegate (26), bFlipForRightToLeftFlowDirection (76),
OnMouseButtonDownEvent (26). Descriptor Brush 148fdf4f0 содержит struct getter
pointer 1418d9130. Тип struct по одному указателю ещё не установлен; схема Brush,
tint, delegates и их применение этим исследованием не закрываются.

## Пакетный source root проход

`scan-ui-widget-roots.py` проверяет native literals / metadata / arrays по полным
байтам текущего EXE и явным getter roots. Затем повторно проверяет Outer слой,
полные SHA UAsset / UExp, класс импорта /Script/UMG.WidgetTree, unversioned header
и весь suffix. `ui_widget_tree.py` допускает только explicit index 0 или omission;
прочие поля отвергаются, не пропускаются с угаданной длиной.

Для положительного RootWidget проверены наличие target export, его Outer =
исходный WidgetTree и общий source owner. Значения 0 / внешняя ссылка и omission
сохраняются отдельно; default root не подставляется.

Результат вне Git: `ui-property-scans/widget-roots/283b9317abad52fb04b7e61cedb0fa208fcf56816b46aa03affae525ef9e7b57/index.json`
в библиотеке `F:/PhoneExit Resources/Vampir`; SHA256
`283b9317abad52fb04b7e61cedb0fa208fcf56816b46aa03affae525ef9e7b57`.
Повтор заново прочитал источники и побайтно сравнил тот же результат.
Учтены 2376 WidgetTree: 2375 explicit local root candidates и один omission.
Omission: pakchunk500-Windows-2171, owner root 2; root не выбран.

Для приоритетных patch пакетов:

| Компонент | Пакет | Source WidgetTree root |
|---|---|---|
| ShortcutkeyHudT | pakchunk500-Windows-2699 | export 1 CanvasPanel_0 |
| PopupBgTitle | pakchunk500-Windows-811 | export 9 CanvasPanel_0 |
| Badge | pakchunk500-Windows-599 | export 1 CanvasPanel_0 |
| ItemIconT | pakchunk500-Windows-2233 | export 58 ScaleBox_1 |

Четыре теста проверяют positive / external / null references, omission,
serialized zero, дополнительные неизвестные свойства, suffix и truncation;
39 вместе с прежними pipeline / impact / builder проверками проходят.

## Границы и следующий шаг

Source RootWidget не означает активный вариант ресурса или видимое окно игры.
Runtime root, текущая cooked compatibility, наследование, DPI, desired size,
Image Brush / текст / шрифты и события остаются неизвестными. Старые native
SizeBox схемы этим не объявлены совместимыми с текущим EXE.
Следующий шаг: source roots как отдельная аннотация IR и точный Brush struct
getter / схема перед чтением изображений и применением оформления.
