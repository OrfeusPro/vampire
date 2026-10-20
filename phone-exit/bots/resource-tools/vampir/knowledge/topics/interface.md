# Игровой интерфейс, контролы и масштаб

## Установлено

Извлечены варианты WidgetBlueprint, контролы, родительские контейнеры,
Canvas/panel slots, размеры, anchors и scale evidence. Пресеты и исходная
геометрия не доказывают активный DPI и доступные координаты клика.
[Каталог](../evidence/interface/UI-CATALOG.md),
[масштаб](../evidence/interface/UI-SCALE.md),
[native-связи](../evidence/interface/NATIVE-UI-LINKS.md).

Есть существующий экранный Android-бот с привязками окон и проверками кадров.
Он не равен самостоятельному сетевому runtime.
[Код бота](../../../../vampir/README.md).

## Открыто

Пользовательская задумка: игровые кнопки и меню, в центре лёгкая 2D-карта,
видимое движение / квесты / бой, отключаемые слои информации. Полное
воспроизведение работающих меню и связь с серверными действиями не реализованы.
Каждый контрол сначала связывать с ресурсом и действием, затем проверять на
актуальном экране. Варианты Windows-ресурсов не выбирать за Android автоматически.

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Vampir: макет → поле кнопки → ветвь обработчика](../evidence/interface/ENTRY-BUTTONS.md)
- [Vampir: вход по ресурсам клиента](../evidence/interface/ENTRY-FLOW.md)
- [Vampir: получение и показ входных окон](../evidence/interface/ENTRY-WINDOWS.md)
- [Vampir: точная связь FaderUI с native-классом](../evidence/interface/FADER-CLASS.md)
- [Vampir: частичная привязка содержимого системного сообщения](../evidence/interface/MESSAGE-NAMED-SLOT.md)
- [Vampir: ветви входа в собранном клиенте](../evidence/interface/NATIVE-ENTRY.md)
- [Vampir: индекс ссылок кода на макеты и попапы](../evidence/interface/NATIVE-UI-LINKS.md)
- [Vampir: код общего сообщения → WBP → текстовый элемент](../evidence/interface/SYSTEM-MESSAGE-UI.md)
- [Каталог окон и интерфейса Vampir](../evidence/interface/UI-CATALOG.md)
- [Vampir: проверка окна с побочными эффектами](../evidence/interface/UI-MANAGER.md)
- [Пресеты UI Scale, настройка и границы восстановления DPI](../evidence/interface/UI-SCALE.md)
- [Vampir: обычный переход через easing и callback](../evidence/interface/UI-TRANSITION.md)
