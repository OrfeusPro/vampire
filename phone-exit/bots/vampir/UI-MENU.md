# Общее меню: первый визуальный проход

Подключаемый компонент main_menu в [components.json](ui-prototype/components.json)
используется через единый openMenu в HUD и заголовках магазина / коллекций.
Собственных подписок, таймеров, игровых команд и отдельных банков данных нет.

Сборщик проверяет WBP_MainMenuUI, pakchunk500-Windows-1707.json и 41 контрол
по именам / типам / export SHA; полные SHA каталога, uasset / uexp и текстур
сохраняются в component-evidence.json, skin-evidence.json и manifest snapshot.
Иконки берутся по полным asset paths из того же пакета; членство в package
names не доказывает конкретный Brush данного NkButton.

OverlayMain → CanvasPanel_13 имеет ширину 751, anchors (1, 0)–(1, 1),
alignment (1, 0), нулевые отступы. Native-frame применяется существующим
geometry.js с reference frame демо 2400 × 1350, UI Scale один раз.
Внешний SafeZone и активная DPI curve игры не восстановлены.

Шесть колонок, порядок / группы, подписи и нижняя строка адаптированы по
сохранённому кадру main-menu-dcb952cf683657ec5d41cf8ca6284522d6e196a1a108e1e60e81f1fb4cb45166.png.
Это не результат восстановления excluded grid slots. CSS задаёт временные
цвета, прозрачность, шрифт, hover / pressed. Все пункты доступны в демо;
серверные eligibility / lock / badge / new не выводятся из кадра.
Native callbacks не подключены. Нереализованные разделы показывают ограничение.

- [x] UI-M-01. Проверить наличие 41 контрола и 41 однозначной исходной текстуры при сборке.
- [x] UI-M-02. Применить исходную ширину / anchors через общий geometry pipeline.
- [x] UI-M-03. Проверить 1280 × 720, 1920 × 1080, 3440 × 1440; иконки, переносы, нижнюю строку, навигацию и фокус.
- [ ] ~ UI-M-04. Восстановить grid slots / порядок, полный состав внешнего заголовка и его размещение.
- [ ] UI-M-05. Восстановить Brush / tint / alpha / шрифты / все состояния и active visibility.
- [ ] UI-M-06. Подтвердить callbacks / данные / условия; подключение бота проверять отдельно по UI-17.

Проверено в snapshot 198f7189806bb5b50764f13df338d1d3db2778948fcfdc064c5d719e06af9c8c:
23 Python / 60 Node тестов и полный verifier; 41 / 41 загруженных иконок,
ширины 400,53 / 600,79 / 801,06 CSS px на трёх размерах. Нижняя строка
остаётся внутри viewport, переполнения тела нет. HUD → меню → коллекции →
меню не создаёт копию; закрытие почты возвращает фокус на кнопку «Почта».
Кадры menu-source-1280.jpg, menu-source-1920.jpg, menu-source-wide.jpg находятся
в F:/PhoneExit Resources/Vampir/ui-prototype-checks. Временный viewport сброшен.
Это проверка демо; полнота игрового меню, точность шрифтов и 50 браузерных окон
не подтверждены. Подписи длинных пунктов пока могут переноситься внутри слова.


## Проверка полноты слотов перед восстановлением сетки

Новый audit-ui-slot-coverage.py читает uasset / uexp через существующий
inspect-ui.py, сверяет полные SHA с каталогом и классифицирует каждый export
с суффиксом Slot как decoded / rejected / unaccounted. Повторная запись одного
слота, неизвестный export или несовпадение SHA / offset / типа останавливают
проверку. Исходные каталоги и опубликованный snapshot не изменяются.

В пакете меню: 264 decoded, 43 rejected ButtonSlot, 39 unaccounted GridSlot.
GridSlot отсутствовали даже в excluded_slots, поскольку decode-panel-slots.py
не включает этот класс. ButtonSlot отклонены проверкой parent type: исходный
родитель NkButton отличается от ожидаемого Button. Нельзя просто снять эту
проверку: контракт наследования / схема свойств требуют отдельного подтверждения.

Полный проход 2376 вариантов: 72153 decoded, 2783 rejected, 964 unaccounted
кандидата. Среди последних: PanelSlot 432, GridSlot 472, ScrollBoxSlot 8,
NamedSlot 44, UniformGridSlot 8. NamedSlot может быть самим виджетом, а не
слотом размещения; это инвентаризация по суффиксу, не доказательство 964
потерянных layout links. Разные roots одного пакета считаются по вариантам.

Отчёт: F:/PhoneExit Resources/Vampir/ui-property-scans/cooked-slot-coverage-02.json.
SHA256: 07b01118bcc7bbaf6768e82b62d82fb16ab428c97677df2fcb6fdfc91d9014c6.
Каталог меню SHA256: 296cf37f3b28e07288f7391527fbf77b10e526b2ff277ada6ed1daef2ce308ac.
uasset SHA256: b825f42ee7d16ea03c67ee5fa184e916ee430866c53388b9ec47df04d9410950.
uexp SHA256: 6a526d9dba9c4e882278603c5657cf053b88a864f860f5a52192e5a51092550a.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-ui-slot-coverage.py --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/cooked-slot-coverage-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_slot_coverage.py
```

Три проверки инструмента прошли: пропуск GridSlot не скрывается, stale SHA и
двойной учёт отклоняются. Это не аудит native-схемы или текущей совместимости.
Следующий шаг — подтвердить GridSlot row / column / spans / layer / padding
и наследование по источникам, затем обновить декодер, граф и renderer. До этого
порядок меню остаётся явно временным, UI-M-04 не закрыт.


## Кандидат декодирования GridSlot

[Отдельное доказательство и ограничения](../resource-tools/vampir/knowledge/evidence/interface/UI-GRID-SLOT-CANDIDATES-11316.md):
в текущем EXE найден массив 9 дескрипторов по адресу данных 0x148fdbbf0;
все 472 исторических GridSlot прочитаны без остатка, включая 39 меню.
Native association класса и совместимость cooked набора ещё открыты.
У Matrix получены Row 3 / Column 5, у Engraving — Row 3 / Column 1;
у Character оба положения пропущены. Текущая сетка демо остаётся временной:
отсутствующий Row / Column не превращается в ноль, отсутствующий Span — в один.

UI-25.07 закрывает отдельный candidate parse, а UI-25.06 / UI-M-04 остаются
в процессе до metadata / defaults / importer / renderer. Шесть локальных тестов
двух новых инструментов прошли; workflow finish сохранил static факт
8d2194a9e0ad47784dcd161caed907c5089f34506892fe40bf9b126890f50316.


## Статическая привязка класса

[Проверена цепочка getter / metadata / property array](../resource-tools/vampir/knowledge/evidence/interface/UI-GRID-CLASS-LINKS-11316.md)
в текущем EXE. У отдельного декодера --class-request связывает извлечённую
таблицу с этим подтверждением по полному SHA; новый проход — 472 слота без
ошибок, прежние отчёты сохранены. Есть pointer chain к getter PanelSlot.
Это закрывает UI-25.09, но не весь UI-25.08: семантика helper, CDO / archetype
и значения пропущенных Row / Column / Span остаются неизвестны. Внешний вид
меню в этом проходе не менялся, UI-M-04 остаётся в процессе.


## Поток инициализации

[Проверен helper и базовый callback](../resource-tools/vampir/knowledge/evidence/interface/UI-GRID-CONSTRUCTION-FLOW-11316.md):
указатель 14358e000 из getter прослеживается в поле класса +0xb0, отдельно
вызывается pointer chain к getter PanelSlot. Проверены четыре полных native
фрагмента; найдена зависимость 14174c9f0 перед завершением базовой инициализации.
Отсутствие записи в callback не доказывает начальное значение поля: выделение
объекта и CDO / archetype копирование ещё не восстановлены. UI-25.10 закрыт,
UI-25.08 остаётся в процессе, следующая проверка — UI-25.11.


## Ограниченная проверка начального состояния

[Diagnostic leaf и replay всей нормальной цепочки](../resource-tools/vampir/knowledge/evidence/interface/UI-GRID-INITIALIZATION-REPLAY-11316.md)
проверены на 40 случаях: 20 возвратов, 20 остановок до исполнения диагностики.
При четырёх начальных шаблонах памяти диапазон object+0x4c..0x5b остаётся
неизменным. Это исключает вывод zero/one defaults из данной цепочки самой
по себе; источник начальной памяти / CDO / archetype ещё открыт. Два новых
теста входят в отдельный current-SHA check. UI-25.12 закрыт, UI-25.11 в процессе,
следующая зависимость — UI-25.13. Внешний вид меню не менялся.
