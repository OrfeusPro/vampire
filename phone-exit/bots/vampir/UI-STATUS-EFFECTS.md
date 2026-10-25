# Строка эффектов: источники и недостающие связи

Эта ветвь относится к [общим компонентам](UI-TASKS.md) и
[данным эффектов](UI-GAME-DATA.md). Генерация остаётся закрытой до аудита.

## Проверка cooked компонентов

`audit-status-effect-ui.py` проверяет сохранённые uasset / uexp по полным SHA,
каждый export контрола по границам / SHA, совпадение метаданных каталога и
exports. Сохраняет импорты пакета, names, decoded slots, parent chains и
индексы unversioned header. Прежние native адреса не используются.

Отчёт `ui-property-scans/status-effect-ui-audit-01.json` вне Git, ID
`af17f38a1cca21432d3005e12936cd5445a4577960835bc028d90b7fe3cd45ee`.
Проверены 10 вариантов / 234 контрола. 74 ссылки на вложенные классы сохранены
как кандидаты с учётом всех вариантов. Они не являются выбором активной версии.

WBP_PCStatusUI, `pakchunk500-Windows-1749.json`:

- TileViewOperationPanelList, export 31, NkTileView; parent slots
  25 → 21 → 23 → 15. SHA export
  `45b8b1b94b400a1cdaff85021d21a4b7ded33bf9318272a7593e82251731327b`.
  В заголовке наблюдаются индексы 1, 2, 8, 15, 27 и 44; 15 имеет zero marker.
  Схема NkTileView пока не связывает их с именами / типами свойств.
- ButtonBuffPanelOpen, export 29, NkButton; slots 22 → 23 → 15.
  Наличие кнопки не доказывает handler или целевой popup.
- TileViewOperationPanelList_Unused — отдельный NkDeferredPanel.
  Суффикс Unused не доказывает, что объект отсутствует во всех runtime состояниях.

WBP_OperationPanelIconT, `pakchunk500-Windows-793.json`, и отдельный
`ProjectRED-Windows-8101.json` имеют по 27 контролов. Сохранены оба варианта:
ImageIcon / ImageBG / ImageBGSmall, TextStackCount, ImageCustom,
ImageDeadlyProgress, ImageGrade, CanvasPanelOmit / CanvasPanelUnusable,
SwitcherBG, MovieScene и Flashing_INST.
ImageIcon export 26 имеет slots 7 → 5, TextStackCount export 40 —
44 → 23 → 9 → 5. Одинаковые SHA отдельных exports не подтверждают
совместимость пакетов целиком. Наличие ImageIcon не раскрывает Brush binding;
наличие Flashing_INST не задаёт условие запуска или частоту мигания.

ZBP_PCStatusUI_OperationPanelList содержит вложенные контроли типа
WBP_OperationPanelIconT_C. Отдельно учтены BossTarget, MonsterTarget и
PCTarget варианты списков, а также WBP_SkillEffectInfoT. Эти классы нельзя
автоматически объявить содержимым NkTileView или popup сведений только по имени.
Поле names пакета, импорт, локальный slot и динамическая factory — разные связи.

Все сохранённые пути родителей являются локальными. DPI, абсолютное положение,
desired size, порядок HorizontalBox и активные visibility / transforms
остаются частью аудита геометрии. Unversioned index без схемы не получает имя
свойства по похожему числу; оставшийся payload не объявляется декодированным.

## Отдельные проверки

- [x] UI-21.E-01. Сверить cooked источники и exports выбранных компонентов. Проверено: 10 вариантов / 234 контрола, полные SHA и границы body, каталог соответствует exports.
- [ ] ~ UI-21.E-02. Восстановить NkTileView entry class / factory и выбор варианта; package names / sample ZBP сохранять как кандидаты. Найдены локальные цепочки и индексы, схема свойств ещё неизвестна.
  - [x] UI-21.E-02.01. Найти и статически проверить current getter класса NkTileView. Проверено: точные строки /Script/NkUMG / NkTileView, глобальный кеш и целая unwind функция на SHA d00a1977; Ghidra и инспектор согласованы. [Доказательства и ограничения](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-REGISTRATION-11316.md).
  - [ ] UI-21.E-02.02. Через отдельное задание исследовать три передаваемых указателя на функции; подтвердить роли и путь к reflection metadata, порядок свойств / наследование. Getter не закрывает эту задачу.
- [ ] UI-21.E-03. Восстановить данные экземпляра эффекта → ImageIcon / ImageCustom / BG / grade Brush; отдельно обычные и small ресурсы, tint, alpha и visibility.
- [ ] UI-21.E-04. Восстановить stack count, оставшееся время, progress, правило обновления и снятие; статическое Effect.StackCount не считать текущими стаками персонажа.
- [ ] UI-21.E-05. Восстановить ButtonBuffPanelOpen → binding → handler → popup, возврат фокуса и закрытие. Название WBP_SkillEffectInfoT не является доказательством целевого окна.
- [ ] UI-21.E-06. Восстановить Flashing / WidgetSwitcher / Omit / Unusable: условия, выбранный индекс, style и события; статические слои не объявлять активными.
- [ ] UI-21.E-07. Сверить общий компонент у игрока и разных целей; определить различия порядка, лимитов, фильтров и размеров, не копировать один вариант во все окна.
- [ ] UI-21.E-08. После аудита подключить компонент через явный демоадаптер: cleanup, обновление изменённых экземпляров, изоляция 50 окон без отдельного фонового таймера на каждую иконку; реальные события сессии проверять отдельно.
- [x] UI-21.E-09. Статически проверить кандидаты getter: таблицу native функций и путь инициализации. Проверено: пять current функций / семь unwind-фрагментов, пара Refresh → 144a8f220, related getter NkScrollView и явные записи памяти. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-CLASS-FUNCTIONS-11316.md). Имена свойств / defaults и schema этим не подтверждены.
- [ ] ~ UI-21.E-10. Отдельным заданием исследовать тело Refresh 144a8f220: вызовы, данные и границы эффекта; не считать его кликом по кнопке или updater без проверки.
  - [x] UI-21.E-10.01. Проверить wrapper и точный leaf setter: передача 16 байтов owner +0x430 → receiver +0x14b8, флаг +0x14f9 и вызовы helper с DL 0 / 1. Проверено: 24 native случая с no-op fixture helper, Ghidra wrapper и полный контроль источника / областей памяти. [Границы доказательства](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-REFRESH-11316.md).
  - [ ] ~ UI-21.E-10.02. Установить смысл передаваемого блока, его producer и property binding, политику helper / reentrancy / объединение обновлений. Подтверждено участие двух double в layout arithmetic; source имена, единицы, тип свойства и полное downstream поведение ещё неизвестны.
  - [x] UI-21.E-10.03. Проверить участие блока в layout arithmetic и cached-count gate. Проверено: 128 positive integer fixtures, две оси; 32 полных cached exits и 96 prefixes до item-count provider, CRT fmodf подтверждён как импорт / заменён fixture. [Доказательства и границы](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-PACKING-11316.md). Source имена, единицы / DPI, arbitrary float32 и весь downstream layout этим не закрыты.
  - [x] UI-21.E-10.04. Проверить статический путь передачи трёх блоков параметров в receiver: owner +0x430 / +0x440 / +0x450 → +0x14b8 / +0x14d0 / +0x14e0. Проверено: 13 differing slots в ограниченном сравнении таблиц, четыре выбранных root / 14 fragments; конкретные инструкции и SHA. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-PARAMETER-FLOW-11316.md). Producer и имена свойств не восстановлены.
  - [ ] UI-21.E-10.05. Установить producer / named metadata для блоков owner +0x430 / +0x440 / +0x450. Не переносить имена Spacing / Padding по сходству арифметики; сохранить различие native offsets и cooked schema indices.
- [x] UI-21.E-11. Включить подтверждённые native участки в план обновления клиента. Проверено: [source-bound план поиска и ручной проверки](../resource-tools/vampir/knowledge/release-ui-list-targets.json) подключён к release-update-targets; статические и bounded области разделены. Совпадение литерала не переносит роль; automatic_runtime_promotion=false. Перенос проверок на следующий SHA и совместимость cooked ресурсов остаются открытыми.
- [x] UI-21.E-12. Проверить условное заполнение оформления прокрутки и найти оригинальные ресурсы-кандидаты. Проверено: 32 native случая с resolver / loader / setter / scheduling fixtures; два точных ключа, float4 единицы, пары 9×8 / 8×9 и сохранение заданных параметров при двух ненулевых указателях. PNG 60×12 / 12×60 сверены по SHA отдельно. [Границы и источники](../resource-tools/vampir/knowledge/evidence/interface/NKTILEVIEW-SCROLL-STYLE-11316.md).
- [ ] ~ UI-21.E-13. Подтвердить native resolver → полный ресурс / активный вариант → Brush / setter и условия gate для оформления прокрутки. Suffix-кандидат и сырые float4 не подтверждают global defaults, цветовое пространство, DPI или nine-slice; frontend пока не применять.
  - [x] UI-21.E-13.01. Проверить локальный resource setter / invalidation и статические ветви resolver. Проверено: 54 native случая, 18 identity exits, записи +0x38 / сброс кеша +0x98 и control +0xa0; helpers ownership — fixtures. Resolver содержит шаблон /UI/Resource/Texture/%s, runtime глобальный префикс не восстановлен. [Источники и границы](../resource-tools/vampir/knowledge/evidence/interface/UI-RESOURCE-SETTER-11316.md).
  - [ ] ~ UI-21.E-13.02. Установить источник глобального префикса 14b5646b0 и строковые helpers resolver; не подставлять /Game/RED из suffix PNG. Подтвердить активный ресурс отдельно от корректного преобразования строки.
    - [x] UI-21.E-13.02.01. Найти default и config источник условного сегмента префикса. Проверено статически: /Game, NnCoreSetting.ContentSubName, branch length >1; в source-bound снимке значение RED, active / precedence false. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-RESOURCE-PREFIX-11316.md). Строковые helpers / config reader целиком не исполнены.
    - [ ] UI-21.E-13.02.02. Подтвердить чтение конфигурации / precedence и полную native сборку строки, включая пустые / нестандартные значения. Только затем связывать полный путь с выбранным ресурсом; один snapshot не доказывает активное состояние.
    - [x] UI-21.E-13.02.03. Проверить начальную ветвь config reader до callback setup. Проверено: 26 native prefixes, lookup через global object / vtable +0x58, missing обходит присваивание, present передаёт длину UTF16 без terminator; lookup и string helper — fixtures. [Источники и границы](../resource-tools/vampir/knowledge/evidence/interface/UI-CONTENT-CONFIG-11316.md). Полная функция, callbacks и precedence остаются открытыми.
    - [ ] ~ UI-21.E-13.02.04. Проверить callable setup / сохранение / исполнение и полный результат reader 1445c2c30; определить, могут ли последующие события менять destination после missing lookup. Общий reader с native replacement / reuse и service fixtures проверен в UI-21.E-13.02.10; последующее исполнение и событие обновления ещё не подтверждены. Не переносить результат ограниченного прогона на весь жизненный цикл.
    - [x] UI-21.E-13.02.05. Проверить локальную роль передаваемых указателей: полное native копирование строкового объекта и leaf forwarding к присваиванию. Проверено: 32 clone / 3 forwarding случая; allocator / byte copy / assignment fixtures, insertion статический. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-CALLABLES-11316.md). Это не подтверждение dispatch или active config.
    - [x] UI-21.E-13.02.06. Проверить перенос двух callable-объектов и локальную очистку захвата. Проверено: 48 native copy случаев без fixtures, 16 cleanup случаев с deallocation fixture, 3 address getter случая; inline / external storage, inactive и guard bytes. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-PAYLOAD-11316.md). Общий lifetime, insertion и полный reader ещё требуют проверки.
    - [x] UI-21.E-13.02.07. Проверить целый reader вместе с insertion / payload copy / cleanup на одной памяти. Проверено: 48 последовательностей / 144 полных возврата, три независимые привязки, native перенос ключа, сохранность предыдущих записей и bucket chain; восемь явных service fixtures. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-READER-11316.md). New-entry сценарии без growth / reuse / replacement; precedence и последующий dispatch открыты.
    - [ ] ~ UI-21.E-13.02.08. Найти native потребителей сохранённых invoke pointers и условия вызова; отдельно проверить uniqueness / replacement, lifetime и ошибки. Локальный поиск / replacement проверен в UI-21.E-13.02.09, read / write consumers — UI-21.E-13.02.12; инициатор события и общий lifetime открыты. Не считать сохранение callable доказательством обновления настройки.
    - [x] UI-21.E-13.02.09. Проверить native поиск ключа, сравнение и замену привязки. Проверено: 512 uniqueness / replacement случаев, 8 lookup и 2 fast exits; настоящий UTF16 compare с ASCII folding, native cleanup, free / memmove fixtures. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-UNIQUENESS-11316.md). Полный reader с заменой и реальный hash ещё не проверены.
    - [x] UI-21.E-13.02.10. Проверить общий reader без uniqueness=false fixture: повторный ключ, новый destination и reuse освобождённого слота на одной памяти. Проверено: 384 последовательности / 2304 полных вызова, 1152 replacements / 768 reuse; native lookup / compare / capture cleanup, восемь service fixtures. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-READER-REPLACEMENT-11316.md). Старый new-entry режим сохранён для регрессии; native hash — отдельная проверка UI-21.E-13.02.11, dispatch / precedence открыты.
    - [x] UI-21.E-13.02.11. Проверить native hash ключа и согласованность с compare, убрать hash fixture из общего сценария. Проверено: 537 отдельных случаев / 8 пар, file-backed таблица и bitwise oracle; 2304 общих вызова с настоящим hash и восемью buckets. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-HASH-11316.md). Встроенный NUL — adversarial вход, не допустимый key contract; active config / dispatch / precedence остаются открытыми.
    - [x] UI-21.E-13.02.12. Найти и проверить read / write consumers сохранённых строковых привязок. Проверено: 96 последовательностей / 288 полных вызовов, native hash / lookup / capture getter / read clone / assignment forwarding; пять service fixtures. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-CONSUMERS-11316.md). Контейнер synthetic; caller / событие и active settings не доказаны.
    - [ ] ~ UI-21.E-13.02.13. Найти caller / условия вызова consumers; общий registration → read / write теперь проверен в UI-21.E-13.02.15. Native assignment — UI-21.E-13.02.14. Перечисление 1445cb6c0 проверять отдельно, не объявлять callback события обновления по одному обходу контейнера.
    - [x] UI-21.E-13.02.14. Проверить native string assignment и убрать whole-assignment fixture из consumers. Проверено: 80 локальных вариантов / 4 identity, затем 288 read/write/read вызовов с 64 native assignments; resize / byte-copy primitives — fixtures. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-STRING-ASSIGNMENT-11316.md). Allocator / registration integration / caller / active config ещё открыты.
    - [x] UI-21.E-13.02.15. Соединить регистрацию / замену / reuse с чтением и записью на одной памяти без host-подстановки bindings. Проверено: 384 последовательности, 2304 reader / 4608 consumer вызовов, 1152 native assignments, сохранность прежних destination / контейнера / захватов. [Доказательства](../resource-tools/vampir/knowledge/evidence/interface/UI-CONFIG-REGISTRATION-DISPATCH-11316.md). Десять primitive services fixtures; caller / precedence / active config / lifetime открыты.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-status-effect-ui.py --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/status-effect-ui-audit-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_property_coverage.py -v
```

Прежние отчёты не перезаписываются. Fixture проверяет zero marker без
выдуманных имён свойств, отказ при изменении export и при выходе за body.
13 тестов аудита прошли. Это не проверка отображения активных бафов в игре.
