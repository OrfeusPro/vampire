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
- [ ] UI-21.E-10. Отдельным заданием исследовать тело Refresh 144a8f220: вызовы, данные и границы эффекта; не считать его кликом по кнопке или updater без проверки.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-status-effect-ui.py --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/status-effect-ui-audit-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_property_coverage.py -v
```

Прежние отчёты не перезаписываются. Fixture проверяет zero marker без
выдуманных имён свойств, отказ при изменении export и при выходе за body.
13 тестов аудита прошли. Это не проверка отображения активных бафов в игре.
