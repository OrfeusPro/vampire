# Исходные корни и Outer-ветви интерфейса

`ui_outer_scope.py` проходит точные Outer индексы экспортов до ближайшего
WidgetBlueprintGeneratedClass. `scan-ui-outer-scopes.py` применяет это правило
ко всему каталогу и строит отдельные схемы по выбранному **исходному** корню.
Имя, единственный доступный root или префикс Default__ не назначают владельца.
Outer не заменяет Parent/Content слота и не доказывает видимый runtime root.

## Проверенный набор

Слой `c5881efd622a6cba6c604d5e7fadbf21296c38ee6d84bf6209043e656bf9018f`
находится в `F:/PhoneExit Resources/Vampir/ui-property-scans/outer-scopes/`.
Вход — полный source audit ui-all-source-audit-02.json с SHA256
`09bd5af2c1dad0c6fd72fde1e004eaeaab5d0c8bfe5799ba9690d60fbca1cfc6`.
Сверены manifest / inventory / catalog / UAsset / UExp / exports и корни вариантов.

- 2374 физических пакета, 200125 экспортов, 2376 исходных корней / вариантов.
- 117727 включений controls принадлежат выбранному корню; 188 — другому, одно — unowned.
- 71985 decoded slots принадлежат выбранному корню; 168 — другому.
- 2775 excluded slots принадлежат выбранному корню; восемь — другому.
- Четыре варианта имеют два корня; циклов / повреждённых Outer ссылок и
  пересекающих корни decoded Parent/Content отношений не обнаружено.

Числа controls / slots считают включения в варианты, включая исторические
копии и виртуальные aliases; это не число одновременно видимых элементов игры.

Для двух физических версий RegionSelect / TitleRegionSelect получено:

| Исходный корень | Controls | Decoded slots | Excluded slots |
| --- | ---: | ---: | ---: |
| 181 · WBP_RegionSelectPopup_C | 25 | 22 | 0 |
| 182 · WBP_TitleRegionSelectPopup_C | 69 | 62 | 4 |

Сформированы 2376 схем `local_widget_schema` существующим компилятором.
Их source_scope сохраняет foreign / unowned / unresolved exports в quarantine,
а cross-scope отношения — отдельной диагностикой. Оригинальные каталоги, старые
схемы и renderer не заменены. Все geometry_verified / implementation_verified
сохраняются false; runtime_visible_root=null. Исходный класс не выбирает активное окно.

## Нераспределённый объект

В pakchunk500-Windows-1565.json export 427 / WBP_EnchantHighlightItemT_C_0
имеет Outer цепочку 427 → 429 → 0. К Blueprint-корню 437 она не приходит.
Экспорт сохранён в unowned; имя / единственный root не используются как fallback.
Нужно отдельно установить назначение этой ветви и её runtime создание.

## Формат и повтор

```text
index.json → sources / tools SHA, packages, variants, root_consumers
packages/<SHA>.json → все exports, Outer chain, owner_root, issues
variants/<catalog file>.json → selected / foreign / unowned / unresolved по root
schemas/<catalog file>.json → исходная локальная схема и source_scope / quarantine
```

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/scan-ui-outer-scopes.py build --audit 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-all-source-audit-02.json' --audit-sha256 09bd5af2c1dad0c6fd72fde1e004eaeaab5d0c8bfe5799ba9690d60fbca1cfc6
python -X utf8 phone-exit/bots/resource-tools/vampir/scan-ui-outer-scopes.py verify 'F:/PhoneExit Resources/Vampir/ui-property-scans/outer-scopes/c5881efd622a6cba6c604d5e7fadbf21296c38ee6d84bf6209043e656bf9018f'
```

Verifier заново строит все ownership / partitions / scoped schemas по источникам
и сравнивает каждый файл. Проверка прошла, результат сохранён вне Git как
`ui-property-scans/outer-scope-verification-01.json`.
SHA256 результата: `a5e10a392655e45a96c2e3027620b7de128718a5fd6ed44e2b3d3ae3fe0fa28a`.
Семь новых тестов проверяют разделение одинаковых имён, отсутствие fallback по имени, unowned / cycle /
dangling состояния, cross-root отношения, quarantine и immutable переиспользование.
Всего с прежними Source / Slot / Layer тестами прошли 48 тестов.

Следующие проверки: runtime visible root / dynamic bindings / desired size,
случай unowned Enchant и интеграция scoped схем в сборщик после соответствующего
аудита. Исходная ветвь сама по себе не закрывает геометрию, стиль или поведение окна.
