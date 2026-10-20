# Vampir — исследовательские инструменты и данные

Главный вход: [README бота](../../vampir/README.md).
[Тематическая сводка](knowledge/TOPICS.md) показывает подтверждённые результаты
и границы. [Правила базы знаний](knowledge/README.md) — обязательный порядок
перед новым разбором. Инструменты исследования не входят в runtime бота.

## Расположение

- В этом каталоге остаются scripts, lock-файлы и вспомогательные данные сборки.
- `knowledge/topics/` — актуальная сводка по каждой теме.
- `knowledge/evidence/<тема>/` — подробные разборы с источниками, SHA и командами.
- `knowledge/questions.json` — известное / неизвестное / следующий шаг / что не повторять.
- `knowledge/function-roles.json` — вручную сверенные роли функций.
- `F:/PhoneExit Resources/Vampir/` — большие отчёты, инструменты, assets и exports.

## Быстрые входы

- [Ресурсы и каталоги](RESOURCE-INDEX.md).
- [Выбор и установка инструментов](ANALYSIS-TOOLS.md).
- [Функции](../../vampir/FUNCTION-INDEX.md).
- [Порядок работ](../../vampir-headless/TASKS.md).

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --build
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --query 14453cdf0
```

Не повторять извлечение или native replay только ради нового отчёта. Сначала
найти существующее доказательство и записать конкретный неизвестный участок.
Новый SHA клиента требует сверки затронутых связей.

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) сохраняет прежний README инструментов.
[document-locations.json](knowledge/document-locations.json) фиксирует переносы;
`regroup-documentation.py` — однократная миграция, повторный --apply запрещён.
