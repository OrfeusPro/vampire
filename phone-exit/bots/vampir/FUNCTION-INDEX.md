# Vampir — функции и доказательства

Единый поиск по адресу/имени:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --build
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --query 14453cdf0
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --query SendSignIn
```

Generated список: `F:/PhoneExit Resources/Vampir/knowledge/INDEX.md`;
машинная база рядом — `function-registry.json`. Последний проверенный экспорт
содержит 408 выбранных функций, а не все функции EXE. В базе есть calls,
curated роли, границы и адресные ссылки на существующие разборы.
Упоминания адресов вне экспорта индексируются отдельно, без выдуманного типа.

- [Тематическая сводка](../resource-tools/vampir/knowledge/TOPICS.md).
- [Правила ведения](../resource-tools/vampir/knowledge/README.md).
- [Текущие вопросы](../resource-tools/vampir/knowledge/questions.json).
- [Уточнённые роли](../resource-tools/vampir/knowledge/function-roles.json).
- [Исторический тематический указатель](FUNCTION-HISTORY.md).

Исторические аналитические имена могут оказаться неточными. Сначала читать
established_role / limits и доказательства; decompilation и название функции
сами по себе не подтверждают реальный игровой сценарий.
