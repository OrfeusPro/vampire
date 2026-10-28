# Продолжение входа 1.13.20: устранён пропуск кандидата

28 октября 2026. После [пакета reader](HEADLESS-LOGIN-READER-FLOW-11320.md)
готовый handler export позволил разрешить последний anchor continuation.
Источник — полный SHA
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.

## Причина и исправление

Начальный raw-фильтр `raw[:3]` в `align-login-continuation-11320.py`
включал displacement первого `CALL rel32`. При переносе адресов эти байты
изменились: старое начало `e80ca3`, текущее `e8bda2`. Поэтому поиск не доходил
до полной проверки нормализованных инструкций. Теперь предфильтр использует
только первый opcode byte; полная форма инструкций и известные callee / RIP
ссылки по-прежнему обязательны. Бюджеты поиска и кандидатов не увеличены.

Субагент независимо проверил единственность последовательности из пяти
инструкций в текущем handler. Точная пара:

- Прежний anchor `0x14679b6ff` → текущий `0x14679e68e`.
- Текущие bytes: `e8bda2fbffe80840d1ff488bc8488b10ff5228`.
- Post-state `0x146758950` → getter `0x1464b26a0` → virtual slot `+0x28`.
- Getter читает singleton `0x14b6014a8`; эта связь независимо присутствует
  в готовом Login alignment.

Генератор также закрепляет SHA обоих использованных exports по уже проверенным
декларациям `login-prepare-11320.json`, а не только по свежему hash файлов.
Само наличие candidate context не считается semantic admission.

## Проверенное поведение

Создан `knowledge/native-contexts/login-continuation-11320.json`.
Обычный `verify-login-continuation-context.py` исполнил **8 native сценариев**
на полном constructor `0x1464a97b0` и reset `0x1464afc70`, с native getter.
Проверены base/final vptr конструктора, getter → singleton, reset в slot `+0x28`,
порядок внешних helper calls, ожидаемые поля, границы памяти и записи reset.
Внешние engine / container / allocation helpers остаются объявленными fixtures.
Прочие virtual slots не объявлены полностью проверенными.

Два native регрессионных теста прошли: 8 сценариев и отклонение подмены таблицы,
singleton или anchor. Отдельный static тест подтверждает, что relocation bytes
больше не скрывают anchor, но не превращают поиск в семантическое подтверждение.

Source variant `native-login-continuation-context` подключён к штатному
`on_update` и кэшу. В граф `game-login` внесены scoped bindings
`continuation-constructor` / `continuation-reset`. Прежние варианты сохранены.
Новый Ghidra export не потребовался; использованы готовые полные roots.

## Происхождение и остаток

Content-addressed alignment в библиотеке `F:/PhoneExit Resources/Vampir`:
`knowledge/continuation-alignment-11320/6e34eadd36eb3cd636564dee64dc2351f88a1646dbd4c76c0c4e375dff2fc807/manifest.json`.
Полные SHA exports закреплены в context. Исторический отчёт `requires_review`
сохранён как результат прежнего поиска; текущий проход его не переписывает.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/align-login-continuation-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_continuation_11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_continuation_candidates_11320.py
```

Блокер поиска continuation снят. Полный handler / post-state и actual nested
LoginResult layout ещё не подтверждены; reset fixture не доказывает весь вход.
Строгий список **346 основных функций и 30 helpers** этим scoped поведением
не закрыт. Сеть, вход в игру и runtime activation не запускались.
