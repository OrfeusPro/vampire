# Обновление Vampir 1.13.22

28 октября 2026. Установлен EXE 1.13.22, полный SHA:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.

Штатный offline audit / plan завершён. Проверены полные SHA 165 архивов;
35 изменились против последнего полного архивного baseline 1.13.16.
Это не утверждение о 35 изменениях именно между 1.13.20 и 1.13.22:
отдельного полного архивного manifest 1.13.20 в библиотеке нет.
Для native функций используются последние подтверждённые роли 1.13.20,
а не архивный baseline. Профиль и runtime не переключались.

Run в библиотеке `F:/PhoneExit Resources/Vampir`:
`knowledge/update-runs/d49a1a4763f5c74caaa8f0b986a650d6a2b2c4b7562edceafa62e9ba617274bf/run.json`.
Audit: `knowledge/update-audits/0ec37918716f6c182fde48aba13bfc251989c877810b868895c2f28ef407be70/manifest.json`.

Общий автоматический function-only каталог сравнил 131 context / 1415 ролей:
403 пары baseline SHA / адрес, из них 379 основных и 24 dependency helpers.
15 соответствий подтверждены (14 основных / 1 helper), что даёт шесть уникальных
адресов в новом EXE. Очередь — 365 основных / 23 helper, всего 388 baseline пар.
Список расширен nested ролями и базой 1.13.20, поэтому его числа не являются
прямым продолжением прежнего счётчика 346 + 30.

Каталог:
`knowledge/function-reuse-catalog/8a2e511e5a1748d5ed14a6e0044b9da9c0b45ced93f22a1b0c6e6e4355334e04/manifest.json`.
В граф внесены пять source-specific function-only bindings: четыре UTF-8 input
helpers LoginResult и `game-version/utf8-length`. Последняя closed_shape recipe
проверена от 1.13.20 к 1.13.22; после подтверждения canonical recipe для следующего
обновления использует уже 1.13.22. Доказательство перехода 20 → 22 сохранено отдельно.
Предложение привязок:
`knowledge/function-bindings-11322/851bc0524485e68a3c6cdc0fd2636bf0ce2dd9cf2d04db9d3c37e4c58401ef45/manifest.json`.

## Автоматизация выбора базы

Субагент исправил общий catalog: прежний `SOURCES` учитывал только 1.13.16 и
1.13.18. Добавлены 1.13.20 и частично проверенная 1.13.22, а также три явных
переименования family для contexts 1.13.20. `input` / `native_input` executable
roles нормализуются с проверкой source/export provenance. Никакие fixture,
table/global addresses функциями автоматически не становятся.
18 fixture tests прошли, включая запрет отката к proof 1.13.20, если уже есть
reviewed binding 1.13.22, но отсутствует его доказательство. Ключ допуска отдельно
различает instruction equivalence, semantic suite и runtime.

Пока вне общего каталога восемь graph bindings 1.13.20: два writers,
wrapper constructor, platform selector/store/lookup, Windows suffix и early
LoginResult handler. Top-level поля этих shapes намеренно не угадываются.
String family не объединяется с combined buffer family: constructor roles различны.

## Закрепление пяти функций 1.13.22

Один `collect` экспортировал только пять явных roots нового EXE, с `-noanalysis`;
очередь экспорта пуста. Получены полные current exports, без обхода дерева вызовов.
Review context `knowledge/native-contexts/function-closure-11322.json` закрепляет
source SHA, обе группы exports и пять dependency-closed recipes от 1.13.20.
`verify-function-closure-11322.py` сверяет полный source, экспортное покрытие
обеих версий, все инструкции / локальные ветвления / объявленные callee и data.
Это пять function-only подтверждений, а не пять native game сценариев.

Три source-bound regression tests проверяют closures, последнюю базу в графе,
отказ при подмене target или export hash. Проверка подключена к `on_update`
и кэшу для полного SHA 1.13.22; четыре UTF-8 input helper roles и length role
сохранены в графе. Старые native semantic checks не объявлены портированными.

Отчёт closure:
`knowledge/function-closure-11322/2be610cd09532931a5bcd544bb4bd25569367393e2df971ad00559eaedf35bd5/manifest.json`.
Collection:
`knowledge/collections/68e0b9bfbe2e237ec26630337ec8b7d33f496b77ecf8e19eb7f91958bb6ac5a7/manifest.json`.
Текущие exports:
`ghidra/request-exports/03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f/run-761b5bc2280d/details.json`.
Прямой proof 20 → 22 для length:
`knowledge/function-reuse-results/070fd6241a90fab3346696b8201aedbd42f77ffe0aaf92d2a2352662698d7506/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/function-reuse-plan.py --source-sha256 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-function-closure-11322.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_function_closure_11322.py
```

Проверка целых игровых контрактов, native semantic suites новой версии,
авторизация и полный runtime не подтверждены. Следующий пакет — явные
projection gaps, source-bound вход / handler и изменившиеся данные 1.13.22.
Числа первого каталога выше — snapshot до добавления current context пяти функций;
не выдавать дополнительные same-source proofs за новые переносы.
