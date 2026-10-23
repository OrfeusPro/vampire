# Связанные проверки в команде обновления

23 октября 2026. Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [SDK runtime profile](../auth/HEADLESS-SDK-RUNTIME-11316.md).

## Как фиксируется применимость

`release-update-targets.json` хранит ориентиры функций, reviewed source SHA,
scope, required checks и ограничения автоматизации. `research-checks.json`
связывает ID проверки с поддержанными SHA, одним offline unittest и зависимостями.
`knowledge/releases/<SHA>/facts.json` хранит выводы с evidence и оставшимся unknown.
Эти три записи отвечают за поиск, проверку и смысл результата соответственно.

Проверка реализации обнаружила пробел: `update` выполнял аудит, resource adapters
и поиск кандидатов, но связанные unittests запускались отдельно через research
prepare / finish. Теперь `research-update.py` вызывает только явно отмеченные
`on_update: true` проверки с `offline_reviewed: true`. Лимит — 32 проверки;
дубликаты ID отклоняются. `--audit-only` их не запускает.

Первый подключённый набор:

| Check ID | Область |
| --- | --- |
| release-launcher-contract | Контракт launcher requests / responses |
| gmc2-geo-native-11316 | Source-bound geo consumer и country policy |
| sdk-runtime-launcher-11316 | Сборка текущего SDK profile и offline input path |
| release-character-selection-probe | Прежняя цепочка списка / выбора персонажа |
| release-world-completion-policy | Прежняя цепочка завершения входа в мир |

Используется общий `research-workflow.run_checks` с явными check IDs.
Кэш зависит от source SHA, definition, теста, кода, объявленных artifacts,
Python / runtime distributions и при необходимости CRT DLL / locale. Неизменные
входы используют сохранённый результат; новый SHA возвращает `requires_port`.
Посторонний документ не требует повторять анализ, если он не объявлен зависимостью.

В `update-results` добавлены `checks` с ссылками на отчёты / cache keys.
Любое состояние кроме passed остаётся в queue: requires_port, failed, timeout,
requires_review. Ошибка проверки inputs сохраняется с причиной; проверка без
offline review не исполняется. Baseline / runtime автоматически не продвигаются.

## Повторная сверка сделанного SDK переноса

Новый dispatcher обнаружил, что NID primitive report закреплял прежний
`research-workflow.py`. Из-за его изменения SDK profile build отказал до тестов.
Report пересоздан: 1124 caller cases, 112 numeric cases и 176 channel cases.
SHA нового report:
`4c9c0bd27f4cfa2c8b4baf4c3a28fe2f7bf393d549b9289ac38ba5a385958ecb`.
Он находится в `F:/PhoneExit Resources/Vampir/code-clues/nid-primitives-11316/`.
Native код, fixtures и границы прежнего исследования не расширялись.

Сборщик явно закреплён за новым report; SDK manifest пересобран и loader
переключён на SHA
`da0dd314a0955190b0cc368ded2c895499083188bf9a7104c546d404c2a17984`.
Каталог: `F:/PhoneExit Resources/Vampir/sdk-source-profiles/<SHA>/manifest.json`.
Прежние reports / manifest сохранены как история; их SHA не переписаны.
Область остаётся только launcher, network_ready / game_protocol_verified false.

## Проверки и границы

15 update tests покрывают выбор opt-in checks, игнорирование остальных,
очередь ошибок / неперенесённых checks, отказ unreviewed, audit-only и повтор
через dependency cache. 14 workflow tests проверяют в том числе изменение
содержимого dependency, неизменность при постороннем документе, CRT и кэш.
Все browser / HTTP / SDK действия синтетические; авторизация не выполняется.

Отдельно вызван настоящий dispatcher пяти подключённых checks для текущего SHA.
Launcher, geo и SDK runtime прошли; список / выбор и world completion
вернули requires_port. Отчёт находится вне Git:
`F:/PhoneExit Resources/Vampir/knowledge/update-check-reviews/4bcc9f4b7ae877b48aac7c599ee3e25473a1ec33de925bfc13b7bf4de9626fea/manifest.json`.
Это проверка dispatch, а не повторный
полный аудит 165 PAK, извлечение ресурсов или живая сессия.

Пункт обновлений остаётся незавершённым: нужно добавить проверенные opt-in
checks для остальных ресурсных и игровых связей, перенести текущий игровой
профиль, отдельно подтвердить живой вход. Затем измерять нагрузку нескольких
ботов и переносить лёгкий runtime на Android. Исследовательские инструменты,
native replay и база знаний в Android runtime не включаются. Расписание не создано.
