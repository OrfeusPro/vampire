# Автоматическое обновление Vampir

Один проход связывает полные SHA, извлечение ресурсов, перенос функций,
проверки, кэш и подготовку пакета следующего входа. Скрипт использует JSON
реестры и manifests. Markdown объясняет порядок, но не задаёт адреса и допуски.

## Запуск и остановка

Ярлык **«Обновление Vampir»** в корне проекта вызывает `start-update.ps1`.
Он запускает наблюдатель через одноразовую задачу текущего пользователя Windows.
Наблюдатель переживает закрытие Codex; автозапуска Windows нет. Повторный запуск
использует существующего владельца. Установка игры и данные аккаунтов не меняются.

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --auto
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch start
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch status
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch retry
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch stop
```

`update --auto` выполняет один проход. `update-watch start` наблюдает за файлами
каждые 15 секунд и ждёт 120 секунд стабильности перед обработкой. Patch manifest,
file version и пауза служат сигналами; целостность подтверждается полными SHA
и контролем входов до / после работы. Незавершённая установка остаётся в ожидании.

`stop` прекращает новые проходы; текущая работа дренируется с сохранением журнала.
Статус `draining` означает, что владелец ещё ждёт свой дочерний процесс.
Stop обновлятора не останавливает игру. Не удалять lock работающего владельца.
Одинаковая ошибка не повторяется каждый цикл; `retry` разрешает новый проход.
Изменение клиента или правил также создаёт новый повод для проверки.

Явные команды сохраняются:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline '<manifest.json>' --plan-only
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline '<manifest.json>'
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --resume '<run.json>'
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-status --run '<run.json>'
```

`--install` задаёт установку. `--auto`, `--baseline`, `--resume` взаимоисключающие.
`--plan-only` / `--audit-only` ограничивают работу планом. Без подходящей полной
описи автомат выдаёт конкретный блокер; старый адрес или чужой baseline не берёт.
`update-status` читает сохранённый журнал, не подтверждая свежесть установленной игры.

## Базы, зависимости и повторное использование

Полная опись файлов и последняя доказанная база роли выбираются отдельно.
Опись текущей версии может существовать до извлечения ресурсов: недостающие
артефакты всё равно требуют обработки. Совпадение samples недостаточно.
Для роли с новой проверенной базой отсутствие proof не разрешает откат к старой.

Нативные источники и явные проекции описаны в
[native-release-registry.json](native-release-registry.json). Рецепты и возможности —
в [update-contracts.json](update-contracts.json), проверки — в
[research-checks.json](research-checks.json), ориентиры — в
[release-update-targets.json](release-update-targets.json).
Дополнительные проверенные semantic drivers описаны в
[native-check-adapters.json](native-check-adapters.json); каждый имеет фиксированный
кодовый адаптер, строгую область выполнения и свой кэш.

Общие функции, checks и missing exports объединяются по полным источникам.
Ghidra собирает только недостающие явные roots партиями до 32, последовательно.
Полный анализ EXE и холодный BinExport не являются обязательными.
Независимые расчёты могут выполняться двумя workers; публикацией владеет координатор.

При переносе проверяются границы, инструкции, вызовы, данные и зависимости.
Generic adapters создают target-bound контексты по зарегистрированным правилам.
У нового SHA нет автоматического общего разрешения: неизвестное семейство,
layout, косвенный вызов или несколько кандидатов оставляют точный блокер.
Готовые native сценарии новой версии исполняются в своей области проверки.

Кэш зависит от реальных материалов, рецептов, fixtures, инструментов и runtime.
Повтор того же прохода проверяет целостность и использует завершённые результаты.
SHA и PE-разбор переиспользуются внутри одного замороженного прохода.
Изменение правил создаёт новую identity; прежние неизменные этапы доступны выборочно.
Подмена файла по одному mtime не становится доказательством.

## Пакет следующего входа

Пакет объединяет контексты, обязательные semantic checks, конфигурацию и профиль.
Готовность считается отдельно для launcher, world-session, карты, квестов и UI.
Функциональное соответствие не закрывает целый контракт. Fixtures сохраняют границы:
неисполненные OS / engine / network effects не объявляются проверенными.

Только полный проверенный набор соответствующей возможности назначается для
следующего явного запуска. Текущий owner сохраняет свой пакет. Admission заново
проверяет точный SHA EXE, данные, правила и runtime; при втором патче неподходящий
пакет отклоняется. Старый SDK-профиль не служит fallback новой версии.
`live_verified` остаётся false до фактического результата входа.
Обновлятор не авторизуется и не отправляет игровых команд.

Для следующего запуска владельца выбирать `--profile prepared-next`; перед
подключением можно выполнить `run-live-sessions.py --profile prepared-next --check-source`.
Явные исторические профили сохраняют свои ограничения и не переключаются скрытно.
Сейчас общие semantic adapters реализованы для UTF-8, полного string writer
и archive IO / Version / Login wire, VersionResult с input buffer, базовой
подготовки Version / Login и интеграции Login SDK-getters. Для writer требуются
подтверждённый target UTF-8 и настоящие exports; archive driver использует
опубликованный writer того же SHA. Базовая preparation использует явные
OS / SDK / helper fixtures. VersionResult
подтверждает только ID 2 / scalar input и конструкторы; другие ответы и strings
требуют своих проверок. [Точные области](evidence/updates/HEADLESS-AUTO-VERSION-11322.md).
Login SDK исполняет три getters и шесть returning leaves над синтетическими
данными; настоящий backend остаётся за границами. Metadata pipeline подключён
отдельным семейством с последующей интеграцией.
[Точные области Login и проверка кэша](evidence/updates/HEADLESS-AUTO-LOGIN-PREPARE-11322.md).
Отсутствие адаптера другого семейства — отдельный блокер, а не доказанное изменение
его кода в новой игре.

Version helpers (NM, CPU, Windows, combiners, platform) и четыре cumulative
preparation уровня обслуживаются общим `version-helper-v1` с отдельными базами,
checks и кэшем каждой из девяти ролей. Integration использует доказанные target
helpers и сравнивает их с собственной базой. OS / SDK / storage / CRT effects
сохраняют явные fixture границы.
[Области и повтор](evidence/updates/HEADLESS-AUTO-VERSION-HELPERS-11322.md).

Login metadata использует общий lifecycle `portable-native-family.py`:
неизменяемые contexts / proof / reports, точные inputs кэша и атомарный index.
Standalone collector / selector / loader / writer / copy / move и интеграция
с SDK проверяются как две отдельные роли. Fixtures map / variant / strings /
backend сохраняют собственные границы; настоящий SDK результат не подразумевается.
[Области, отчёты и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-METADATA-11322.md).

LoginResult использует две роли `login-nested` / `login-strings-buffer`: первая
проверяет whole nested layout с fixture primitives, вторая исполняет настоящий
scalar / string / UTF-8 input и buffer construction. Shared VersionResult input
служит проверенным seed, без расширения прежнего scalar report. Полный input
зависит от собственного target nested proof и semantic report. Source-bound
harness разрешает только 6 / 20 явных roots после проверки proof.
[Точные области и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-INPUT-11322.md).

Continuation/reset и четыре ранние ошибки LoginResult доступны отдельными
`login-handler-v1` ролями. Они проверяют только свои 8 / 14 сценариев, без
исполнения общего gate и успешной ветки. Публикации хранятся в
`generated-login-handlers/<family>/index.json`.

Повтор публикации готовых native contexts использует отдельный
`native-publication-validations` receipt после обычного полного adapter publish.
Driver каждый раз сверяет актуальные context / report / selected index rows,
транзитивные доказательства, tools / runtime и полные SHA исходников. Только
после финального барьера квитанция разрешает пропустить повторный transfer;
повреждение остаётся блокером, отсутствие строки восстанавливается полной
публикацией. Метрики `publication_cache` различают reused / validated и source
reads / PE builds. [Области, отказы и замер](evidence/updates/HEADLESS-AUTO-LOGIN-HANDLERS-11322.md).

Общий result gate и post-state доступны как независимые `response-v1` роли.
Для gate специальное правило отделяет 251 инструкцию от inline таблиц и
проверяет две indexed displacements; 227 остановок перед выбранной веткой
не подтверждают её внешние effects. Post-state использует свою последнюю
проверенную базу 18, gate — базу 20. Новые публикации сохраняются в
`generated-responses/<family>/index.json`.
[Области и повтор](evidence/updates/HEADLESS-AUTO-RESPONSE-11322.md).

Метрики публикаций из driver сохраняются также в
`native_contexts.publication_cache` обычного update journal. Они включают reused /
validated / receipts_written и source-store counters. Поле seconds — время
всей сессии driver, включая его этапы; это не таймер одного publish.

Целый current LoginResult handler доступен как `login-full-v1` /
`login-full-handler`: два native roots (handler и gate), synthetic packet 352 байта,
48 точных сценариев. Разовый legacy import не означает неизменность handler;
обязателен новый target report. Дальнейший перенос использует весь проверенный
current handler и независимые target dependencies. Указатель публикации —
`generated-login-full/index.json`. Reader, post-state / continuation integration,
реальная регистрация в контейнере и допуск онлайн отдельны.
[Правило и замеры](evidence/updates/HEADLESS-AUTO-LOGIN-FULL-11322.md).

Same-packet композиция доступна как `login-composition-v1` /
`login-response-composition`: 22 roots объединяют native buffer / reader и
handler / gate. 77 сценариев проверяют общий packet, source strings и cursor;
при отказе reader handler не вызывается. Прямой вызов управляется координатором,
native dispatch этим не подтверждается. Новая опубликованная роль заменяет
начальный seed при выборе базы. Указатель — `generated-login-composition/index.json`.
[Границы и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-COMPOSITION-11322.md).

Регистрационный `registration-v1` / `login-registration` переносит проверенную
базу 18 на 22: полный helper (101 инструкция / 395 байт) и настоящий ID 4 leaf
исполняются в native стенде; окно owner из 75 байт проверяется статически.
Адреса конструктора и handler связываются с опубликованными target contexts
`login-nested` и `login-full-handler` и их semantic reports. Запрос выделения
в исходном окне составляет 344 байта; `packet_bytes=352` означает область хранения
проверочного стенда. Эти величины сохраняются раздельно, прежние reports
и их границы не переписываются. Конструктор, owner, container insert, name getter,
UTF-8 conversion и внешние сервисы не исполняются этим пакетом. Name fixture
возвращает отдельный descriptor и сохраняет outparam; cleanup текущего указателя
не подтверждает реальное владение исходным packet. Native dispatch, integration
post-state / continuation и онлайн требуют собственных доказательств.
Указатель публикации — `generated-login-registration/index.json`; это не next-profile.
34 новых native сценария и 602 tooling теста прошли. Общий повтор 26 drivers
использовал 78 этапов и 26 публикаций из кэша без native / JVM / PE rebuild
(77.785473 с); reports и кэш-метрики сохранены в отчёте.
[Области и приёмка](evidence/updates/HEADLESS-AUTO-LOGIN-REGISTRATION-11322.md).

## Журналы и дальнейшая работа

В библиотеке ресурсов вне Git хранятся `knowledge/update-runs`, `update-stages`,
`update-contexts`, `check-results`, `prepared-profiles`, `prepared-bundles` и
`next-profiles`. Данные наблюдателя находятся в
`%LOCALAPPDATA%/PhoneExit/Vampir/update-watch/<установка>/`.
Базы generic семейств публикуются отдельно в `generated-native/index.json`
(UTF-8), `generated-string-writers/index.json` и `generated-archive-wire/index.json`,
а также `generated-version-results/index.json`, `generated-version-prepare/index.json`,
`generated-login-prepare/index.json` и `generated-login-sdk/index.json`;
семейства Version helpers — в `generated-version-helpers/<family>/index.json`;
Login metadata — в `generated-login-metadata/<family>/index.json`;
LoginResult — в `generated-login-input/<family>/index.json`;
они не являются next-profile. Указатели читаются соответствующими adapters отдельно
от исторических function catalog projections.

Сводка различает проверенные функции, semantic результаты, возможности,
корневые блокеры и зависимых потребителей. Число строк прежней queue не равно
числу независимых ручных задач. Метрики показывают исполнение, reuse, JVM,
длительности и стоимость проверки кэша; обещания времени будущего патча не делаются.

Новый общий блокер разбирать по [RESEARCH-WORKFLOW](RESEARCH-WORKFLOW.md).
После результата подключать правило к автомату и кэшу сразу. Автоматическое
применение готового правила сохраняет машинную квитанцию; повторный ручной
`prepare/collect/finish` для каждой неизменной функции не требуется.

Исторический замер прежнего контроллера:
[HEADLESS-RESUMABLE-UPDATE-11316](evidence/updates/HEADLESS-RESUMABLE-UPDATE-11316.md).
Прежняя инструкция, закреплённая историческим фактом, сохранена побайтно в
[RESUMABLE-UPDATE-11316](RESUMABLE-UPDATE-11316.md); её команды и запреты относятся к тому этапу.
Установленные инструменты и их ограничения: [ANALYSIS-TOOLS](../ANALYSIS-TOOLS.md).
Проверка текущей автоматизации, замеры и оставшиеся границы:
[HEADLESS-AUTOMATIC-UPDATE](evidence/updates/HEADLESS-AUTOMATIC-UPDATE.md).
Следующий подтверждённый пакет:
[автоматический string writer 20 → 22](evidence/updates/HEADLESS-AUTO-STRING-WRITER-11322.md).
Архивные методы и целые тела пакетов:
[автоматический archive-wire 20 → 22](evidence/updates/HEADLESS-AUTO-ARCHIVE-WIRE-11322.md).
Подготовка и чтение ответа:
[автоматический Version 20 → 22](evidence/updates/HEADLESS-AUTO-VERSION-11322.md).
