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
и archive IO / Version / Login wire. Для writer требуются подтверждённый target
UTF-8 и настоящие exports; archive driver использует опубликованный writer того же SHA.
Отсутствие адаптера другого
семейства — отдельный блокер, а не доказанное изменение его кода в новой игре.

## Журналы и дальнейшая работа

В библиотеке ресурсов вне Git хранятся `knowledge/update-runs`, `update-stages`,
`update-contexts`, `check-results`, `prepared-profiles`, `prepared-bundles` и
`next-profiles`. Данные наблюдателя находятся в
`%LOCALAPPDATA%/PhoneExit/Vampir/update-watch/<установка>/`.
Базы generic семейств публикуются отдельно в `generated-native/index.json`
(UTF-8), `generated-string-writers/index.json` и `generated-archive-wire/index.json`;
они не являются next-profile. Последний указатель читается archive adapter отдельно
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
