# Подготовка и фиксация исследования

`knowledge-index.py` объединяет поиск и явный offline lifecycle исследования.
Код и небольшие записи знаний — в Git; база, задания, логи проверок и выгрузки —
в `F:/PhoneExit Resources/Vampir/`. Инструменты не входят в runtime бота,
не запускают авторизацию или игровые действия.

## Новые выбранные пакеты

Обычное обновление начинается общим `update --auto`. Новый scoped workflow нужен
для конкретного общего блокера или нового правила. Адреса берутся из машинного
отчёта, полный SHA проверяется фактически. В переменные ниже передаются адрес
блокера и пути manifests, напечатанные предыдущей командой:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/research-scoped-v2.py prepare --question release-automatic-update --function $taskAddress --release installed
python -X utf8 phone-exit/bots/resource-tools/vampir/research-scoped-v2.py collect --request $requestPath
python -X utf8 phone-exit/bots/resource-tools/vampir/research-scoped-v2.py finish --request $requestPath --result $resultPath
python -X utf8 phone-exit/bots/resource-tools/vampir/research-scoped-v2.py check --completion $completionPath
```

Глобальные `--root`, `--knowledge`, `--database` указываются до операции.
Prepare принимает 1..32 уникальных явных адреса, installed либо полный SHA;
при необходимости `--export` передаёт конкретный готовый Ghidra report.
Report pointers сохраняются и используются при повторе даже без discovery DB.
Collect запускает только недостающий набор; сохранённый неизвестный / failed
outcome не повторяется вслепую. Новая причина или изменённые inputs требуют нового
request. Старые v1 requests продолжаются прежним entrypoint, не конвертируются.

Scoped admission проверяет выбранную closure, не всю history. Непроверенные
SQLite status / body_json / name и Markdown не дают role или runtime admission.
Полные SHA EXE, использованных report / receipt / pseudocode, tools / runtime
проверяются перед результатом. Неиспользованная история остаётся за границами.
Finish сохраняет прежние fact objects и проверяет атомарную запись / rollback.
Изменение decision rules требует нового request; known / unknown / next_action /
evidence — поля вывода question, их можно обновить между операциями.

Tooling checks остаются инфраструктурным gate, не доказательством клиента.
Для method=bounded_native нужен source-bound client check. SHA-pinned --context
файл должен оставаться неизменным; scoped CLI пока не переносит selected-fact
projection через собственную запись этого registry. Использовать отдельные
immutable context pointers. Полная история и обязательный staged Markdown audit
по-прежнему проверяются `knowledge-index.py check` перед коммитом.

[Результаты и ограничения v2](evidence/updates/HEADLESS-UPDATE-INFRASTRUCTURE-V2-11322.md).

## Подключение новой возможности к обновлению

Для задачи по квестам, движению или данным персонажа агент выбирает действующий
контракт и адаптер до реализации. Если нужна новая роль, он расширяет реестры
и общий recipe вместе с кодом возможности. Инструкции задают этот порядок,
а обновлятор читает подключения из машинных реестров.

| Область | Место подключения |
|---|---|
| Capability, contract, функции, зависимости и ресурсы | [update-contracts.json](update-contracts.json) |
| Offline check, его область, зависимости и fixtures | [research-checks.json](research-checks.json) |
| Native-семейство и проекции | [native-release-registry.json](native-release-registry.json), проверенные контексты в `native-contexts/` |
| Исполнение общего native recipe | [native-check-adapters.json](native-check-adapters.json), reviewed driver в `native-drivers-v2/` |
| Извлечение ресурсов, кэш и барьеры | Действующий pipeline и правила из [RESUMABLE-UPDATE](RESUMABLE-UPDATE.md) |
| Следующий запуск и runtime admission | Пакет следующего входа и обязательные контракты из [RESUMABLE-UPDATE](RESUMABLE-UPDATE.md) |

Выбирать применимые строки по фактическому изменению. Для UI, использующего
готовый адаптер, достаточно указать покрывающий контракт и проверить влияние
на его входы. Адреса, версии, поля layouts, идентификаторы пакетов и допуски
хранятся в manifests / реестрах с происхождением и полными SHA. Новая версия
получает собственное доказательство по зарегистрированному правилу.

Для квестов учитывать получение списка, ID и русскую локализацию, состояния,
диалоги, команды и обработку ответов в соответствующих контрактах. Движение
связывать с позицией, миром и подтверждённой командой. HP / MP и окружение
связывать с декодером, layout, обновлением состояния и потребителем данных.
Общие readers, строки, packet headers и ресурсы включать в зависимости
конкретных потребителей. Открытые пробелы идентичности и поведения фиксировать.

До завершения подтвердить компонентным проходом, что обычный обновлятор
достигает нового адаптера. Неизменный повтор должен переиспользовать проверенный
результат. Изменение существенной общей зависимости должно затрагивать нужных
потребителей. Проверку версии клиента и допустимого пакета сохранять перед
следующим входом. Полный проход и наблюдатель запускаются в режиме, заданном
пользователем и [инструкцией обновления](RESUMABLE-UPDATE.md).

Передаваемый результат содержит capability / contract / family IDs, пути
реестров и adapters, точный источник, проверку обычного пути и кэша, evidence
и оставшиеся blockers. Если автоперенос ещё требует исследования, указать
это в TASKS и итоговом отчёте с конкретной причиной и следующим доказательством.

Пример задачи для нового чата этого проекта.

> Доработай получение и выполнение квестов. Применяй AGENTS.md проекта,
> включи результат в штатное обновление и укажи проверки обычного пути,
> кэша и оставшиеся пробелы.

## Команды v1 и история

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py prepare --question common-data-population --function 14455bc40 --function 14455c950 --release installed
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py collect --request '<request manifest>'
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py finish --request '<request manifest>' --result '<result.json>'
```

`prepare` обновляет индекс, сверяет источники и собирает вопрос, материалы,
ограничения и выбранные проверки. Выходной `request` — путь content-addressed
manifest в `knowledge/requests/` библиотеки. Повтор с теми же входами возвращает
то же задание. `--reason` задаёт конкретную причину нового эксперимента.
Допустим явный SHA вместо `installed`; `all` для исследования запрещён.
Задание `installed` отклоняется после изменения установленного EXE.

Состояния функции: `ready` — завершённый псевдокод и инструкции; `incomplete` —
неполный материал; `missing` — экспорта нет. `ready` не доказывает семантику.
Прежние вопросы и документы доступны как исторический контекст / навигация.
Роли старого реестра относятся только к его явному SHA.

`collect` повторно проверяет наличие материалов и запускает закреплённый Ghidra
runner только для недостающих явных адресов, максимум 32. Принимаются начала
unwind functions. Leaf / tail без отдельного доказательства границ остаются
в очереди. При нескольких comparison projects
выбор остаётся в очереди. При отсутствии comparison project
создаётся отдельный проект по SHA с import / process `-noanalysis`. Экспортируются
только явные unwind roots задания; неполный import сохраняется для проверки.
[Проверенные границы и результаты](evidence/tools/HEADLESS-REQUESTED-GHIDRA.md).
Экспорт проверяется обычным importer.
Неполная / неудачная попытка сохраняется, тот же request не запускается по кругу.
Новое задание требует изменённого входа либо явной новой причины.

Для исходного E9 на другой explicit unwind root того же задания collector
записывает `requested_tail_calls`. Ghidra проверяет bytes/target и сохраняет
модель CALL_RETURN в export, чтобы не включать callee в тело wrapper.
Это metadata анализа; EXE и unwind-границы не меняются. Условные/косвенные и
неуказанные targets остаются без такой модели.
[Проверенный случай и воспроизведение](evidence/updates/HEADLESS-LOGIN-POST-STATE-11316.md).

Исследования сериализованы, Ghidra имеет дополнительный lock. После аварии lock
удаляют только после проверки записанного PID и его дочерних процессов; по одному
возрасту файла lock не снимается. Вызов Ghidra ждёт завершения принадлежащего ему
JVM, чтобы не оставить осиротевший процесс с открытым проектом.

## Формат результата

```json
{
  "question": "common-data-population",
  "source_sha256": "<полный SHA задания>",
  "addresses": ["0x14455bc40"],
  "conclusion": "Конкретный проверенный вывод",
  "method": "bounded_native",
  "limits": ["Явные fixtures и границы проверки"],
  "unknown": "Что осталось неизвестно",
  "next_check": "Какая следующая проверка изменит вывод",
  "evidence": [{"path": "<абсолютный путь>", "sha256": "<полный SHA файла>"}]
}
```

Методы первой версии — `static` и `bounded_native`. Все адреса входят в задание.
Evidence — документы внутри knowledge или публичные материалы Ghidra; credentials
и TCP auth captures не импортируются. `finish` проверяет поля, SHA, ссылки и
выбранные проверки, сохраняет вывод в `knowledge/releases/<SHA>/facts.json`
репозитория и обновляет индекс. Одинаковый вывод не дублируется. При ошибке
индексирования прежний facts file восстанавливается. Изменение evidence требует
осознанной сверки его SHA; устаревшая ссылка не считается действующим доказательством.
Агент пишет смысл вывода и обновляет README / вопрос вручную по результату.
Структурная проверка не устанавливает истинность утверждения.

## Проверки

[research-checks.json](research-checks.json) связывает question IDs, поддержанные
SHA, один проверенный offline unittest и зависимости. Начальный набор включает
UpdateGmc2 / UpdateSDKSetting. Остальные проверки подключать явно после просмотра
на отсутствие авторизации и игровых действий. Отсутствие записи означает отсутствие
автоматического покрытия. Для `bounded_native` нужна зарегистрированная проверка.

`prepare` и `finish` запускают только выбранные проверки. Кэш зависит от SHA
источника, definition, Python, теста, кода и явно заданных Ghidra artifacts.
Посторонний README его не инвалидирует. Непортированный тест даёт `requires_port`;
ошибка / timeout блокируют `finish`. Saved replay metadata остаются историческим
результатом с fixtures / limits, не подтверждением новой сессии.

Для native checks, вызывающих локальную Windows CRT, есть явная зависимость
`system_runtime_files: ["ucrtbase.dll"]`. Поддерживается только этот library name:
произвольные пути и другие файлы отклоняются. Системный каталог определяется
Windows API, в ключ кэша входят полный SHA DLL и текущая CRT locale. Их сверяют
также после выполнения проверки. Изменение DLL / locale требует нового результата;
инструмент не меняет locale. Фактическую DLL и locale дополнительно записывает replay.

`artifact_dependencies` принимает публичные Ghidra-материалы и проверяемые
ресурсы в `release-snapshots/<SHA>/`: content-addressed `manifest.json` и
`csv-blobs/<SHA>.csv`. Для record / table manifest с `source` также сверяются
release manifest, принадлежность PAK к его полным SHA и фактический SHA
установленного архива до обращения к кэшу. Изменившийся PAK требует нового
release snapshot; повреждённый CSV отклоняется. Приватные captures и произвольные
файлы этим допуском не разрешаются. Ключ кэша и проверка неизменности во время
теста включают эти файлы вместе с исходниками проверки.

Для именованных ресурсов дополнительно поддержан directory-only manifest в
`resource-config-snapshots/<SHA>/manifest.json`: полный SHA PAK должен принадлежать
release manifest, `configs` — быть пустым. В кэш входят manifest, `directory.json`,
`encoded-entries.bin`, release manifest и фактический SHA PAK. Повреждение любого
материала отклоняется до использования сохранённого результата проверки.

После staging перед коммитом:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py check
git -c core.safecrlf=false diff --cached --check
```

`check` проверяет связи вопросов / фактов / evidence, Markdown-ссылки, индекс и
признаки ошибочно экранированного Markdown в staged документах. Числовой смысл и
русский текст проверяются по diff: автоматической замены слов / цифр нет.

## Обновления клиента

Обычное обновление выполнять через `knowledge-index.py update --auto` или
наблюдатель, запущенный ярлыком. [Команды, базы, кэш и допуск](RESUMABLE-UPDATE.md).

`prepare → collect → finish` используется для нового вопроса, нового правила
или конкретного незакрытого блокера. Перед сбором проверить готовые материалы.
Не повторять эту процедуру вручную для каждого механического применения
готового правила: автомат сохраняет квитанцию с source / target SHA, правилом,
зависимостями, результатами и границами. Не приписывать квитанции вывод человека.

Новый подтверждённый рецепт сразу подключать к реестру, графу, semantic adapter
и `on_update` / кэшу. Отсутствующий адаптер фиксировать конкретной причиной;
массовое добавление SHA в allowlist не заменяет доказательство переноса.
Полную опись файлов, перенос функции, контракт и онлайн различать.

## Проверено 21 октября 2026

Локальный набор содержит 32 проверки: index / context / layout, research workflow,
update, current common-context native replay и существующие config guards.
Проверяются разделение SHA, отсутствие дубликатов, сохранность базы при ошибке,
неполный результат, выборочный кэш, отказ без повторного запуска и изменённые
архивы / EXE. Resource orchestration проверен с fixture adapters; массовое
переизвлечение реальной установки этой проверкой не выполнялось.

Реальная проверка `prepare` / `collect` использовала готовые функции без Ghidra,
затем отдельное задание выгрузило только `0x143d1d470`. Его экспорт:
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-56052032a1e9/details.json`,
SHA `eb8abfb20fcabd2981732523a3d57c050357561bbf3d448f3f51a64f6a52b37a`.
Семантика helper этим smoke test не установлена. `finish` сохранил подтверждённый
common-context результат в [facts текущего SHA](releases/98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e/facts.json).

Реальный `update --audit-only` проверил 165 архивов, около 21 ГБ; полный SHA есть
для каждого. EXE остался `98802d550890…`. Для 75 архивов доказано полное совпадение
с прежним baseline; для 90 прежний baseline имел только samples, поэтому равенство
с прежними bytes не доказано. Корректный новый manifest в библиотеке:
`knowledge/update-audits/e9c3dd6f62bd6e051610d0e70cdba6d31e5c3cad6306ad5b55fd025c50357aec/manifest.json`.
Отчёт: `knowledge/update-results/932418e6e4be5c3519210d636e1d41bbe1fc787f747dbf6041fa7e3cd2cd113d/manifest.json`.
Первый экспериментальный отчёт `05e0ba17…` неверно обозначал CEF archives как
удалённые из-за неполного охвата; он заменён указанным повторным аудитом.

## Проверки из update

Общий проход использует зарегистрированные offline checks и проверенные
source-bound adapters. Одну эффективную проверку исполняет один раз для всех
потребителей, повтор использует кэш с проверкой целостности. Новый source без
подходящего правила остаётся `requires_port` / конкретным блокером.

Аудит без исполнения не подтверждает совместимость. Только обязательные
прошедшие проверки точного SHA позволяют подготовить соответствующую возможность
для следующего входа; работающий owner не переключается. Исторический dispatch:
[доказательства](evidence/updates/HEADLESS-UPDATE-CHECK-DISPATCH.md).
