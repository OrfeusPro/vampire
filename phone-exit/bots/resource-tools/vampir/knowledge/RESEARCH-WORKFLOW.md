# Подготовка и фиксация исследования

`knowledge-index.py` объединяет поиск и явный offline lifecycle исследования.
Код и небольшие записи знаний — в Git; база, задания, логи проверок и выгрузки —
в `F:/PhoneExit Resources/Vampir/`. Инструменты не входят в runtime бота,
не запускают авторизацию или игровые действия.

## Команды

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

[Текущий возобновляемый процесс, контракты и границы](RESUMABLE-UPDATE.md).

После завершения загрузки лаунчером:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline '<предыдущий manifest.json>'
```

`--install` задаёт установку, совпадающую с baseline; `--audit-only` отключает
переизвлечение. Полные SHA считаются для EXE, архивов Content/Paks / Patch/Install
и каталогов архивов из baseline, включая встроенный браузер Engine.
Inventory, размер и mtime проверяются до / после; изменение прерывает обработку.
Стабильность файлов не заменяет сигнал лаунчера: запускать после окончания загрузки.
Новый EXE сохраняется как отдельный immutable snapshot и регистрируется в индексе.

Изменённые PAK v11 передаются существующему scanner доступных records. При наличии
прежних индексов запускаются сравнение blobs и извлечение таблиц. Для известных
main / pakchunk0 вызывается extractor конфигурации с проверкой index hashes.
Отказ ключа / parser, неподдержанный архив, удалённый ресурс или недостающий
baseline попадают в очередь. Связи UI / карты / таблиц требуют семантической
перепроверки; наличие извлечённых bytes не означает их совместимость.

Изменение EXE создаёт очередь затронутых контрактов без переноса старых ролей.
Отчёт не меняет runtime profile и не продвигает новый baseline автоматически.
Новый manifest можно явно использовать для следующей сверки; применимость
связей подтверждается отдельно. Среда рано утром — ориентир, фонового расписания нет.

При новом EXE обычный `update` также ищет native candidates по
[машинному плану ориентиров](release-update-targets.json). Точные строки,
исторические функции и обязательные проверки сохранены заранее. Результат
`native_targets` не меняет runtime profile; неоднозначности попадают в queue.
[Поиск, границы и следующий ручной шаг](UPDATE-TARGETS.md).

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

Обычный update выполняет проверки, назначенные контрактам, и дополнительные
checks с явными `on_update: true` и `offline_reviewed: true` в research-checks.json.
Используется общий source/dependency cache. Новый SHA даёт requires_port; ошибки
и неперенесённые проверки сохраняются в queue и checks итогового отчёта.
Audit-only их не запускает. Совместимость, baseline и runtime не продвигаются
автоматически. Подключённый набор и границы:
[dispatch проверок](evidence/updates/HEADLESS-UPDATE-CHECK-DISPATCH.md).
