# Участки GMC2 URL и headers в 1.13.16

23 октября 2026. Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Baseline 1.13.14:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [проверки игровых настроек](HEADLESS-SDK-OVERRIDE-NATIVE-11316.md).

## Поиск и статическая сверка

В старом source по явным unwind roots найдены точные ASCII diagnostic
signatures RefreshSDKConstants и RequestGMC2. Они сохранены отдельно в
`knowledge/release-gmc2-request-targets.json` с прежними SHA / roots / literals.
Locator подтвердил baseline и нашёл по одному текущему кандидату без gaps:

| Функция | Прежний root | Текущий root |
| --- | --- | --- |
| RefreshSDKConstants | `0x1444faff0` | `0x1444fa180` |
| RequestGMC2 | `0x1444fca30` | `0x1444fbbc0` |

Оба полных exports получены через prepare / collect в проекте текущего SHA.
Индексация первого collect остановилась из-за изменения knowledge inputs;
экспорты и завершённый Ghidra сохранены. Следующий collect повторно использовал
готовые функции без JVM и успешно закончил индексацию.

`audit-gmc2-request-11316.py` проверяет полные SHA двух EXE и export,
совпадение всех экспортированных инструкций с целыми source unwind roots,
затем сравнивает формы инструкций и локальные branch offsets.
RIP displacements и внешние direct targets маскируются; их содержимое
и семантика не считаются проверенными.

| Участок | Start включительно | Stop исключительно | Инструкций в участке / whole root |
| --- | --- | --- | --- |
| URL | `0x1444fa308` | `0x1444fa61d` | 172 / 456 |
| Headers | `0x1444fbe00` | `0x1444fc051` | 139 / 433 |

Формы совпали не только в участках, но и во всех 889 инструкциях двух roots.
Внешние callees / globals могут отличаться при таком совпадении. Это не native
проверка URL или headers и не разрешение обновить runtime profile.
Например, getter build code теперь явно вызывается как `0x1445320c0`;
его поведение ещё нужно перенести отдельно.

## Автоматизация следующего обновления

Основной `release-update-targets.json` ссылается на дополнительный набор
через additional_target_plans. `knowledge-index.py update` при новом EXE
последовательно запускает locator для основного набора и этого GMC2-набора.
Исходный лимит 16 anchors / 32 roots на набор не увеличивался.
Разрешено не более трёх дополнительных наборов, только существующие sibling
JSON files внутри knowledge; рекурсивное расширение не выполняется.

Результаты основного набора остаются в native_targets, дополнительных —
в additional_native_targets с именем плана. Отказ / неоднозначность любого
набора создаёт именованную задачу в очереди. Audit-only не запускает locator.
Ни новый baseline, ни runtime profile автоматически не продвигаются.
Это запуск проверки по изменению EXE, а не новое фоновое расписание.

У обеих текущих функций добавлены automation annotations: точный SHA,
scope «статическая whole coverage / masked shape», required_checks.
Статическая проверка не обозначена как выполнение native ветки.

## Материалы и проверки

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Locator: `code-clues/update-targets/29dd2baf76e3c9b34b5f5aed0da45c54327fd8e1e6b6cb1d1769dade93482631/manifest.json`.
- Export: `ghidra/request-exports/<текущий SHA>/run-777fc0535ec7/details.json`,
  SHA `a0509eeaa329af68616c59bbb695a7440c1487aaa894f808615cebe0139bf2fa`.
- Audit: `code-clues/gmc2-request-11316/ca6bbe497db73e29b4b56e19c57a7402ada657c7db65f8f231b90cf54c5cb046/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/locate-release-update-targets.py --targets phone-exit/bots/resource-tools/vampir/knowledge/release-gmc2-request-targets.json --source-sha256 d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-gmc2-request-11316.py
```

Три audit-теста проверяют точные участки, whole coverage и отклонение
повреждённых source / export. Одиннадцать update-тестов покрывают также
последовательный дополнительный поиск, очередь неоднозначности, запрет
выхода из knowledge, дубликатов и превышения лимита наборов. Update-тесты
используют синтетическую установку и adapters, не настоящую загрузку игры.

Далее выгрузить явные новые getter / append / initializer dependencies,
исполнить участки URL и headers с ограниченными fixtures и сверить результаты
с portable helpers. До этого внешний контракт GMC2 остаётся неперенесённым.
