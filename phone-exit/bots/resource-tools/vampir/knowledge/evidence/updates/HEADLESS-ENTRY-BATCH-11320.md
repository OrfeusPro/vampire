# Подготовка входа и VersionResult: общий пакет 1.13.20

28 октября 2026. Продолжение [wire пакета](HEADLESS-WIRE-BATCH-11320.md) и
[очереди функций](HEADLESS-DEPENDENCY-FRONTIER-11320.md).
Проверенные SHA EXE: база 1.13.18
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`,
цель 1.13.20
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Игра и сетевые команды не запускались. Runtime не активирован.

## Выполнено

| Группа | Native сценарии |
| --- | --- |
| Version prepare, NM, CPU, Windows, combiner, platform и их интеграции | 1072 |
| Login prepare, SDK, metadata и интегрированная metadata | 3424 |
| VersionResult reader / constructor / короткие тела / отказ каждой операции | 126 |
| VersionResult handler с reader, construction и всеми switch indices | 331 |

Общий `run-entry-batch-11320.py` исполняет первые три строки — **4622**
сценария. Это количество исполнений в объявленных наборах, не число уникальных
функций. Отдельный handler добавляет **331**, всего **4953** исполнения.
В пакет входят 16 текущих contexts: десять preparation Version, его reader и
handler, четыре preparation / metadata Login. Проверяются целые функции и
заданные интеграции, таблицы, вызовы, порядок полей, ABI, canaries, cleanup.

Результат общего пакета в библиотеке ресурсов:
`knowledge/entry-batch-verified-11320/5d8d52caf23644079d5d3663cf167432ce6617a2208960df6207fa66a8fb8ad2/manifest.json`.
Первое исполнение `reused=false`; повтор — тот же SHA и `reused=true`.
Handler report:
`knowledge/native-version-result-handler-checks/03ea1910d28b20615dfd14c90b5575655f599cae93584b3cfba4839c705b9003/manifest.json`.
SHA обоих файлов совпадают с именами каталогов.

## Источники и автоматизация

Субагенты независимо подготовили bounded Version/Login alignment и gate.
После достижения лимита субагентов родитель продолжил с их сохранёнными
результатами, не объявляя незавершённые части готовыми.
Кандидаты ограничены явными roots и окном ±65536; неоднозначные одинаковые
тела разрешаются только ссылками из уже уникальных callers. Совпадение форм
не выдаётся за проверку семантики. Генератор текущих contexts использует
source-bound links, действительные exports и проверенные bounded leaves.

Первый набор 32 roots, включая input-архив и gate, уже был выгружен до потери
наблюдаемого процесса. После проверки отсутствия PID и детей снят устаревший
research lock; обычный `collect` вернул reuse без нового Ghidra. Экспорт:
`ghidra/request-exports/<SHA цели>/run-cd7653218083/details.json`.
Дополнительный набор 26 roots остановился на `0x146758950`: decompiler block
outside requested unwind ranges. Этот post-state root исключён с явной
причиной; независимые 25 roots получены без ослабления проверки:
`ghidra/request-exports/<SHA цели>/run-85faf6d508b5/details.json`.
Неудачный export и логи сохранены. Анализ всего EXE и обход дерева callees
не запускались.

`generate-entry-contexts-11320.py` сохраняет происхождение, полные SHA,
актуальные tables / leaf bytes / call sites. Для Login обнаружено изменение
compiled tag. `verify-login-prepare-context.py` требует явные metadata нового
источника; прежняя константа разрешена только для проверенных 1.13.16 / 1.13.18.
Input fixture допускает только отдельный текущий SHA и base table
`0x1496731e8`, без увеличения function budget.

Gate `0x1467d0c60` имеет 251 инструкцию и явное разделение code / inline data.
Проверены таблица четырёх RVA, index из 227 байт, dispatch sequence и границы
unwind. `version-gate-switch-11320.py` содержит отдельные current constants;
handler выбирает модуль только по фиксированной паре полного SHA и switch ID.
Обычная нормализация других roots сохраняется. Четыре отдельных gate-теста
отклоняют неверный источник, неполную выгрузку и изменённые bytes / таблицы.

13 штатных проверок получили source variants для 1.13.20 и прошли обычный
`run_checks`. Они используют общий кэш подготовки; handler проверяется отдельным
штатным check со своим dependency cache. `native-entry-batch-11320` и
`native-result-gate-11320` подключены к `on_update`. Основной набор — шесть
тестов, включая source / tag / export / callsite и изолированную cache tamper /
path escape проверку; handler — два теста, gate — четыре. Synthetic cache case
не доказывает native поведение. Старые checks сохраняют прежний выбор.
В граф контрактов добавлены только проверенные preparation / constructor /
VersionResult reader / handler bindings нового полного SHA.

## Что осталось

- **LoginResult изменился:** полные формы прежних constructor / reader / handler
  не совпали. Имя `PktLoginResult` связано с текущей таблицей `0x149929040`,
  candidate reader — `0x1456dc140`. Новая структура и обработка ещё не перенесены;
  старые contexts к ней не применяются. Это конкретный следующий пакет.
- Post-state `0x146758950` имеет описанный выше пробел границ. Registration /
  continuation и full result pipeline пока не допущены на 1.13.20.
- SDK / OS / storage / allocator / strings / send и внешние эффекты остаются
  явно ограниченными fixtures. Не доказаны реальные значения SDK, сетевой вход,
  длительное соединение и несколько реальных аккаунтов на новой версии.
- Более строгая очередь `closed_shape` 346 основных / 30 helpers не закрывается
  искусственно этими bounded сценариями. Закрыты 13 source-specific проверок
  поведения; оставшиеся контрактные checks сохраняют `requires_port`.

Готовые wire / UTF-8 сценарии вручную не повторялись. Штатный source/dependency
cache проверяет целостность и переиспользует неизменённые результаты.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/run-entry-batch-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_entry_batch_11320.py
```
