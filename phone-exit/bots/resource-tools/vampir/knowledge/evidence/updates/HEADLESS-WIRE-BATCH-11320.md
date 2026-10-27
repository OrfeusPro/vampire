# Общий пакет UTF-8, строк и архивов 1.13.20

28 октября 2026. Продолжение
[очереди общих зависимостей](HEADLESS-DEPENDENCY-FRONTIER-11320.md).
Перенесены три штатные проверки: `native-utf8-context`,
`native-string-writer-context`, `native-archive-wire-context`.
Они выберут отдельные проверенные source variants для нового полного SHA.
Профиль игры не активирован, вход и сетевые команды не выполнялись.

## Источники и явный набор

База 1.13.18:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Цель 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Полные EXE snapshots сверены SHA, используются закреплённые Capstone 5.0.6
и Unicorn 2.1.4. Исследовательские инструменты не входят в runtime.

`align-wire-contexts-11320.py` ограничен 18 явно заданными адресами из прежнего
пакета и окном ±65536 байт: 15 unwind roots и три объявленных leaf spans.
Совпадение полного нормализованного тела и локальных переходов даёт кандидата;
ближайший адрес и общий сдвиг не используются. Все кандидаты оказались
уникальными. Генератор связывает прямые targets и RIP references, отдельно
проверяет slot +0x10 таблиц packet writers. Это ещё не семантический допуск.

Через `prepare` → `collect` получены полные экспорты **14 нужных roots**.
Overflow growth не включён в исполняемый набор и отвергается fixture.
Экспорт: `ghidra/request-exports/<SHA цели>/run-af05ed4ef63f/details.json`
в библиотеке ресурсов. Коллекция: `83201807f3ddd6529cb5bcdceeba98d5edc9456e831ad40967f73acfafc36605`.
Остальные функции EXE не декомпилировались.

Отчёт генератора с настоящим экспортом:
`knowledge/wire-context-alignment-11320/24f17b4d0ff04f6b7dbe8bbba49139ba35d05f49b92055fbacc79dfd35936c74/manifest.json`.
Он содержит происхождение и три сгенерированных контекста
`utf8/string-writer/archive-wire-11320.json`. Полные таблицы, bytes / SHA
листьев, cookie, IAT и текущие targets берутся из новой сборки; старые адреса
не подставляются. Семантику независимо проверяют прежние native verifiers.

## Выполненные сценарии

| Общая часть | Фактически проверено |
| --- | --- |
| UTF-8 length / conversion / encoder | 142 вектора и 80 scalar/capacity случаев; malformed UTF-16, границы, canaries |
| Целый string writer | 228 случаев: small/heap strings, временные allocations/free, точные аргументы, байт результата archive |
| Архив и Version/Login writers | 45 archive случаев и 64 целых тела пакетов: порядок и значения полей, bytes и guards |

Итого **559 native сценариев** в одном общем пакете.
Архивная таблица `0x149673420` проверена полным SHA 0xf8 байт и семью slots;
constructor связан с ней и своим base-constructor. String writer
`0x144aad3d0` проверяет порядок direct / indirect calls, cookie и identity
`_invalid_parameter_noinfo_noreturn` из CRT import. Version writer
`0x1456e89e0` связан с таблицей `0x149929818`, Login writer `0x1456e84d0` —
с `0x149928e80`. Тела Login проходят round-trip переносимого кодека;
bool сохраняет исходный байт, включая 0x80.

Общий отчёт в библиотеке:
`knowledge/wire-batch-verified-11320/c7d429d94d30290786fdb67a16f9853c218f9cbc2e50ba5ad8eda2609b3d2467/manifest.json`.
SHA совпадает с именем каталога. Первое выполнение вернуло `reused=false`,
следующее — тот же SHA и `reused=true` без повторного native исполнения.

Общий набор содержит 14 тестов, включая отрицательные source/export/leaf,
table hash / slots / constructor / callee, cookie / import / fixture,
field-order проверки и четыре synthetic проверки целостности кэша. Последние
не доказывают native поведение. Три source-specific wrapper проверки используют
тот же кэш. Схема контрактов и source variants также проверены.

## Подключение к обновлению

`run-wire-batch-11320.py` сохраняет один content-addressed отчёт трёх частей.
Ключ зависит от полного SHA EXE, контекстов, export artifacts, инструментов,
Python и runtime metadata. Повтор проверяет целостность отчёта, состав, границы
источника и неизменность входов. Существует lock с PID владельца.

В `research-checks.json` у трёх прежних checks добавлены source variants для
SHA 1.13.20; старые проверки 1.13.16 / 1.13.18 сохраняют прежний выбор.
Дополнительно `native-wire-batch-11320` подключает отрицательные проверки к
`on_update`. Все четыре проверки используют один общий native результат.
В графе `game-version` и `game-login` закреплены только проверенные текущие
writer / string-writer bindings; отдельно сохранён `utf8-length`.
В release targets записаны область и обязательные checks новой версии.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/run-wire-batch-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_wire_batch_11320.py
```

## Что ещё не доказано

Это перенос **проверяемого поведения в объявленных fixtures**, а не полная
эквивалентность всей цепочки OS / engine / allocator. Growth запрещён,
allocator/free/memcpy/security заменены ограниченными fixtures. Нет allocation
failure, framing, Version/Login preparation, response handling и онлайн-приёма.
Полный game contract остаётся неполным, runtime не активируется.

Счётчик 346 основных функций / 30 helpers из прежнего frontier относился к
более строгому полному `closed_shape` допуску. Этот пакет его не уменьшает
искусственно: закрыты три отдельные семантические проверки новой версии.
Следующий пакет использует уже готовые wire / UTF-8 результаты и исследует
Version/Login preparation / readers или связанную общую input-archive группу.
Повторять данный native разбор при неизменённых входах не требуется.
