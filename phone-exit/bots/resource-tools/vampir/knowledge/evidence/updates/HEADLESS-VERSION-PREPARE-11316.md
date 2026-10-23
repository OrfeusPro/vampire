# Version prepare 1.13.16: целая функция с явными входами

Источник — EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
После [проверки тел Version / Login](HEADLESS-ARCHIVE-WIRE-11316.md)
исполнены целые Version prepare `0x1467ce6a0` и constructor `0x1456d7be0`.
Их готовые exports повторно использованы; нового запуска Ghidra нет.

[Контекст](../../native-contexts/version-prepare-11316.json) фиксирует каждый
call site, SHA exports, packet table `0x149926d08`, wrapper table
`0x149dc9320`, send slot `+0x38` → `0x1467cf3e0` и prepare slot `+0x48`.
[Verifier](../../../verify-version-prepare-context.py) сверяет эти связи с
EXE и исполняет только заявленные инструкции / явные fixtures.

## Проверенный участок

64 сценария: четыре варианта исходной памяти × наличие / отсутствие context
store × пустые / Unicode строки × raw enum 0 / `0xffffffff` × send return 0 / 1.
Getter selector задан byte `0x87`, и его передача в context-value fixture
проверяется. Send fixture получает именно текущий packet table и owner.
Нативный код проходит весь путь, включая работу после возврата send.

Строки захваченного пакета по порядку writer:

| Поле объекта | Источник в этом эксперименте |
| --- | --- |
| `+0x10` | Global FString `0x14b592080` |
| `+0x28` | Явный результат second combiner fixture |
| `+0x38` | First-text getter fixture |
| `+0x48` | Provider getter + string-copy fixtures |
| `+0x58` | Копия входного `param_2` FString |
| `+0x68/+0x78/+0x88/+0xa0` | Пустые строки |
| `+0xb0` | Проверенный tag pointer `0x14b1b9e98` → `0x149960020` |

Integers `+0x20/+0x98/+0xc0`: `0`, `207`, raw global `0x14b194560`.
Число 207 не объявляется угаданной версией протокола.
Tag — `32283C4C6485307BCF524765A84409C3`, как в прежней проверке.

Подтверждены сброс owner `+0x160` в 0, сохранение остальной памяти owner и
canaries, отсутствие изменения входного FString, freeing всех временных
allocations, destructor call, два log call и сохранение семи nonvolatile
registers / RSP. Одинаковая проекция и cleanup выполняются при send return 0 / 1;
само принятие пакета сетью этим не проверяется.

## Границы fixtures

OS / context / text getters, оба combiner, FString construction / resize /
copy / free, packet destructor, logging, memcpy и send — bounded fixtures.
Их адреса и caller arguments сверяются, но их реальные тела не исполняются.
Combiner output задаётся явно; проверяются его входные descriptors, включая
native separator `_`, а не делается вывод о полном алгоритме конкатенации.
У getter outputs есть Unicode и пустые варианты; это не прочитанные параметры
реального устройства. Полный caller не доказывает корректность всех portable
подготовителей без переноса этих зависимостей.

Не исполнялись Login prepare, Version / Login result readers, framing,
авторизация, socket и игра. Runtime profile / baseline не переключались.
Живой тест до каталога разрешён пользователем, но этот отчёт его не заменяет.

[Machine receipt](VERSION-PREPARE-11316.json). Прямой прогон занял около
3 секунд, три acceptance tests — 8,115 секунды на текущем ПК. Проверки
отклоняют неверный source SHA, повреждённый export, изменение call site и
подмену send target. Это время участка, не полного обновления.

## Повтор и следующее обновление

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-prepare-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-prepare-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_prepare_context.py
```

`native-version-prepare-context` зарегистрирован как offline / on_update check
контракта game-version с кэшем зависимостей. Ориентир
`native-version-prepare-current` в
[release-update-targets](../../release-update-targets.json) фиксирует способ
поиска кандидата через constructor / tables и review всех callees. Для нового
SHA требуется перенос; автоматического продвижения runtime нет.

Дальше — actual OS/context/string helpers этой функции, отдельная подготовка
Login с языком / SDK metadata и текущие result readers. Сохранённые prepare /
constructor exports и проверенные тела запросов повторно не выгружать.
