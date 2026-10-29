# LoginResult: автоматический nested layout и native string/buffer input

30 октября 2026. Перенос 1.13.20 → 1.13.22 по точным SHA:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c` →
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинные доказательства и измерения](AUTO-LOGIN-INPUT-11322.json).

## Две области проверки

| Семейство | Native roots | Сценарии | Граница |
| --- | --- | --- | --- |
| `login-nested` | 6 | 232 | Whole constructor / reader, time / period, fixture primitives и строки |
| `login-strings-buffer` | 20 | 506 | Whole ответ с native scalar / string / UTF-8 input и buffer construction |

Nested suite проверяет два заполнения памяти × два bool значения × два truthy
результата primitives × 29 вариантов остановки: успех либо отказ на каждом из
28 полей. Проверены layout 352 байта, точная последовательность и destinations,
немедленная остановка при отказе, constructor defaults, padding / vptrs и canaries.

Вторая suite исполняет тот же whole packet с 14 настоящими input / UTF-8 roots:
128 полных ответов, 367 побайтовых усечений, один ответ с хвостом, четыре строковые
границы и шесть фиксированных malformed / embedded-NUL / noncharacter наблюдений.
Матрица полных ответов: четыре текста × четыре result-кода × четыре raw bool ×
два заполнения памяти. Нормализация bool, все 20 scalar projections, восемь
строк, cursor и source buffer проверяются native. GPR, XMM6–15 и RSP сохраняются
после constructor / reader; записи вне объявленных областей запрещены.

У отчётов сверяется весь состав матриц и outcomes, включая типы bool / int,
порядок и уникальность сочетаний. Сумма 738 — пересекающиеся bounded сценарии,
не число уникальных функций и не подтверждение всего входа.

## Перенос и границы

Общий input closure берётся из независимо подтверждённого VersionResult того же
SHA. Это источник checked mappings; его прежний scalar report не расширяется
на строки. Новая suite исполняет строки отдельно. Полный input context также
сверяется с самостоятельным target nested proof и его semantic report.

Rule проверяет все инструкции / branches / calls, concrete unwind boundaries,
точные direct и virtual call roles, RIP defaults / empty UTF-16 data, ID 4,
таблицы и alias partitions. Оба constructor uint32 defaults сохраняют значение 1.
Сопоставлены 1119 instruction / call / data links и шесть таблиц. Неисполненные
virtual slots сохраняют provenance без semantic admission.

Nested содержит две returning leaves и один точный virtual tail; полный input —
четыре returning leaves и два точных tails. Storage / growth / assignment / free,
stack security, empty trailing-string construction и bounded memcpy остаются
явными fixtures. C++ free имеет отдельный exact пятибайтовый E9 на free fixture.
Настоящие storage / CRT / OS effects, endian-swap и exception branches не заявлены.

Новый scoped harness допускает только эти два семейства и точные 6 / 20 roots
после проверки source-bound transfer proof. Самостоятельное указание family,
layout или большего budget не разрешает исполнение. Прежний harness с адресами
старых версий и готовые proof engines не менялись. Окончания строк инструментов
и исторических contexts закреплены: byte SHA всех 27 зависимостей сохраняются
после Git checkout.

## Автообновление и повтор

Обе роли зарегистрированы в [native-check-adapters.json](../../native-check-adapters.json)
и штатном `update --auto`. Immutable lifecycle публикует отдельные indexes
`generated-login-input/login-nested/index.json` и
`generated-login-input/login-strings-buffer/index.json` в библиотеке ресурсов.
Следующий патч выбирает последнюю доказанную базу каждой роли; текущая сессия
и runtime profile не переключаются.

Кэш фиксирует реальные baseline / target contexts, proofs, reports и exports,
инструменты и pinned runtime. Seed memo учитывает полную lineage и target report,
не делит изменённые или повреждённые доказательства с готовыми. SourceStore
переиспользует PE внутри frozen прохода и сверяет источники перед завершением.

Новые suites прошли по одному разу. Два повтора не запустили JVM или native;
последний переиспользовал шесть этапов. Общий проход 19 drivers использовал
57 этапов кэша без нового исполнения. Прежние готовые suites не повторялись.
Первый selected pass — 342.289515 с, последний — 56.269373 с;
общий cached pass — 171.831087 с. Зарегистрированный tooling набор — 326 тестов passed.
Время selected drivers не включает сверку индекса, сбор exports и полный аудит установки.
Подготовка исследования в этом запуске заняла около 25.5 мин, включая tooling.
Индекс отдельно сверяет около 37 тысяч исторических pseudocode files; стоимость
этого integrity прохода зафиксирована как следующий инфраструктурный пробел скорости.
Сбор явных roots и reused / missing перечислены в машинной квитанции выше.
Три субагента завершили pure rules, case contracts и независимую admission ревизию;
координатор выполнил интеграцию, serialized collect, native acceptance и публикацию.

## Осталось

Следующий пакет — LoginResult handlers, registration и response composition;
далее clock / heartbeat и world contracts. Настоящий SDK backend и provider
effects сохраняют отдельные пробелы. Авторизация, игровые команды, переключение
профиля и онлайн-допуск этим offline пакетом не выполнялись.
