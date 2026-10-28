# LoginResult 1.13.20: native string decoder и buffer construction

28 октября 2026. Продолжение [scalar input](HEADLESS-LOGIN-INPUT-11320.md).
Полный SHA EXE:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.

## Что теперь исполняется native

В whole LoginResult integration добавлены FString reader `0x144aad090`,
std::string reader `0x144aac450`, UTF-8 length `0x14144c4a0`, converter
`0x141446700`, core `0x14143bd90`, scalar converter `0x14143ba00`, concrete
input constructor `0x144aacc00` и base buffer constructor `0x144aac1f0`.
Native constructors получают исходный buffer и длину; ручная запись указателя,
длины и cursor из предыдущего scalar пакета в этом варианте исключена.
Проверяется reading mode 1 / endian 0. Остальные режимы не заявлены.

`generate-login-strings-buffer-11320.py` использует готовый content-addressed
Login alignment, сверяет producer и все его inputs, переносит только однозначные
ссылки. Не найденный прямым alignment u8 thunk связан через соответствующий slot
старой/новой input table и совпадающие полные bytes. Никакой nearest-address выбор
не используется. Старое текстовое смещение RIP-indirect call не переносится:
вычисляется source-linked import slot и новое displacement. Полные call sites
и current table bytes затем сверяются перед исполнением.

Context воспроизводится целиком по готовым источникам:
`knowledge/native-contexts/login-strings-buffer-11320.json`.
Двадцать roots (packet/nested + input/string) допущены общим harness только по
фиксированному полному SHA, точному набору roots и scope `login-result-buffer`.
Произвольного увеличения бюджета нет. Лимит инструкций строкового вызова взят
из прежнего проверенного string integration: 1000000; scalar-only сохраняет 30000.

## Сценарии и границы

Прошли **506 native сценариев**:

- 128 полных пакетов с пустыми, ASCII, Unicode/emoji и длинными строками,
  несколькими result codes, bool values и двумя начальными заполнениями памяти.
- 367 byte усечений трёх вариантов пакета; все отклонены.
- Один ответ с пятью лишними bytes: cursor останавливается после пакета.
- Четыре границы строки: 15, 16, 127 и 128 bytes.
- Шесть специальных входов: `ff`, `c0af`, `eda080`, `f4908080`, `610062`, `efbfbe`.

Проверены реальные UTF-16 значения восьми string fields, scalar values, buffer
construction/cursor, ABI, packet padding/vptrs и canaries всех выделений.
Строковые входы больше не декодируются Python fixture.
ABI assertion относится к packet reader после buffer construction; отдельная
полная ABI-проверка самого buffer constructor этим пакетом не заявлена.

Под текущими storage fixtures специальные входы приняты с полным потреблением:
для пяти входов first string — `?`, для `a NUL b` — `a`. Последний результат
включает смоделированную C-string assign boundary; это не самостоятельное
доказательство поведения настоящего FString assign. Нестандартные UTF-8 исходы
закреплены как наблюдения текущего native decoder, не как обещание стандарта.

Выделение/рост/присваивание/освобождение строк, security check, bounded memcpy
и создание пустой trailing string остаются объявленными fixtures. Настоящие
allocator / UI / network / server effects не доказаны. Полный handler не исполнялся.

## Автоматизация

Четыре новых regression tests прошли: 506 сценариев и специальные исходы,
точная regeneration context, отказ при неподдержанном бюджете и подмене call.
Два scalar regression tests также прошли после изменения общего verifier.
Source-specific `native-login-strings-buffer-11320` подключён к `on_update` и
кэшу вместе с generator/source/context/export/runtime dependencies; восемь scoped
bindings добавлены в `game-login`. Прежние scalar и полные contract checks сохранены.
Изменение общего harness меняет ключ зависимых проверок: штатный проход проверяет
новый рецепт автоматически, а неизменённые материалы Ghidra переиспользуются.
Независимый read-only review субагента не нашёл блокеров строкового пакета,
но выявил слишком короткий timeout вызывающей tag-проверки: 120 секунд против
600 секунд у её общего cold entry dependency. Первый проход сохранил timeout;
после проверки завершения PID 28460 и всех его дочерних процессов удалён только
его orphan entry-cache lock. Source variant tag получил те же 600 секунд,
без расширения сценариев или instruction budgets. Добавлен регрессионный тест
согласованности таймаутов. Общий entry-пакет завершился штатно и дальше reused.

Отчёт в библиотеке `F:/PhoneExit Resources/Vampir`:
`knowledge/login-strings-buffer-11320/82d68bacc8f66b29516e800ae64486376463a8f59ea2d2c3e40c0e8815b58aa1/manifest.json`.
Collection reuse:
`knowledge/collections/d1215c21e75458874ad8ff00ad55712a94e7380fc7f71790e195a70989517cce/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/generate-login-strings-buffer-11320.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-login-input-11320.py --strings-buffer
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_strings_buffer_11320.py
```

Остались остальные handler paths, включая успешный вход и новые field actions,
registration и post-state boundary. Строгие **346 основных функций и 30 helpers**
не объявлены целиком закрытыми этим bounded пакетом. Игра, авторизация и сеть
не запускались; новый Ghidra export не потребовался.
