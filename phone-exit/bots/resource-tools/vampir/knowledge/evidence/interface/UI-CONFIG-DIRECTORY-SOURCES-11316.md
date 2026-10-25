# Условия UserDir и системная директория конфигурации

25 октября 2026. Продолжение [источников базового пути](UI-CONFIG-SOURCE-HELPERS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline native replay / static; Windows API, клиент и реальные конфиги не запускались.

## Источники

Explicit request `4f1aa73e805e475f5dc50f615c5836052af75de47f41caa16a352c0ad4ef4bee`:
141578190, 141589b30, 1415d9250, 141455330. Collect завершён, очередь пуста.
`ghidra/request-exports/<полный SHA EXE>/run-b459eef1dc6f/details.json`, SHA256
`a733618d1bd4f39219d5a5529cb79e62e8a1e1b75f758f14e2708dee3d607610`.
Псевдокод / инструкции согласованы. Целые unwind тела gate 141589b30…141589bc7
и системного wrapper 1415d9250…1415d93be исполняются; остальные два root —
только статическая проверка, все chained fragments / direct calls сохранены.

## Gate 141589b30

Cache byte 14b2f0f4a, guard 14b2f0f4c, обычная TLS epoch цепочка.
При guard инициализации проверяются последовательно:

1. Ненулевой AL helper 141533f40.
2. Результат 14152d5c0 и точный literal SaveToUserDir по 148a16818,
   переданные в 141584470; проверяется AL.
3. Ненулевой AL 141403ab0.
4. Count по result+8 от 141578190 больше 1.

Первое выполненное условие записывает cache=1, ни одно — cache=0.
Следующие условия пропускаются. После footer возвращается cache byte.
Готовая ветвь cache не нормализует произвольный synthetic байт: 2 / 255
возвращаются как есть; это не доказательство допустимости таких живых значений.

64 initialization cases: два TLS index, результаты трёх predicates 0 / 2,
четыре override count 0 / 1 / 2 / 8. Проверены short circuit, точный literal /
ABI, нормализация и запись cache, полный возврат. Ещё 16 cached cases:
четыре byte значения, header без инициализации / пропуск header, два TLS index.
Все predicates и guard machinery — fixtures; реальное действие SaveToUserDir
и значения условий ещё не доказаны. Название mode в отчёте — имя fixture,
не установленная роль 141533f40.

## System-folder wrapper 1415d9250

Cache FString по 14b33f0e0, count +8, capacity +0xc; guard 14b33f0f0.
Первичная guard ветвь регистрирует cleanup target 148864fe0 через atexit.
При count 0 или 1 вызывается helper 1415d7dd0; его AL выбирает GUID:

| Условие | Адрес | Исходные 16 bytes |
| --- | --- | --- |
| AL != 0 | 14a897330 | a4a120a58017f64fbd18167343c5af16 |
| AL == 0 | 14a897370 | 8527b3f1ba6fcf4f9d557b8e7f157091 |

PE import table и точные bytes thunk 1487dea9d подтверждают:
IAT 14899b2c0 — SHGetKnownFolderPath; IAT 14899c440 — ole32.dll CoTaskMemFree.
Имя / смысл конкретных известных папок по GUID здесь не присваивались.
API получает GUID, flags=0, token=0 и output pointer. Отрицательный signed
HRESULT пропускает обновление и возвращает прежний cache либо пустой literal.

При неотрицательном результате вызывается string-copy 141426b30. Затем
141435320 получает temporary, новый output object, literals backslash / slash
и dword stack argument 1. Это именно dword, старшие четыре байта не определяются
этой записью. 14142b8a0 получает следующий output, промежуточный object и slash.
Нормализация / добавление разделителя — ещё fixtures, не native доказательство.

Старый data cache освобождается при ненулевом pointer. Новый FString переносится
в global cache с обнулением source. Освобождаются две временные строки, затем
исходный OS pointer передаётся CoTaskMemFree. Count !=0 выбирает cache data,
count 0 — literal 1489e1b34. Count >=2 пропускает запрос API.

64 случая: четыре count, HRESULT 0 / -1, два результата выбора GUID, наличие /
отсутствие старого data, guard initialization / готовая ветвь. Проверены оба
GUID, ABI / signed HRESULT, запросы при count 0 / 1, сохранение cache при ошибке,
перенос / cleanup, порядок services, RIP / RSP и восемь nonvolatile GPR.
Fixtures OS/string/free возвращают synthetic C:/Demo/; эта строка не является
наблюдением папки ОС. Count / data сочетания здесь могут быть некорректными
FString: это branch probes, не доказательство полного ownership контракта.

## Override и fallback: статический контекст

141578190 получает manager. Поле +0x38 — FString override, byte +0x118 — cache
flag. При нулевом flag вызывает parser wrapper 14158edf0 с точным UserDir=
по 148a17040, flag low byte 1 и пятым argument 0; затем выставляет cache flag.
При count >1 вызывает 1415818e0. Его AL выбирает ветвь с 141455330 / join /
14142b8a0 либо ветвь 141583fe0 / 14142b990. Значение predicate и строковых
операций не выводится из названия. Whole override ещё не исполнялся.

Fallback 141455330 получает object от 14144b6b0 и поле +0x48. Учитывает pointer
14b2e60f0 / byte+9 и flags 14b2bdcb0 / 14b2bdcb1, при изменениях вызывает
1414366d0. При пустой строке использует дополнительные источники / условия,
сопоставляет runtime UTF16 global 14b1d6e70 с literal None и строит строки,
в том числе с literal ../../. Direct calls и инструкции сохранены; полный
fallback и значения источников не проверены. Нельзя называть это безусловным
путём установки или автоматически переносить в настройки UI.

## Повтор и остаток

`replay-ui-config-directory-sources.py`, Unicorn 2.1.4 / Capstone 5.0.6;
полные SHA, unwind, literals, imports / thunk проверяются до исполнения.
Отчёт `code-clues/ui-config-directory-sources-d00a-03.json`, SHA256
`4f2fe3a8d73356d83254d3dcea7b4f512ea5ee0149b17c1a8a6de05bbf81d216`.
Все внешние predicates / OS / string / storage / guard calls — fixtures.
Allocation errors, настоящие потоки, реальная папка / API и fallback не проверены.
Далее — predicates, whole override / fallback, строковые операции и интеграция
с base-path; loader / precedence / активное UI применение остаются открытыми.
