# Manager, выбор директории и обёртка parser параметра

25 октября 2026. Продолжение [цепочки Saved / Config](UI-CONFIG-PATH-JOIN-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline native replay / статический анализ; клиент, профили и игровые команды
не запускались. Выбор реальных путей и активных настроек этим не подтверждается.

## Источники

Explicit request `51b9287b1813959c7b33b77647768658d8c586ae2189a26032d4ee0538f70eaa`:
14157d1d0, 141585960 и 14158edf0. Collect завершён, очередь пуста.
`ghidra/request-exports/<полный SHA EXE>/run-8e0efd67f630/details.json`, SHA256
`2dfb7dac7ed6d8d7fb06f2ee77ec102b4f0a2408e820c9c1b3dfe33c475ec0e9`.
Все chained fragments сверены с инструкциями. Полные диапазоны roots:
14157d1d0…14157d252, 141585960…141585a71, 14158edf0…14158ef64.
Последний root содержит три chained fragments; второй — три.

## Manager: исполненный wrapper

14157d1d0 читает тот же TLS index 14b6a4c20 / GS:[0x58] и epoch block+0x101184.
Guard здесь другой: 14b2f1198; pointer cache 14b2f1190. Если global epoch больше
TLS epoch, вызывается header 1487e920c. Только guard == -1 после header вызывает
constructor 14156c020 со статическим storage 14b2f1068. Адрес storage записывается
в pointer cache; atexit 1487e914c получает 148863f20, footer — адрес guard.
Возвращается pointer cache. Результат constructor не выбирает адрес cache.

14 сценариев: два TLS index, два TLS epoch, два global epoch; header без
инициализации и header с инициализацией, когда native gate её допускает.
Проверены вызовы, адреса storage / cleanup / guard, cache и полный возврат.
Конструктор, TLS память, guard header/footer и atexit — fixtures; структура
полного manager и настоящая синхронизация потоков ещё не проверены.

## Parser wrapper: исполненное тело

14158edf0 получает входную UTF16 строку, ключ, output FString, low byte флага
и пятый pointer argument. Null и строка нулевой длины не вызывают core parser,
возвращают AL=0 и не меняют output. Native сканирует UTF16 до NUL.

Для непустого входа нужен buffer_count = input_units+1. До 4096 включительно
используется stack buffer; больше — allocator 141586cf0 с inline-storage object.
Буфер начинается с NUL. Core 14158f1a0 получает input / key / buffer / count,
low byte флага и исходный пятый pointer. Смысл параметров самого core неизвестен.

Ненулевой AL core вызывает 141426b30 для temporary FString и 141427760 с output /
temporary. Ненулевой data temporary затем освобождается. Отдельно освобождается
heap parser buffer, если был выделен. Возврат wrapper — AL=1 при ненулевом core AL,
иначе AL=0; верхние биты RAX не являются результатом bool-контракта.
Поэтому synthetic core AL=2 также даёт AL=1. Настоящий parser не исполнялся.

192 сценария: null / пустой вход, ASCII, surrogate pair, длины 4095 / 4096 units;
flag 0 / 255, core result 0 / 2, два варианта fixture переноса temporary
(очищает data / сохраняет data), null / ненулевой пятый pointer и два результата
core — пустая строка / кириллица с surrogate pair. Проверены ABI, обе ветви
буфера, NUL перед core, порядок копирования / переноса / очистки, сохранность
output при отказе и guard bytes, полный RIP / RSP возврат и RBX.

Stack probe, cookie, allocator/free, core parser, string-copy и string-transfer —
fixtures. Cookie сохраняет фактический native RAX, не подставляет результат.
Stack probe сохраняет ожидаемый RAX=0x2070. Варианты переноса проверяют реакции
wrapper, но не доказывают реальный контракт 141427760. Успешное чтение конкретного
параметра и правила кавычек / регистра / совпадений этим не установлены.

## Выбор основы директории: только статическая проверка

141585960 сначала вызывает 141578190. Если dword result+8 >1, передаёт объект
в 1414266a0 и возвращает output. Иначе вызывает 141589b30:

- При AL=0 вызывает 141455330 и передаёт результат в string-copy 141426b30.
- При AL!=0 вызывает 1415d9250; сканирует полученный pointer и глобальный UTF16
  текст 14b1d6e70 до NUL, резервирует временную строку через 1414366c0, передаёт
  первый текст в 141429e10, затем глобальный текст в уже изученный join 1414324d0.
  Helper 14142b8a0 получает output, temporary и literal `/`; temporary очищается.

Имена каталогов, значение runtime global и условия 141589b30 пока неизвестны.
Не присваиваем ветвям имена AppData / установка по форме кода. Тело выбора
директории не исполнялось; полный список direct calls сохраняется в отчёте.

## Повтор и следующий участок

`replay-ui-config-source-helpers.py`, Unicorn 2.1.4 / Capstone 5.0.6.
Проверяются полный SHA, unwind roots, ключевые edges, границы native исполнения.
Отчёт `code-clues/ui-config-source-helpers-d00a-01.json`, SHA256
`654af98d9957f53d4abfe3c3c8f001008a71b27137b918c7d58497fbb3ab44b0`.
Malformed counts, allocation errors, реальный cleanup / concurrency не проверены.
Следующие explicit roots: core parser 14158f1a0, источники директории 141578190 /
141589b30 / 1415d9250 / 141455330 и manager constructor 14156c020.
Отдельно остаются context constructor 141547b10 / loader 14155bbe0 и precedence.
Активные настройки и генерация внешнего вида не разрешаются этим отчётом.
