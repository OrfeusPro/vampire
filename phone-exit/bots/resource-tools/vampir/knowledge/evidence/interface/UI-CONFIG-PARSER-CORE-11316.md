# Core parser параметра и общий прогон с FString wrapper

25 октября 2026. Продолжение [обёртки parser](UI-CONFIG-SOURCE-HELPERS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline native replay на synthetic строках; настоящая командная строка,
конфигурационные файлы и профили не читались и не менялись.

## Источники

Первое explicit задание `9509c34fefd3da748780ee1382e7ac73d5f2fafbd4344c8f446b0e5f15a55a5d`
выгрузило core 14158f1a0. Второе
`a7a9322e9dc794f08d54e4390f01405b51040ee8bec9b8d9b7474f9d4dab3e70`
явно добавило compare 14145f4a0; готовый core использован повторно.
Обе коллекции завершены с пустой очередью. Ghidra details:

- `ghidra/request-exports/<полный SHA EXE>/run-eaaf586161a6/details.json`, SHA256
  `dac2a578cd9f0f5f3948b35607ac32c704d7098f00b3e366ce3fdb6c4bbab55d`.
- `ghidra/request-exports/<полный SHA EXE>/run-cf2acdf8d5bb/details.json`, SHA256
  `0ed9b6cfdf89fb0829086e01ee49466f4d944ccc305e1351539da851d9f4b873`.

Псевдокод сверен с инструкциями. Core 14158f1a0…14158f447 состоит из трёх
chained fragments; compare 14145f4a0…14145f545 — целое отдельное тело.
Wrapper 14158edf0 используется из прежнего explicit задания
51b9287b1813959c7b33b77647768658d8c586ae2189a26032d4ee0538f70eaa.

## Найденные правила

Core принимает input, key, output buffer, capacity, low-byte flag и optional
pointer для конца значения. Capacity 0 возвращает AL=0 без записи output /
end pointer. При capacity >0 key сканируется до NUL до проверки null key;
поэтому null key не входит в безопасный исследованный контракт.
При отсутствии совпадения output[0]=NUL, optional end pointer=0, AL=0.

Поиск пропускает ключ внутри двойных кавычек и после ASCII буквы / цифры.
Подчёркивание и прочие символы не считаются ASCII буквой / цифрой; например,
_ перед -saveddirsuffix= допускает совпадение, x перед ним — нет.
Выбирается первое подходящее совпадение. Первый символ сравнивается с ASCII
преобразованием регистра, остальные — через настоящий compare 14145f4a0.
Его file-backed таблица 1489f4400 проверена для всех 128 ASCII значений;
A–Z переходят в a–z, остальные байты сохраняются. Не-ASCII units сравниваются
как исходные числа; общей Unicode case-folding семантики не заявляем.

Если значение начинается непосредственно с двойной кавычки, она пропускается,
конец ищется по закрывающей кавычке, либо берётся NUL при незакрытой строке.
Кавычка после пробелов относится к другой ветви: полноценного shell parser
или escape обработки по этому коду не объявляем.
Без начальной кавычки пропускаются пробел / CR / LF / TAB. Flag 0 завершает
значение по этому же набору; ненулевой flag добавляет запятую и правую скобку.
Точные UTF16 delimiter literals проверены по 1489e4474 / 148a16718 / 148a16728.

Результат ограничен capacity-1 UTF16 units, затем дописывается NUL.
Усечение может разделить surrogate pair; oracle сравнивает сырые units.
Optional end pointer указывает на конец исходного значения до усечения;
для закрытой quoted строки проходит за закрывающую кавычку. Даже пустое найденное
значение возвращает AL=1. Встроенный NUL завершает input до дальнейшего поиска.

## Проверка

`replay-ui-config-parser-core.py`: целый native core и compare, независимый
Python oracle на UTF16 units. 600 случаев: 30 synthetic input fixtures,
два flag, capacity 0 / 1 / 2 / 7 / 64, optional end pointer включён / выключен.
Включены отсутствие ключа, пустое значение, ASCII case, word boundary, кавычки,
незакрытая кавычка, повторы ключа, whitespace / comma / parenthesis, Unicode,
surrogate pair и embedded NUL. Проверены AL, output / неизменённый хвост / guards,
end pointer, неизменность input, RIP / RSP и все восемь nonvolatile GPR.
Quote search 1487f5ad7 и byte-copy 1487f5ab9 — explicit fixtures;
никакого fixture, возвращающего найденность или готовое значение parser, нет.

Ещё 128 сценариев исполняют wrapper → core → compare в одной памяти:
те же 30 строк плюс два длинных входа, два flag, два варианта fixture передачи
временного FString. Native wrapper сам сканирует input, выбирает stack / heap
buffer, вызывает настоящий core, ветвится по результату и выполняет cleanup.
На null / пустом входе core не вызывается. Проверены успешный и отказной output,
heap cleanup, optional end pointer и отсутствие подстановки результата parser.
String-copy / move, allocator/free, stack-probe и cookie остаются fixtures;
move с очисткой / без неё проверяет реакцию wrapper, не реализацию 141427760.

Отчёт `code-clues/ui-config-parser-core-d00a-02.json`, SHA256
`583851d258971e7626d312df993899036946f5dc646334abd569d6445eebc522`.
Unicorn 2.1.4 / Capstone 5.0.6 закреплены; полный SHA, unwind и ASCII table
проверяются до исполнения. При выходе за тела / явные services replay отклоняется.

Фиксированный непустой ASCII key; valid non-overlapping UTF16 buffers.
Null / пустой key, отрицательные capacity, aliasing и allocator errors не проверены.
Нельзя переносить эти правила на все ключи / Unicode / malformed input без проверки.
Actual command line, Saved directory, precedence и UI применение ещё неизвестны.
Далее — оставшиеся string / CRT primitives и интеграция с base-path helper;
источники директорий и context loader исследуются отдельно.
