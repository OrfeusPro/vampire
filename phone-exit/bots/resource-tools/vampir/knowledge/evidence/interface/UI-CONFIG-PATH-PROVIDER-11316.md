# Provider строки Config/: кэш и ленивая инициализация

25 октября 2026. Продолжение [path-copy wrapper](UI-CONFIG-LOAD-WRAPPERS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Ни конфигурация, ни игра, ни профили не запускались и не менялись.

## Источники

Explicit request `6fe6bdcb5457008f5a939aeef8bf63004b8b61f74b8367cb5f3f73b023d7fb3e`,
root 14144b5b0; collect завершён с пустой очередью.
`ghidra/request-exports/<полный SHA EXE>/run-52b76b2d8385/details.json`, SHA256
`2e6cd7551c9eeb8221d7b44af7c799eab994a1d0d28b8c49dddb47a5b52b1044`.
Псевдокод сверен с инструкциями полного unwind тела 14144b5b0…14144b6ac.

## Цепочка

Global object строки: data 14b2bdcb8, count 14b2bdcc0; guard 14b2bdcc8.
Native читает TLS index 14b6a4c20, GS:[0x58], соответствующий TLS block и
signed epoch по block+0x101184. Если global guard больше TLS epoch, вызывается
header 1487e920c. Только guard == -1 после header открывает инициализацию.
Это статическая форма guard; синхронизация настоящих потоков не проверялась.

141585780 возвращает исходный строковый объект. Его data и count читаются,
глобальный data обнуляется, count переносится. Запрашивается count+8 единиц
при ненулевом count, иначе 9; native проверяет signed overflow сравнением
результата с count. Overflow target 141431a10 и int3 существуют, но не исполнялись.
Allocator 141436ed0 получает global object, рассчитанный count и R8=0.
При ненулевом исходном count копируется count*2 байт через 1487f5ab9.

Затем 1414324d0 получает global object, точный UTF16 literal `Config/` по
1489f3fb0 и R8=7. Семантика самого append helper ещё не проверена; успешное
получение пути на диске из этих аргументов не следует. В atexit 1487e914c
передаётся target 14885e690; затем вызывается footer 1487e91a0 с guard.
При возврате count != 0 выбирает global data; count == 0 — пустой literal
1489e1b34. Сам provider не перечитывает файлы на каждом вызове.

Полный базовый путь зависит от 141585780. Его ещё нельзя называть каталогом
установки, Saved или активной конфигурацией; precedence и доступность файлов
остаются открытыми. Точный literal Config/ не разрешает угадывать этот префикс.

## Проверка

`replay-ui-config-path-provider.py`, Unicorn 2.1.4 / Capstone 5.0.6, проверяет
SHA EXE, unwind root, литералы и исполняет целое native тело. Выход за тело и
явные services отклоняется. Native выполняет TLS чтение, signed сравнения,
переходы, расчёт allocator аргументов, копирующий / append вызовы и возврат.
GS/TLS memory, header/footer, base-path provider, allocator, byte-copy, append
и atexit — fixtures. Они не доказывают реальный allocator или строковую семантику.

18 cached cases: три count 0 / 1 / 8, guard epoch -2 / 0 / 2, TLS epoch 0 / 2.
Проверяются пропуск header и header без инициализации, выбор пустого / data
указателя, неизменность global descriptor. 12 initial cases: два TLS index,
два epoch и три base-path fixtures — пустой, ASCII и кириллица. Проверены
полный порядок вызовов, counted copy до append, allocator count / ABI, footer,
atexit target, полный RIP / RSP возврат и сохранение RBX / RDI.
Append fixture явно формирует результат; это не native доказательство строки.
Count 1 в cached ветви — synthetic descriptor, содержимое не читается.

Отчёт `code-clues/ui-config-path-provider-d00a-01.json`, SHA256
`483a7a07274851b02484571f2d4adabcf790bc5624d60f209ad99bfb84cf1416`.
Настоящие multi-thread initialization / ожидание, overflow / исключения,
cleanup body и смена пути после инициализации не проверены.
Source-bound check включён в план обновлений без автоматического переноса роли.

Далее проверить 141585780 и append 1414324d0; отдельно loader 14155bbe0 /
constructor 141547b10 и приоритеты файлов. Генерация UI остаётся закрытой.
