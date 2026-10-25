# Объединение пути и статический источник Saved

25 октября 2026. Продолжение [provider пути](UI-CONFIG-PATH-PROVIDER-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline replay и статический анализ; файловая система игры / профили не менялись.

## Источники

Explicit request `814acd8766fb1ce262d877abd3de9ed0879b36d61aedc2a95bc9c85931a0eab8`:
1414324d0 и 141585780. Collect завершён, очередь пуста. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-0b803e5b448e/details.json`, SHA256
`74dad1cd7ee4a9aa33e4b9cc3e9ef0775e697764f12312dcc5516b530241fb24`.
Псевдокод сверен с инструкциями, включая все пять chained unwind fragments
141585780…14158595a; куски не объединяются по предположению декомпилятора.
Join — целое тело 1414324d0…1414325f2.

## Native join

1414324d0 получает FString object, указатель добавляемой строки и явное число
UTF16 units без завершающего NUL. Он не сканирует source до NUL.
Если добавляемое число равно нулю, непустой базовый путь получает завершающий
`/`, когда последний символ не `/` и не `\`. Пустая строка остаётся пустой.
При ненулевой добавляемой части разделитель вставляется, когда база непустая,
её последний символ не `/` / `\`, а первый символ source не `/`.
Начальный `\` source эту последнюю проверку не заменяет.

Существующий завершающий NUL базы переиспользуется либо заменяется `/`, затем
копируются source_count*2 байт и записывается новый NUL. Count включает NUL.
Рост / reserve вынесены в services 141438050 / 141437970. Двойные `/` не
нормализуются: A/ + /Config/ даёт A//Config/. Это работа со строкой, не проверка
канонического пути, существования каталога или безопасности перехода по пути.

`replay-ui-config-path-join.py`: 378 случаев на целых native инструкциях,
8 префиксов / 7 добавляемых строк, два представления пустой базы (count 0 / 1),
три запаса capacity, in-place / relocation allocator fixtures. Проверены
пустой suffix, / и \, кириллица, surrogate pair, counted embedded NUL,
результат / count / capacity, неизменность source и guard bytes, полный RIP /
RSP возврат и RBX / RBP / RSI / RDI. Reserve / grow / byte-copy — fixtures;
непересекающиеся валидные буферы ограничены. Overflow, aliasing, malformed counts,
исключения / ошибки allocator и реальный filesystem не проверены.

Отчёт `code-clues/ui-config-path-join-d00a-02.json`, SHA256
`28ab9d7707412650dba0031dd2d881ad3fd8c6d48895825d1bcbd74b89dbe69f`.

## Provider с native join

`replay-ui-config-path-provider.py --join-request <новое задание>` добавляет
explicit root join того же SHA к прежнему explicit provider request
6fe6bdcb5457008f5a939aeef8bf63004b8b61f74b8367cb5f3f73b023d7fb3e.
В одной памяти provider вызывает настоящее тело join без host-подмены строки.
28 initialization cases: семь base-path fixtures, два TLS index / два epoch;
18 прежних cached cases. Проверены оба copy вызова, отсутствие append fixture,
итоговая counted строка, служебный порядок и полный возврат. Preallocation
provider достаточна в этих случаях; неожиданный allocator вне явных services
отклоняется. Base path, TLS/guard machinery, allocation/copy/atexit — fixtures.
Сохранён прежний режим без join-request для проверки исходной границы отдельно.

Отчёт `code-clues/ui-config-path-provider-native-join-d00a-02.json`, SHA256
`5747f431bca53300fb3f86c277529dcadc21d2b55af36155af8a89d632862913`.
Первый запуск выявил ошибку нового copy fixture: он игнорировал destination offset.
Она исправлена; оба source / destination ABI проверяются до копирования.
Это ошибка исследовательского fixture, не обнаруженный дефект клиента.

## Статический base-path helper

141585780 получает manager через 14157d1d0. При manager+0x119 != 0 возвращает
адрес FString manager+0x48. Иначе вызывает 141585960, передаёт результат и
точный literal Saved по 148a12da0 в 14142b990.
Затем результат 14152d5c0 и literal -saveddirsuffix= по 148a167c0 передаются
в 14158edf0 с output string, low byte 1 и stack argument 0.

В ненулевой ветви результата разбора native перебирает UTF16 suffix. Для каждого
символа вызывает 1487f5ae3 с literal
_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz по 148a16740.
При нулевом результате вызывается 1414349f0 и индекс повторяется. Название
«фильтрация» описывает форму кода; реальные membership / удаления services ещё
не исполнены. При count >1 suffix передаётся с `_` в 14142b760, результат — в
141429e10. Затем отдельно добавляется `/` с count 1. Временные data освобождаются,
FString перемещается в manager+0x48 с очисткой source; flag+0x119 становится 1.

Эта ветвь только статически проверена. Manager, исходная директория, parser /
membership / удаления / строковые операции и активная командная строка неизвестны.
Нельзя выдавать Saved или Config/ за доказанный абсолютный путь и приоритет
конфигурации. Следующие explicit roots: 14157d1d0 / 141585960 / 14158edf0;
отдельно остаются loader 14155bbe0 и constructor 141547b10.

Проверки закреплены за Unicorn 2.1.4 / Capstone 5.0.6 и полным SHA.
Генерация UI и реальное применение настроек этим результатом не разрешаются.
