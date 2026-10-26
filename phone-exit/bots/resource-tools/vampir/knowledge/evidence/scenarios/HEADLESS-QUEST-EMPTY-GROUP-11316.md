# Пустой service group: настоящий CSV getter и CRT

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [нулевой ветви фильтра](HEADLESS-QUEST-SPARSE-INSERT-11316.md).

`1445f5eb0` — exact 30-byte leaf: проверяет индекс относительно count по row+0x20,
выбирает 32-байтовую ячейку из row+0x28 и уходит в `1445f14d0`. Второй exact
17-byte leaf выбирает SSO pointer по capacity+0x18 и уходит через IAT `14899bbf8`.
Проверен импорт `api-ms-win-crt-convert-l1-1-0.dll!atoi` по текущему EXE.
Оба адреса не имеют unwind root: попытки collect остановились до JVM, не повторялись.
В native replay листья допущены только точными байтами, а не вымышленными roots.

Проверены 14 случаев: пустая строка / 0 / пробелы / 000 / 10000 / -1 / «  +17x»;
для каждого inline SSO и external storage. Настоящий клиентский код исполняется
Unicorn; imported atoi вызывает настоящую локальную Windows ucrtbase.dll через
ограниченный bridge. Python не подменяет преобразование. Полный SHA DLL и CRT
locale записаны, сверены до/после, включены в cache key offline check.

Первые четыре нулевых текста, оба storage, также проходят целый `145a4d2f0`:
AL=0, не пропускать строку; внешний runtime service policy не вызывается.
Три out-of-range column index возвращают 0 до обращения к CRT. Проверены
неизменность row/cells/buffers и guards. Ненулевые результаты не пропускаются
через service policy: её результат не заявляется.

Ячейки и row layout в памяти синтетические. CSV tokenizer / создание пустой
ячейки и привязка колонки не исполнялись. Другие CRT/locale/platforms и overflow
не покрыты. Пустая CSV строка, правильно представленная нулевой строкой, допускается
фильтром; фактическая загрузка всей таблицы, overrides и active step ещё не доказаны.
`order_admitted=false`; игровых команд и reconnect нет.

Контекст `knowledge/native-contexts/quest-empty-group-11316.json` закрепляет leaves,
IAT identity и SHA export `run-ad5876ba33cb`. Инструмент
`replay-quest-empty-group-11316.py`, тест `test_vampir_quest_empty_group_11316.py`.
Offline check `native-quest-empty-group-11316` зарегистрирован с `ucrtbase.dll`.
Артефакт:
`code-clues/quest-empty-group-11316/d39f11d0b021068074c19d78fa94ce99db52e9196bdaecaa04a244b5ac59b644/manifest.json`.

Следующий шаг — рост/rehash sparse maps и полный путь CSV row creation / iteration;
для live admission отдельно учитывать свежую загрузку и overrides.
