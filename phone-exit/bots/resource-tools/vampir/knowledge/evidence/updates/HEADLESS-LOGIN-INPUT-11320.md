# LoginResult 1.13.20: native входной архив и скалярные readers

28 октября 2026. Продолжение
[вложенных readers](HEADLESS-LOGIN-NESTED-EARLY-11320.md).
Источник EXE — полный SHA
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.

## Проверенное поведение

`verify-login-input-11320.py` исполняет текущий полный LoginResult constructor /
reader, nested time / period и семь функций native input archive:

| Роль | Адрес |
| --- | --- |
| Input constructor | `0x144aac250` |
| u16 | `0x144aac310` |
| u32 / raw32 | `0x144aac360` |
| time primitive wrapper | `0x144aac530` |
| u64 | `0x144aac560` |
| bool | `0x144aac5b0` |
| raw bytes | `0x144aac680` |

Ссылки происходят из готового Login alignment, а исполняемый код — из ранее
проверенных полных current exports. Таблица архива `0x1496731e8` и slots
`0x28/0x50/0x58/0x60/0x70/0x88/0x90` сверены с точными native targets.
Constructor устанавливает эту таблицу. Base constructor leaf и count setter
закреплены точными bytes; leaf заканчивается на `RET`, padding не включён.

Вместо прежних scalar fixtures числа теперь читаются из реального входного
буфера через native readers. В составе whole packet проверены значения u16,
u32/raw32, u64/time, bool и новые trailing raw32 поля `+0x150/+0x154`.
Для raw bool 0, 1, 2 и 255 проверен результат нормализации 0/1.

Прошли **496 сценариев**:

- 128 полных ответов: четыре строковых содержимых × четыре result кода ×
  четыре raw bool × два начальных заполнения памяти.
- 367 усечённых ответов: каждое byte усечение для пустой, ASCII и emoji строки.
- Один полный ответ с лишними пятью bytes: cursor останавливается после пакета.

Проверены точные scalar values, потребление буфера и отказ при усечении,
неизменность packet padding/vptrs, archive за пределами cursor/bookkeeping,
исходного buffer, canaries, fixture allocations и nonvolatile registers / RSP.
Чтение не изменяет source buffer. Строковые содержимые разнообразят offsets
скалярных полей, но сами не являются доказательством native UTF-8 decoder.

## Fixtures и автоматизация

String reader / UTF-8 conversion / allocation, пустая trailing string в packet
constructor и bounded memcpy остаются явными fixtures. Buffer pointer/length
передаются после native input constructor вручную; реальный buffer constructor
этим пакетом не подтверждён. Handler, авторизация, сеть и runtime не запускались.

Source-specific `native-login-input-11320` подключён к `on_update` и кэшу:
код, review context, полные export SHA и Capstone/Unicorn входят в dependencies.
В `game-login` внесены семь scoped input bindings с reviewed recipes.
Полные result/handler checks не заменены этим ограниченным результатом.
Два regression tests прошли: интеграционные сценарии и отклонение подмены
таблицы либо base leaf bytes. `collect` вернул reuse без нового Ghidra.

Review context: `knowledge/native-contexts/login-input-11320.json`.
В библиотеке `F:/PhoneExit Resources/Vampir`:

- Native report: `knowledge/login-input-11320/a7d134bc74021b4435e3ef866d36892810e604513f5e349e0a324351b6204cef/manifest.json`.
- Collection reuse: `knowledge/collections/bf7311c0e8cb818cbe90c76c84a064620b4f8dad2af8d59bcf629e5e6ea3becf/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-login-input-11320.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_input_11320.py
```

Остались actual string decoder, native buffer construction, остальные handler
paths, registration и post-state boundary. Строгие **346 основных функций и 30
helpers** этим bounded пакетом не объявляются полностью закрытыми.
