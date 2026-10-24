# Native числовой input archive в LoginResult 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [reader с явными archive fixtures](HEADLESS-LOGIN-RESULT-11316.md).
Числовые границы заменены реальными методами archive на том же harness, где
исполняются LoginResult/nested constructors/readers. Строковый UTF-8/FString
reader пока остаётся fixture. Runtime и baseline не переключались.

## Источники и bindings

Первые 20 байт прежнего uint16 reader дали единственный current unwind root
`144aac250`. Его указатели обнаружены в нескольких table offsets; один prefix
не установил точную таблицу. Проверены RIP references constructors и таблицы:

| Роль | VA | Связь |
| --- | --- | --- |
| Default input constructor | `144aac190` | Устанавливает `1496706e8` |
| Base leaf constructor | `144aace10` | Обнуляет поля, задаёт flags; explicit source bytes |
| uint16 | `144aac250` | Slots `+68` / `+70` |
| uint32 | `144aac2a0` | Slots `+58` / `+60` |
| Time raw64 adapter | `144aac470` | Slot `+28`, вызывает virtual `+50` |
| uint64 | `144aac4a0` | Slot `+50` |
| bool | `144aac4f0` | Slot `+88`, нормализует прочитанный byte |
| Raw read | `144aac5c0` | Slot `+90`, bounded memcpy import |
| Last-read bookkeeping | `144aad1a0` | Сохраняет EDX в archive `+10` |

Отдельная concrete table `149670880` имеет те же scalar/raw slots. Её constructor
`144aacb40` также сохранён в новом export, но не исполняется: он вызывает иной
buffer constructor `144aac130`, который ещё не проверен. В этом scope actual
default constructor исполняется, затем buffer fields задаются явно.
Не заявляется проверка concrete buffer constructor или выбора archive в dispatch.

Новый batch `run-6c5bd9da86eb` содержит восемь явных roots; используется семь.
Два прежних result exports переиспользованы. Base init и bookkeeping без unwind
проверяются по отдельным instruction bytes. Все SHA, table bytes и call sites:
[контекст](../../native-contexts/login-result-input-11316.json).
[Квитанция прогона](LOGIN-RESULT-INPUT-11316.json).

## Что заменено в общей проверке

Default archive конструируется перед каждым случаем. Явный fixture задаёт buffer
pointer `+20`, size `+28`, cursor `+30`; endian flag `+38` остаётся нулевым.
Actual vptr сохраняется: числовые операции идут через настоящие table slots.
Установка нарисованной scalar table из прежнего теста здесь не используется.

Наблюдение entry/return проверяет receiver, порядок и адрес каждого поля.
Time adapter действительно вызывает uint64 reader, а тот — raw read. Наблюдение
не пишет готовое число в destination. Принудительный отказ на выбранной операции
возвращает 0 на её entry; остальные случаи исполняют тело scalar полностью.

Raw read вычисляет доступное число байт, копирует min(remaining, requested),
двигает cursor и записывает фактический count в `+10`. При частичном числе
destination может измениться, хотя метод возвращает 0. Поэтому guards разрешают
изменение только поля предпринятой операции; остальные поля / padding сохраняются.
Bool использует отдельный временный byte и пишет 0/1 только после успешного raw read.
Это уже native normalization для входов 0/1/2/255, а не политика fixture.

## Результаты

- 320 полных LoginResult совпали с Python decoder по всем 25 операциям / полям.
  Каждый случай имеет 3 прямых u32, 2 u16, 6 Time adapters, 2 прямых u64 и 5 bool.
- 332 коротких префикса дали 0; cursor не вышел за доступный body. Внутри
  числовых операций частичное потребление выполняет настоящий raw reader.
- 25 принудительных отказов остановили последующие операции caller.
- Trailing `extra` остаётся за пределами consumed=99. Python policy по-прежнему
  строже и отвергает хвост.
- Проверены packet/nested vptrs, поля и canaries, source buffer, actual archive
  writes только в cursor/bookkeeping, сохранение восьми nonvolatile регистров / RSP.

FString fixture синхронизирует позицию с тем же archive cursor. Только на этой
границе длина uint16 / UTF-8 conversion / allocation ещё моделируются. Параметр
успешного возврата 1/128 теперь относится к string fixture; native scalars
возвращают свои реальные значения. Прежний полностью fixture-archive тест сохранён.

## Границы и следующий патч

Little endian only. Byte-swap ветви и неизвестные targets не исполняются.
Начальные cursor/buffer корректны и ограничены 4 096 байт; произвольные испорченные
указатели, low32 overflow remaining-арифметики и malformed archive state не проверены.
memcpy — ограниченный scratch-only fixture для проверенного CRT import.
Native scalar read не доказывает native обработку malformed UTF-8 или FString.
Handler/dispatch/result gates/переход к персонажам, сеть и авторизация не запускались.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_input_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_context.py
```

Новые три теста прошли за 12,396 секунды; прежние три — за 10,872 секунды.
Проверены также отказы при подмене input SHA, export, callee и table bytes.
Это время наборов, не всего обновления.

`native-login-result-input-context` включён в game-login/update. Кэш зависит от
обоих context, verifier/input module, Python decoder, harness/runtime/тестов
и трёх exports. На новом SHA сверять constructor/table/callees, scalar slots,
cursor/remaining/last-count layout и short-input behavior. Новый SHA не переносится
автоматически; game-login остаётся partial. Далее — реальные FString/UTF-8 input,
concrete buffer constructor и handler/dispatch; готовые roots не выгружать повторно.
