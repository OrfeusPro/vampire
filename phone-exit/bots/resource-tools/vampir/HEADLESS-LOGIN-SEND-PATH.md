# Login: request handoff → кадр и очередь

19 октября 2026. Продолжение [Login writer](HEADLESS-LOGIN-PACKET-WRITER.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Сначала прочитан общий экспорт Ghidra `Request_Handoff.c` и `Game_SendWrapper.c`:
`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`. Затем проверены инструкции
и исполнен единый native путь через Capstone 5.0.6 / Unicorn 2.1.4.

[replay-login-send-path.py](replay-login-send-path.py) →
`F:/PhoneExit Resources/Vampir/code-clues/login-send-path-replay.json`.
SHA256 отчёта: `6f3c9d612821c394380be84b023c22ca552d10c6966ea21b018ad209a9a3c88e`.
Отчёт сохраняет source/tool/upstream SHA, fragments, bytes/file offsets,
таблицы handle/packet, getter/ID leaves, строковые и frame helpers, 34 сценария.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-send-path.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_send_path.py
```

## Единый исполненный путь

**0x144aa8020 → 0x144aaa9d0 → virtual+0x38 → 0x1467aaa10 →
0x144aab2f0 → 0x144aaccf0 → 0x1456e57c0 → queue 0x1445eac20**.

Singleton getter реально читает global **0x14b520d90**. В эмуляции global
указывает на синтетический wrapper с настоящей таблицей **0x149d84e50**,
её slot+0x38 равен **0x1467aaa10**. Это не найденный живой singleton.
Ранее установка derived table конструктором привязана в
[key change evidence](HEADLESS-KEY-CHANGE.md). В новом replay конструктор
wrapper не выполняется, таблица и getter bytes проверяются отдельно.

Исполняются native request lookup/ветвления/выбор timeout/getter/virtual call,
metadata wrapper, lower thunk, send-B gates, настоящий Login ID getter,
Login writer, UTF-8 conversion, archive primitives, CRC/XOR/header и
синхронное добавление кадра в очередь. Это продолжение
[Version send path](HEADLESS-VERSION-SEND-PATH.md) с PktLogin/ID 3.

## Дубликаты и timeout

Handoff сравнивает manager+0x40 с manager+0x6c; если записи есть,
выбирает inline buckets manager+0x70 либо external pointer manager+0x78.
Bucket вычисляется из `(bucket_count-1) & kind`, значение 0xffffffff — конец.
Проверяются uint16 kind в nodes по 32 bytes, переход к следующему index+0x18.
Совпадение завершает handoff до insert/notify/getter/send.

Проверены duplicate kind 4 в inline bucket и в третьем узле external collision
chain `[8,12,4]`; collision chain `[8,12]` пропускает kind 4 к отправке.
Эти nodes/buckets/counts — явные fixtures; они не созданы настоящим контейнером.
Raw kind 4 соответствует аргументу исходного Login callsite **0x1467a9af7**
из [подготовки Login](HEADLESS-LOGIN-PACKET-FIELDS.md). Он отличается от ID 3
внутри кадра. Семантика вида запроса не выводится из числового совпадения
с ID другого пакета.

Для float timeout +0.0 и -0.0 native код берёт manager+0x30 (fixture 12.5).
Явные 3.25 и -2.0 проходят без изменения. Это выбор raw float, не доказательство
единиц времени, правил допустимости или реального срабатывания таймера.
NaN/inf, системные часы, expiry и reconnect здесь не проверены.

## Контейнер и уведомление: границы

Вызов insert helper **0x144aa7640** на **0x144aa80d9** захватывает:
manager+0x38, указатели на kind/timeout и переданный opaque argument
(fixture 0x12345678). Его backend не исполняется и pending map не изменяется.

Вызов **0x144aa7870** на **0x144aa80f3** также capture. Он получает manager+8
и descriptor с raw address **0x141423088**, выставленным native handoff.
Имя/тип descriptor и действие callback не доказаны; поле `callback` в отчёте
обозначает только снятые raw bits. Source Login передаёт R9 из global;
новый прогон не подменяет его смысл выдуманным именем.

Insert и notify происходят **до** getter/send. Даже в трёх transport refusal
scenarios эти captures уже вызваны. Rollback, фактическое состояние pending
после отказа, callback lifecycle и снятие запроса по ответу здесь неизвестны.
Return value handoff не трактуется как bool success: функция не имеет
подтверждённого контракта возвращаемого результата.

## Проверенные кадры

Из 34 сценариев:

- 25 вариантов из native Login writer формируют кадры при разных synthetic
  key/sequence/metadata/wake; sequence 0/65535 покрывает wraparound.
- Collision без совпадения, explicit timeout, negative zero и negative timeout
  добавляют ещё четыре кадра. Всего **29 успешных queue appends**.
- Два дубликата дают 0 insert/notify/getter/queue calls.
- Disabled, mode 2 и special дают insert/notify/getter, но не вызывают Login
  writer, не формируют кадр и не продвигают sequence.

Для каждого из 29 кадров независимо проверены:

`inner = uint16LE(3) + uint16LE(sequence) + LoginPayload.encode(...)`,
`clear = uint32LE(CRC32(inner)) + inner`,
`frame = uint24LE(len(clear)+3) + XOR(clear, synthetic_key)`.

Общий portable `LoginPayload` берётся из shared core. Проверяются bytes целиком,
native entry order, metadata byte, sequence, queue append/wake counts.
Затирание временного archive buffer после отправки не меняет очередь:
она владеет копией кадра. Wake остаётся capture, не запуском scheduler.

[Три новых tests](../../test_vampir_headless_login_send_path.py) воспроизводят
report, проверяют source/table/calls, все 29 кадров и различия отказов.
Смежные четыре Login writer и три Version send path tests прошли.

## Ограничения и следующий шаг

Поля Login взяты из прежних preparation snapshots; сам SDK response и
Login preparation не входят в этот единый run. Metadata lookup/predicates,
name constructor/allocators/free/memcpy/cookie/cleanup — ограниченные fixtures.
Filter пустой; archives/queue заранее имеют 4096 bytes, роста/переполнения нет.
Ключи и поля тестовые. Не читались профиль, память процесса или credentials;
игра, сеть и Android не запускались.

Полный системный lifecycle запросов ещё не готов. Native drain/socket,
ответ LoginResult, session state и переход к персонажам в этот run не входят.
Далее — LoginResult reader/handler/result gates и стыковка с уже исследованным
transport drain; отдельно остаются insert/notify/timeout lifecycle и свежие
SDK/device/profile inputs. До живого входа требуется проверить эти связи.
