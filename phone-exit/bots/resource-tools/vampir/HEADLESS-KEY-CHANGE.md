# Vampir — уведомление и подтверждение смены ключа

18 октября 2026. Продолжение [receive envelope](HEADLESS-RECEIVE-ENVELOPE.md),
[общий реестр](../../vampir/FUNCTION-INDEX.md). H03b.2b остаётся частичным:
подтверждён источник смены peer key, но не исходная авторизация и не весь приём.

## Источник и повторение

Собранный Windows EXE `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса — VA, image base `0x140000000`. Версия Windows/Android parity unknown.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-key-change.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_key_change.py -v
```

Выход: `F:/PhoneExit Resources/Vampir/code-clues/headless-key-change.json`,
SHA256 `bf48a4ff2541effc83799ee9e69a0155f8d0675701797708bb09edb422504aa5`.
Report хранит source/tool hashes, 9 fragments/18846 instructions, vtable/name/
registration/IO-slot proofs, payload и handler slice vectors.
В значениях экспериментов только явно заданные тестовые числа, не живые ключи.

## Подтверждённая цепочка

Точная диагностика `PktKeyChangeNotifyHandler::OnHandler()` закреплена
LEA `0x146765060` внутри handler root `0x146765050`.
Factory `0x14678ec40` создаёт notify конструктором `0x1456d4c00` вcall
`0x14678ee5e`, регистрирует пару вcall `0x14678ee71` → `0x1467a7250`.
Handler table `0x149d81038` имеет target+10=`0x146765050`.

| Тип | ID | Vtable | Constructor | Writer | Reader |
|---|---:|---|---|---|---|
| PktKeyChangeNotify | 11 | 0x1498d5f58 | 0x1456d4c00 | 0x1456b6770 | 0x1456b3360 |
| PktKeyChanged | 12 | 0x1498d5e90 | 0x1456d4c20 | 0x1456e5740 | 0x1456d92f0 |

Оба типа сериализуют raw64[obj+10] в8байт little-endian в доказанной swap=0
ветке. Notify использует IO slots b8/50, ack — b0/48, но эти слоты текущих
архивов указывают на те же реальные u64 primitive routines. ID getters
`0x1421dbdf0`/`0x1414f51d0` реально исполнены и возвращают11/12.
Name getters `0x1456e3320`/`0x1456e3350` связаны с точными строками иvtable+38.
Signedness на уровне исходных типов не переименовывается; codec хранит raw bits.
Найдено также имя PktKeyChangedResult, но его контракт здесь не разобран.

## Порядок обработки уведомления

Native диапазон `0x1467650c1..0x146765113`:

1. Конструирует PktKeyChanged на стеке.
2. Копирует notify[obj+10] вack[obj+10].
3. Получает peer handle через singleton getter `0x144aaa9d0`.
4. Вызывает виртуальную отправку slot+38 сack.
5. Снова получает handle, передаёт адрес raw64 изnotify вsetter slot+40.

Таблица derived handle `0x149d84e50` ставится конструктором вroot
`0x1467a79e0`; slot+40 равен `0x144aab330`. Base table `0x14961b740`
имеет тот жеsetter. Он выполняет peer=[handle+10], key=[argument],
[peer+248]=key. Этот же main+248 используется send-B; receive-B получает
subobject main+200 ичитает subobject+48, то есть то же поле.

Следовательно, **вызов отправки ack предшествует записи нового ключа**.
Native код наэтом участке не проверяет return value отправки: новый ключ
записывается ипри явно смоделированном false. Нельзя выводить изэтого доставку
ack, синхронность сокета или корректную политику повторов будущего клиента.
При асинхронной очереди важно не переупаковать уже созданный ack новым ключом;
полный контракт очереди пока не восстановлен.

## Что реально исполнено

- 10 roundtrips:2типа ×5raw64patterns, включая2^53+1 иall-ones;
  native packet/primitive/raw IO безподмены, только внешняя CRT memcpy shim.
- 16коротких read cases:0..7байт дляобоих типов, native false.
- 20handler slice scenarios:2старых ключа ×5новых ×2send returns.
  Настоящие constructor/singleton getter/setter; виртуальная отправка заменена
  capture shim. Вмомент вызова захватываются старое состояние иack bits;
  затем фиксируются вызов setter иитоговое состояние.

Логирование/cleanup handler исключены; handle/vtable/object graph иsingleton
явно синтетические. Таблица дляэксперимента сохраняетдоказанные slot offsets,
но slot отправки направлен вcapture shim. Сервер/сокет/реальные ключи неиспользованы.
Пять тестов сверяют исходныеbytes/SHA, всеvectors иповторяют4native сценария.

## Общий модуль ипродолжение

`vampir-shared/vampir_core/key_change.py`: IDs11/12 и `KeyChangePayload`,
encode/decode точных8байт. Repr скрывает значение. Это не защищённое хранилище:
живые ключи всёравно нельзя логировать, сериализовать втелеметрию илиproof отчёты.
Модуль не переключаетсессии и не отправляет ack автоматически.

Далее: как Notify попадает вdispatcher изсырого транспорта, входной layout/
CRC validation, transport buffering иполитика send queue. Генерация ключа на
сервере ипервичная авторизация остаются неизвестными. `network_ready=false`.
Ранее кандидат setter теперь подтверждён цепочкой Notify→ack→state update.
