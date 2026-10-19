# LoginResult: вложенные readers и переносимый декодер

19 октября 2026. Продолжение [Login send](HEADLESS-LOGIN-SEND-PATH.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Ghidra и воспроизведение

Сначала прочитаны имеющиеся `PktLoginResult_Read.c` и `LoginResult_Handler.c`.
Для вложенных полей пакет Ghidra расширен с 22 до 32 функций:
constructor/writer LoginResult, Archive_ReadFString/ReadStdString,
PeriodServerDate constructor/reader, TimeBase reader и UTF-8 conversion helpers.
Успешный export и verifier: 32 функции, 15 warnings; warnings сохранены.
Главный индекс — `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Текущий экспорт: `export-c7552efd2125/run-8b3fb838b7a7` относительно `ghidra/`.

`functions.json` SHA256:
`bc747114c1aa2afef10a17ecb5e1fe31e36f069dffb994b5dcb2a070932eb6cd`.
Seeds и SHA исходных PE ranges воспроизводимы через
[build-ghidra-manifest.py](build-ghidra-manifest.py), экспорт — через
[run-ghidra-export.py](run-ghidra-export.py) с `--reuse`.

[replay-login-result-reader.py](replay-login-result-reader.py) →
`F:/PhoneExit Resources/Vampir/code-clues/login-result-reader-replay.json`.
SHA256: `83f0ae92b0b4fc09a424c77c67306106c1c319cf65af2b8868a7d968ea1cf602`.
Report сохраняет source/tool/upstream SHA, native fragments/bytes/file offsets,
leaf thunks, packet/nested/archive tables и полные результаты чтения.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-result-reader.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_result_reader.py
```

## Исполненный код

Constructor **0x1456d4da0**, reader **0x1456d9600**, packet vtable
**0x1498d6218**, ID 4 из [packet bindings](HEADLESS-PACKET-BINDINGS.md).
Проверяется actual slot+0x20→reader, constructor и ID binding.

Вложенные объекты:

- **PktTimeBase**: vtable **0x1498cf2c8**, constructor leaf **0x1457eca60**,
  reader **0x1457f0a90**. Reader пишет raw64 в subobject+8.
- **PktPeriodServerDate**: vtable **0x1498d61d0**, constructor **0x145794c20**,
  reader **0x1457986b0**. Два bool-поля и четыре вложенных TimeBase.
- Thunk **0x144aa68b0** передаёт archive/объект в virtual reader+0x20.

Имена вложенных типов привязаны к таблицам и literal bytes в клиенте.
Они не доказывают единицы времени, timezone или календарную семантику raw64.
Конструкторы реально исполняются; vptrs не заменены нарисованным layout.

Исполнены Archive_ReadFString **0x144aa66f0**, ReadStdString **0x144aa5ab0**,
UTF-8 length **0x141446940**, wrapper **0x141440ba0**,
decode core **0x141436230** и scalar decode **0x141435ea0** со связанными
PE fragments. Рост std::string, финальное присваивание FString,
allocator/free/memcpy/cookie остаются bounded fixtures.

## Wire body и object offsets

Порядок ниже подтверждён native чтением. Смещения — поля объекта клиента,
не смещения в переменном wire body. Никакие vptr/padding по сети не передаются.

| Порядок | Поле объекта | Формат |
| --- | --- | --- |
| 1 | +0x10 | uint32, raw result code handler |
| 2–4 | +0x18, +0x28, +0x38 | 3 строки |
| 5 | +0x48 | uint16 |
| 6 | TimeBase+0x50, value+0x58 | raw64 |
| 7 | +0x60 | uint16 |
| 8 | +0x68 | raw64 |
| 9 | +0x70 | строка |
| 10 | +0x80 | raw64 |
| 11 | +0x88 | bool byte |
| 12 | +0x90 | строка |
| 13 | +0xa0 | bool byte |
| 14 | TimeBase+0xa8, value+0xb0 | raw64 |
| 15–16 | +0xb8, +0xc8 | 2 строки |
| 17 | PeriodServerDate+0xd8, flag+0xe0 | bool byte |
| 18–21 | values+0xf0, +0x100, +0x110, +0x120 | 4 raw64 |
| 22 | PeriodServerDate flag+0x128 | bool byte |
| 23–24 | +0x130, +0x134 | 2 uint32 |
| 25 | +0x138 | bool byte |

Все числа little-endian; signedness исходных C++ типов не восстанавливается
по ширине. Строки имеют uint16 UTF-8 byte length, затем UTF-8 без NUL.
Native FString conversion выполнялась для корректных строк.
Bool reader нормализует 0/1/2/255 к 0/1 во всех пяти полях.
Итого 7 строк/3 uint32/2 uint16/8 raw64/5 bool bytes, минимальное тело 99 bytes.
ID 4 и transport header в эти 99 bytes не входят.

## Native-проверки

21 полное тело: 7 строковых вариантов (empty, ASCII 15, ASCII 16, ASCII 128,
кириллица+иероглиф, emoji, multibyte), 10 raw result codes и 4 набора flags.
Проверены широкие uint32/uint16/raw64 values, вложенные поля и consumed length.
Result codes 1/14/22/37/54/9400/9818/9819/90021/0xffffffff читаются как данные;
это не исполнение handler branches или подтверждение серверного ответа.

332 префикса: 99 от минимального тела, 106 от тела со строками `x`, 127 от тела
со строками emoji. Каждый native reader возвращает 0, consumed не выходит
за доступный ввод. Полное тело с `extra` принимается native reader,
consumed=99: trailing bytes остаются вне разобранных полей.

Невалидные UTF-8, NUL, очень большие строки и allocator failure native-прогоном
не покрыты. Известное поведение writer при отказах не переносится автоматически
на reader: здесь реально исполнены и проверены именно эти short-input cases.

## Общий кодек и его локальная политика

[vampir_core.login_result](../../vampir-shared/vampir_core/login_result.py):
`decode_login_result(body, max_payload_size=...)` возвращает frozen
`LoginResultBody`. Ordered tuples:

- strings: 18,28,38,70,90,b8,c8;
- u32: 10,130,134; u16: 48,60;
- u64: 58,68,80,b0,f0,100,110,120;
- flags: 88,a0,e0,128,138, нормализованные Python bool.

Все смещения выше hex. `result_code` — только raw u32+0x10; 0 не доказывает
сессию. Остальные поля не названы userID/token/timezone без отдельной связи.
Все значения скрыты из repr. Только stdlib, без I/O, хранилища и SDK.

Строгая локальная политика требует immutable bytes, явный byte budget,
корректные UTF-8 scalar values и точное потребление тела. Запрещены NUL,
U+FFFE/U+FFFF, trailing bytes, неверные размеры/типы. Это сознательно строже
native trailing acceptance; прочие native malformed semantics не заявлены.

[Четыре tests](../../test_vampir_headless_login_result_reader.py) перестраивают
report, сравнивают 21 decoded object, отвергают 332 short bodies, проверяют
trailing policy, immutable fields/unsigned bounds/budgets/repr/text errors.
Смежные Ghidra/VersionResult/Login writer tests также пройдены.

## Следующий участок

Handler **0x146765540** прочитан через Ghidra: он имеет result gate,
особые error branches и дальнейшие UI/state calls. Эти ветки ещё не исполнены
в новом replay. Decoder не объявляет code 0 готовой игровой сессией.
Следом — handler/result gates и связь с последующим запросом персонажей.
Listener/Dispatch, actual response framing, LoginResult handler и live socket
не входят в этот body-only run. Profile/process memory/credentials/network/
Android не использовались. Полный SDK→Login→server→character flow ещё не готов.
