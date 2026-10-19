# Список и выбор персонажа: owner и ограниченные body codecs

## Продолжение: ограничения ID102 сняты

Appearance/optional ветви и covered ID102 handler проверены следующим этапом:
[актуальная схема, SHA, API budgets и preferred index](HEADLESS-CHARACTER-LIST-EXTENSIONS.md).
Замечания ниже об UnsupportedCharacterExtension и отсутствующих extensions
описывают первичный этап; текущий decoder поддерживает эти ветви. Lifecycle,
ID109 field sources/frame проверены [следующим этапом](HEADLESS-CHARACTER-SELECT-SEND.md);
ID110/live session остаются открытыми.

20 октября 2026. Работа без запуска игры. Ближайший этап **частично выполнен**:
owner policy больше не fixture; основной профиль списка и body выбора проверены.
Полный список, selection response и живая сессия ещё не готовы.

## Источник и воспроизведение

Код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4, 101 функция / 53 предупреждения. Актуальный экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-81ba9f90e983`.
Manifest SHA256 `a69e67552d279f84a267ba8c03cfc09d178933b13db248a787268f3a7e0e2821`.
Псевдокод, инструкции и native replay относятся к одному SHA, а не к исходному C++.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-owner.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-list-reader.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-writer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_character_progress.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
```

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Файл | SHA256 | Проверка |
| --- | --- | --- |
| character-list-owner-replay.json | `47acac7cd9087fc0d635d5dd6071225d53caf99b96aa7a4be823cfa5bfd6a6cc` | 2 owner→request cases |
| character-list-reader-replay.json | `00bfdaed831215dec4c530328a78d6d5da85275997e908dfe61b98796e6266d1` | 12 полных bodies, 38+191 short inputs, trailing |
| character-select-writer-replay.json | `75dd034248d44abb165e057f574cf3f7735fec4f934a660ab463998c41f6da14` | 16 writer vectors |

## Owner: actual policy 1 → CharacterListRead

Ранее найденная ссылка на caller `0x1468f1d70` находится в
`0x149e0ef78`. Таблица `0x149e0e7c8` установлена native constructor
`0x1468e29a0` (объект передаётся через pointer wrapper).
Это подтверждено исполнением, а не только выбором предполагаемой границы таблицы.

- Table+`0x7b0` → caller `0x1468f1d70`.
- Table+`0xa18` → `0x140bb4a10`, точные байты `b0 01 c3` (AL=1; RET).
- Table+`0xa00` → `0x1468f09a0`, helper затем virtual+a20; при actual policy 1
  эта ветка caller не исполняется.

Два replay (lookup disabled/enabled с null fixture) исполняют constructor,
actual caller, actual policy и RequestA/packet constructor до send capture ID101.
Базовый constructor, выделение member storage и UI helpers остаются fixtures.
Класс, назначение engine slot 7b0, связь с загрузкой CharacterSelect_02 и реальный
вызов этого lifecycle hook пока не доказаны. Поэтому нельзя автоматически
посылать ID101 сразу после LoginResult, ссылаясь только на этот результат.

## CharacterListReadResult / ID102

Binding: vtable `0x1498d8540`, constructor `0x1456d47a0`,
reader `0x1456d8d80`, handler `0x14675dce0`.
Reader вызван с actual archive; packet/record/nested readers и UTF-8 conversion
исполняются. Контейнерное выделение, shallow copy и cleanup — bounded fixtures;
native lifetime владения строками этим не проверен.

Body: `<IIH` (raw+10/result code, raw+14, record count), записи,
затем `<QIQQ` (raw+28/+30/+38/+40). Минимальное тело — 38 байт.
Count — uint16 в wire, а не размер native TArray. Native stride записи — 0x170;
wire запись имеет переменный размер и не содержит vptr/padding.

Main record: constructor `0x14577d3d0`, table `0x1498d7ff8`,
reader `0x145781c80`. Последовательность (native offsets):

| Offset | Wire |
| --- | --- |
| +08, +10, +18, +28, +30 | Q, I, UTF-8 string, Q, I |
| +38/+40, +48, +50, +60 | nested TimeBase Q, Q, string, byte с clamp до 6 |
| +68/+70 | nested четыре uint16, не timestamp и не доказанный uint64 |
| +78/+80, +88, +90/+98, +a0, +a8 | TimeBase Q, Q, TimeBase Q, Q, Q |
| +b0 | appearance, см. ниже |
| +f0, +f8, +100, +108 | Q, Q, Q, normalized bool |
| +110 | optional-present bool; при true дополнительный массив/map |

Q/I — LE raw bits. Строка — uint16 длина UTF-8 bytes + bytes.
Семантика ID/имени/уровня/координат не устанавливается одним offset.
Для +68 общий decoder сохраняет четыре raw uint16 отдельно;
подтверждённый native reader `0x14578dfa0` читает именно четыре uint16.

Appearance table `0x1498cffa0`, reader `0x1457812a0`: enum byte clamp≤2,
девять raw bytes, string, normalized bool, raw byte, uint16 count и элементы.
Optional table `0x1498d1b90`, reader `0x1456bf640`: bool, при true массив/map.

Общий `vampir_core.character_list.decode_character_list` поддерживает основной
профиль **только с пустым appearance extension array и отсутствующим optional**.
Неподдерживаемые ветви дают `UnsupportedCharacterExtension`; данные не пропускаются
и не заменяются пустыми значениями. Обязательны byte/count budgets, immutable
bytes, строгий UTF-8 и полное потребление тела. Native допускает trailing bytes;
общий decoder намеренно отвергает их как локальную политику.
Модели frozen, поля записей скрыты из repr. Код результата сам по себе не
устанавливает состояние сессии.

12 полных vectors: 0/1/2/4 записи, ASCII/кириллица/CJK/emoji, UTF-8 length 128,
uint32/64 maxima, enum clamps и normalization byte 255. 229 short prefixes
отвергнуты native и общим decoder. Есть отдельный native trailing case.
Пять тестов воспроизводят отчёты, проверяют parity, limits и явный отказ extensions.

## CharacterSelect / ID109

Writer `0x1456e53a0`: raw packet+10 uint64 → +18 uint32 → +20 uint64,
ровно 20 байт `<QIQ`. Native writer/archive IO проверены на 16 vectors,
включая четыре raw field snapshots из ранее исполненного virtual 50 handoff.
Это отдельный writer replay, не цельный handoff→frame→socket.

Общий `vampir_core.character_select.CharacterSelectPayload` кодирует immutable
raw поля с явным byte budget и uint range checks, без сети и defaults аккаунта.
Назначения всех трёх полей пока не доказаны. Нельзя выбирать персонажа, подставив
предполагаемый ID или фиксированный ноль вместо неизвестного поля.

## Продолжение

1. Закрыть appearance extension: callbacks table `0x1498ef500`, resize
   `0x1456b60e0`, item read `0x145737650`, item table `0x1498cff58`.
2. Закрыть optional map: callbacks table `0x1498d5038`, resize `0x1456cf6b0`,
   read `0x1456c3890` → value reader через объект+8; insert `0x1456b99b0`.
   Экспорт callbacks уже готов; полного native/общего decoder этих ветвей нет.
3. Проверить actual ID102 handler/result gate, перенос списка, preferred selection
   по packet+38/record+8 и источники полей virtual 50. Псевдокод handler показывает
   эти обращения, но runtime семантика пока не проверена.
4. Связать owner hook с lifecycle уровня; завершить ID109 frame и ID110 nested
   body/handler. Экспорт ID110 reader/handler уже есть, native проверок ещё нет.
5. Лишь затем live вход на согласованном аккаунте с настоящим SDK/device context,
   ручным подтверждением устройства при необходимости и получением позиции.

Аккаунт, секреты, реальный сервер, процесс игры и Android не использовались.
Это не завершённая цепочка входа и не работающий сетевой бот.

Предшествующие связи: [caller](HEADLESS-CHARACTER-LIST-CALLER.md),
[service/handoff](HEADLESS-SELECTION-SERVICE.md),
[packet bindings/регистрации](HEADLESS-PACKET-BINDINGS.md).
