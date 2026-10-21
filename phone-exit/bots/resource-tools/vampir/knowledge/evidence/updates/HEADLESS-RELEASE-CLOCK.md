# Источник часов Ping: UTC, Unix epoch и поправка в минутах

21 октября 2026. Собранный EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Это продолжение [producer Ping](HEADLESS-RELEASE-BOOTSTRAP.md#исполнение-целого-producer),
не утверждение о принятом Login бота. Основной эталон — запись 4c713eb5.

## Источник и source-bound переходы

Сначала проверены README / вопрос login-invalid-state / реестр по getter
`0x1445ce230`. Новый [Ghidra clock mode](../../../inspect-release-bootstrap.py)
проследил ссылки на global `0x14b567a40` и затем `0x14b567700`.
В отличие от отсутствующих PktPing literal xrefs эти ссылки присутствуют в
сохранённом проекте. Чтения / записи и владельцы выгружены вместе с инструкциями.

Default factory в `0x1445dab10` выделяет 0x50 байт, устанавливает таблицы
`0x14955a248` и `0x14955a278`, обнуляет +0x10/+0x18/+0x20/+0x28.
Есть альтернативная factory ветвь; активный runtime factory не установлен.
Primary slot +8 ведёт в `0x1445d4bc0`, который очищает state и делает JMP в
`0x1445dad40`. Первый slot secondary table ведёт в `0x1445d8b20` с this = object+8:
он вызывает тот же refresh для object, затем обрабатывает sync flags / float delta.
Нельзя объявлять этот slot деструктором только по его номеру.

| Участок | Source address | Проверено |
| --- | --- | --- |
| Refresh | 0x1445dad40 | UTC calendar ticks, Unix epoch и две clock cache величины |
| UTC calendar getter | 0x14156ae00 | Platform UTC fields → actual calendar constructor |
| Platform fields | 0x1415da9a0 | KERNEL32.dll GetSystemTime, распределение SYSTEMTIME |
| Calendar constructor | 0x1415483d0 | Дни от года 1, календарная арифметика и 100-нс ticks |
| Offset / server sample setter | 0x1445d8a30 | signed short minutes, server sample и sync flags |
| Clock secondary update | 0x1445d8b20 | Refresh cache и первый sync-frame gate |

Import `GetSystemTime` проверен по PE import table, IAT `0x14899c928` и actual
CALL на `0x1415da9f1`, а не только по имени из псевдокода.
Для `0x14b567700` нет file-backed bytes: это PE zero-fill область.
Нулевое начальное отображение не является подтверждением рабочего offset.

## Формула

Обозначим U — UTC ticks из календарного constructor, E — ticks для
**1970-01-01 00:00:00.000**, O — global offset ticks, L — локальная UTC-поправка.
Refresh реально выполняет:

- object+0x40 = U;
- object+0x10 = U − E + O; именно это поле читает producer Ping;
- object+0x18 = object+0x10 + (L − O) = U − E + L.

Setter принимает signed short M и отдельный signed server sample S:
O = floor(M × 600 000 000 + 0,5), server ticks = floor(S × 10 000 + 0,5).
Константы / bytes проверены в текущем EXE. Для допустимых целых M это
M минут в 100-нс ticks. Server sample записывается в +0x20 и при первом
значении также в +0x28; выставляются sync flags. Он не подменяет UTC cache +0x10.
Локальная поправка в getter `0x1445d0050` отдельно кэшируется как разница
local-calendar / UTC-calendar; в replay её backend задан fixture, а влияние
на поля разделено. Политика однократной TLS инициализации этого cache не исполнена.

Producer Ping выполняет уже проверенное `int(double(object+0x10) × 0.0001)`.
Следовательно, для этого default пути используются Unix milliseconds с
настроенной поправкой M минут. **Постоянного правила «UTC+9» из этого не следует.**

## Native проверка

[replay-release-clock.py](../../../replay-release-clock.py) исполняет целиком
initialize → actual UTC getter / platform adapter / calendar constructor →
setter → secondary update / refresh. Он проверяет совпадение Ghidra instruction
bytes для leaf-функций без .pdata и отображает source RIP data pages через
Capstone, не заменяя машинную арифметику Python-формулой.

OS GetSystemTime — явная fixture с валидным SYSTEMTIME; валидатор количества
дней в месяце, local-offset cache и cookie backend также fixtures. Календарная
арифметика actual constructor и построение epoch исполняются native.
Сам системный clock не меняется, реальный процесс / credentials не читаются,
сеть не используется. Полная lifecycle ветвь смены timezone / factory / DST
этими сценариями не закрывается.

24 native cases: UTC epoch, високосный 2000-02-29, дата эталона;
M = −720 / 0 / 540 / 840 минут и L = 0 / 180 минут. Проверены exact +0x10,
+0x18, +0x20/+0x28, +0x40, sync flags, два UTC acquisition и object guards.
Server sample намеренно отличается от локальных часов на 12 345 мс,
чтобы проверить, что эти источники не смешиваются.
Три [регрессионных теста](../../../../../test_vampir_release_clock.py) повторно
запускают реальный native код, проверяют epoch, signed offset, независимость
local / server cache и значение первого Ping эталона.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --clock
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-clock.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_clock.py -v
```

## Сверка с эталоном

В записи 4c713eb5 оба lobby ID 2 / body 23 байта (flows 81 / 88) имеют
raw +0x38 = **540**. Game LoginResult / flow 89 имеет raw +0x60 = **540**.
Кодек и CRC проверены прежним checker; сохранены только эти числовые поля,
размеры, времена и IDs. Указанные raw values соответствуют M = 540 минут.
Для UTC 2026-10-21 16:29:02.863 native clock даёт Ping clock
**1792632542863**, что совпало с первым полем первого Ping эталона.
Второе поле равно первому при last = 0, как уже доказано producer replay.

У setter два найденных прямых caller: `0x14679c4f0` и `0x1467ace30`.
Второй передаёт в setter raw object+0x30 и signed short +0x38. Его привязка
к ID 2 затем подтверждена через текущую регистрацию и native replay ниже.
Первый передаёт +0x58 / +0x60 из packet object и обновляет offset также
непосредственно; полный dispatcher / handler lifecycle не исполнялся.
Источник часов / формула и привязка lobby packet к setter установлены.

## Регистрация ID 2 и передача полей в часы

От адреса handler найден aligned pointer slot +0x10 таблицы `0x149dc7ab0`.
Её LEA в `0x1467b5e00` приводит к первой паре регистрации: выделяются handler
и packet, вызывается constructor `0x14574ab20`, затем общий register
`0x1467ccbc0`. Register получает ID через packet vtable+0x28 и передаёт
в map запись ID / packet / handler. Actual ID getter `0x14148aa20` возвращает 2.
Packet table `0x149942ce0` содержит reader +0x20 → `0x145750670`,
ID getter +0x28 и name getter +0x38 → `0x14575a280`; literal имени —
`PktLobbyVersionResult` в `0x149942d30`. Роль не выведена из сходства offsets.

Whole reader читает 23 байта: uint32 code, bool, два raw64 TimeBase и uint16.
TimeBase constructors / reader выполняются вместе с archive readers, включая
`0x144aad7c0`. Handler передаёт второй TimeBase в clock setter, а первый —
в manager через tail JMP `0x1467ace8c` → `0x145d5e440`. Важно сверять инструкции:
декомпилятор показал этот tail как объединённую логику внутри handler.

[replay-release-lobby-clock.py](../../../replay-release-lobby-clock.py)
исполняет первую пару регистрации до возврата, actual constructor / ID getter,
целый reader, handler, clock-pointer getter, setter и manager tail. Проверены
18 комбинаций: M = −180 / 0 / 540 минут, bool bytes 0 / 1 / 255,
первый TimeBase 0 / 2000. Раздельно проверяются offset ticks, server ticks,
нормализация bool и manager state. Все 23 коротких префикса отвергнуты;
полный body принят. Три [регрессионных теста](../../../../../test_vampir_release_lobby_clock.py)
повторяют native выполнение и проверяют регистрацию, поля и короткие входы.

Fixtures: allocator, вставка в map с успешным результатом, базовая инициализация
dispatcher, UI / maintenance getters, сравнение manager clock и cookie backend.
Generic dispatcher / TMap и TCP routing не исполняются; UI branch обходится
явным fixture state. Проверены только bodies с code 0. Это не доказательство
успешной авторизации бота или необходимости Ping для принятия Login.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --lobby-clock
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-lobby-clock.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_lobby_clock.py -v
```

## Материалы вне Git

Общий каталог Ghidra:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Отчёт | SHA256 |
| --- | --- |
| bootstrap/run-4398dc0d34cf/export/bootstrap.json, pointer refs / factory | d6d1c226ecad9f5ef0ac389c4ddef9d3ffdffe7dbd3fef602d72583ca42bbb63 |
| bootstrap/run-aa9d3f766ff1/export/bootstrap.json, initialize | 0d7ed611834d0ab44e77f701c0094bb2e7c8393a829b7b62c80e71f9f819e96c |
| details/run-c7d2f2ad9bfc/details.json, refresh | 1e0b7a0181b6f4392d9475a5e1c6f469ddaedfccf80ca8078c43e0f537b3f122 |
| details/run-7c4690fdf614/details.json, UTC / date / local offset | 8a66f7e97ce2f6061b93b74140201ffde77150069c1f8f4356919dad1bb95e46 |
| details/run-95c224ed8e25/details.json, setter | 3a6c6333b604008f5da59dade96eadef100c547a6f43828b0da495e0fca3ec6a |
| bootstrap/run-1ffad6459713/export/bootstrap.json, full clock / callers / UTC import adapter | 5da074763b362b2d05d3adfac4ec200ee9f221e34c469fbd2fb1fec9878a7bbb |
| clock-replay/96b11b0f3047704cfe84eb11d584eda06cbdb5753e39566a070f9058664d820b/manifest.json | 96b11b0f3047704cfe84eb11d584eda06cbdb5753e39566a070f9058664d820b |
| details/run-9bd31940a8e9/details.json, registration root | a8b4ae3cbf59723cbdbadf866622429d02785212ae994cdccabf316bf0fd9ae2 |
| details/run-d1178d85d75e/details.json, constructor / register | f5c2306a7e7603a99f471a98e744de6f4b8cf4d0a7bcafd7cc5662faedd61b1d |
| bootstrap/run-f534419cd27a/export/bootstrap.json, packet / handler tables and functions | a2c3a7104e1218d61b31e638daea50a4e67dc54ab6142abf967df52e369885dd |
| lobby-clock-replay/bb68dd02904ce28fa7e69793e13d4d2e5c6022c82f8b4cbc0cbd28a2de1871b0/manifest.json | bb68dd02904ce28fa7e69793e13d4d2e5c6022c82f8b4cbc0cbd28a2de1871b0 |

Capture field report:
`F:/PhoneExit Resources/Vampir/code-clues/official-clock-fields-4c713eb5.json`,
SHA256 `f84afefdb8cf0e0cf636f0c486832a512e7fd6a2fdd55d2f8f6a4f521ac83c38`.
Его checker — `check-official-capture-clock-fields-20261021.py` в том же
каталоге, производный прежнего CRC / ReceiveStream checker, без raw auth output.
SHA256 checker: `90341e64c1e96fcb9376b37d211d2696020b492f6c66d3b1804c351792ed78e6`.
Новые native function targets от Ghidra CALL / JMP передавались существующим
`find-release-sdk-references.py` и затем `inspect-release-function-candidates.py`;
invocations / pinned inputs / source / script / output hashes сохранены рядом.

Следом — свежий lobby clock context в runtime и ранний Ping. Источник кадра
30413 остаётся неизвестным; порядок эталона целиком ещё не воспроизведён.
Runtime бота и живой вход на этом проходе не менялись.
