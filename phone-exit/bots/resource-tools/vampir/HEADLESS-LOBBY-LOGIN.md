# Лобби: отдельный LoginResult и источник игровых серверов

20 октября 2026. Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Цель — продолжить [диагностическую проверку Version](../../vampir-headless/VERSION-PROBE.md)
по настоящей цепочке лобби, без повторной отправки к неподтверждённой цели.

## Экспорт и воспроизведение

Сначала прочитан существующий Ghidra export, затем добавлены lobby routines.
Ghidra 12.1.4, 309 функций, 142 предупреждения:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-c1d2c2161282`.
SHA manifest: `00a7ff984b8a91e757ab5693f649f46adea34e5b56eadc9144f2247552d2f11d`.
SHA functions.json: `c15c7d2b8881b3d40fc887ee4e14fe987746cf3bf7dd23d91d8050d154557e6a`.
Предупреждения и неверные inferred types не скрыты; псевдокод не заменяет
проверку инструкций и исполнения. Native emulator использует закреплённые
Capstone 5.0.6 / Unicorn 2.1.4 вне runtime.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-lobby-login-path.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-login-result.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_result.py -v
```

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Отчёт | SHA256 | Результат |
| --- | --- | --- |
| lobby-login-path.json | c458fbe72cf41e01f46f27db3eba482767ec0e88e1711d673589ab18ab9689a3 | 58 проверенных direct calls, 34 корня |
| lobby-login-result-replay.json | 3da4f93bdd232d773760d196d7d2e08adde8380a965e1b1cf198f99bf39aa9d5 | 7 полных bodies, 72 коротких префикса |

Discovery сверяет SHA текущего EXE и прежних packet bindings, проверяет
границы E8 через полный decode unwind ranges; сохраняет bytes / offsets /
SHA fragments и связанные строковые литералы. Это статические связи.

## Подтверждённые пути

`RdLobbyPeer::Login()` (0x1467a9360) создаёт PktLobbyLogin на 0x1467a9422
и вызывает sender 0x144aa89b0 на 0x1467a96c7. Sender совпадает с ранее
исследованным [send-A](HEADLESS-SEND-FRAME.md): отдельный peer state,
sequence по +0x228, fallback XOR. Подготовка игрового Version использует
другой peer / send-B. Наличие этих функций пока не доказывает полный порядок
подключения лобби или его первое сообщение.

LobbyLoginResult handler 0x14677ec50 проверяет result по packet+0x10.
В успешной ветви два FString assignments связаны с игровым Login:

| LobbyLoginResult | Копирование в wrapper | Затем PktLogin |
| --- | --- | --- |
| FString +0x20 | +0xf0, call 0x14677ee08 | FString +0x10 |
| FString +0x30 | +0xe0, call 0x14677ee1d | FString +0x20 |

Последний переход подтверждён прежней [подготовкой Login](HEADLESS-LOGIN-PACKET-FIELDS.md).
Это raw строки ответа лобби; их прикладные имена не угаданы. Handler также
сбрасывает busy byte +0x38 у объекта getter 0x145d37220. Остальные UI / SDK /
security ветви не исполнялись в новом replay, этот сброс не реализован в runtime.

Отдельный `PktLobbyServerListReadResultHandler::OnHandler()` (0x14677f350)
на успешном результате вызывает `FRdServerListManager::Update()` (0x145d4afe0)
на 0x14677f4ee. Это источник данных master model, из которой
[BeginGameImpl](HEADLESS-BEGIN-GAME-SERVER-TARGET.md) выбирает запись сервера.
Внутри Update есть работа с коллекциями и отдельные guards: полный перенос
записей и сетевой decoder ответа списка серверов ещё не проверены.

Дополнительно экспортированы три sender callers 0x145d44eb0 / 0x145d44fa0 /
0x145d45030. Метки RequestA / B / C аналитические; типы их пакетов и порядок
вызовов пока не доказаны. Не подменять их автоматически запросом списка.

## Полный reader ответа LobbyLoginResult

PktLobbyLoginResult имеет ID 4, vtable 0x1498f02b8, reader 0x14574aa80.
Он отличается от игрового LoginResult с тем же ID. Порядок body:

| Native object offsets | Wire |
| --- | --- |
| +0x10, +0x14, +0x18 | три LE32 |
| +0x20, +0x30, +0x40, +0x50, +0x60 | пять FString: LE16 длина UTF-8 в байтах, затем bytes |
| +0x70 | LE32 |

Минимальный body — 26 байт. В частности, последний archive slot +0x60
читает **четыре байта**, что проверено исполнением и consumed count.
Назначения трёх полей кроме result code не установлены.

Replay исполняет настоящий reader, archive primitives и UTF-8 readers.
Packet перед запуском — явный zeroed fixture с исходной vtable; constructor
не исполняется. Allocation / FString assignment / std::string growth /
free / cookie — ограниченные fixtures унаследованного harness.
Сценарии содержат пустые / ASCII / длинные / кириллические / CJK / emoji строки
и предельные uint32. Все 72 коротких префикса отклонены. Native reader
при extra bytes возвращает успех и оставляет хвост; portable decoder требует
точного размера body как собственную политику.

## Runtime и границы

`vampir_core.lobby_login_result` добавляет отдельный immutable response type
и bounded decoder. Значения скрыты из repr. Невалидный UTF-8, NUL, запрещённые
кодовые точки и extra bytes отклоняются; malformed-text поведение native
reader этими локальными ограничениями не заявляется.

`login_context.bind_lobby_login_fields` принимает только успешный отдельный
ответ и явный Login template, заполняет первые две строки. Пустые значения
и конфликт со старым контекстом отклоняются; прочие поля не меняются.
Владелец соединения обязан установить происхождение / аккаунт ответа:
decoder и binder сами этого доказать не могут.

Четыре новых теста воспроизводят оба отчёта, сравнивают native / portable
reader, короткие inputs, бюджеты и привязку полей. Также прошли шесть тестов
Login context и девять тестов GameConnection. Внешних сетевых запросов,
запуска игры и сохранения auth-данных на этом этапе не было.

Далее — lobby connect / первый пакет, реальные bindings запросов и ответа
списка серверов, его bounded decoder и загрузка игрового endpoint. Реальный
игровой вход, список персонажей, выбор и позиция пока не получены.
