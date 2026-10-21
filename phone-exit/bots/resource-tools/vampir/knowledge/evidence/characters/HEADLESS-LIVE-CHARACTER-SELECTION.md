# Выбор персонажа после принятого списка

Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Самостоятельный Game Login и список одной записи уже приняты в
[JP-проверке](../auth/HEADLESS-RELEASE-GMC2-GEO.md#живая-jp-проверка-login-и-список-приняты).

## Источники и границы

Запрос ID 109, constructor / indexed caller / state / writer новой сборки
проверены в 25 native сценариях; тело `<QIQ` из выбранного record и текущего
rawF0 совпало с portable codec. Повторять готовую ветвь не требуется.
[Адреса и fixtures](../updates/CLIENT-RELEASE-AUDIT.md).

Внешний reader ID 110 новой сборки — `0x1456f1390`. Сначала читает u32 в
packet+0x10, затем вложенные блоки +0x18 / +0x290, u64 +0x2b0, блоки +0x2b8 /
+0x318, строки +0x328 / +0x338 и два bool +0x348 / +0x349. Полный nested
reader на новой сборке этим статическим экспортом не проверен.

Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-d44249673b72/details.json`.
SHA256: `a36a67359571ec08597700915fedb4eed931140d8541b58803932b854aef6151`.

Полный portable ID 110 decoder по-прежнему имеет source SHA прежней сборки
c7552efd…; его совместимость со всеми данными новой версии не заявлена.
Он используется как строгий bounded parser: короткий / лишний / неизвестный
формат отклоняется. Успех на одном реальном body подтвердит только этот body,
не все возможные варианты новой сборки. Raw vector не считается позицией.

## Подключение к runtime

`probe-selected-game-login.py --read-character-list --character-index 0`
разрешает выбрать нулевую запись только после принятого свежего списка.
Без character-index запрос выбора не отправляется. Индекс проверяется до
авторизации по типу / диапазону, затем по фактическому размеру списка.
Нет fallback на preferred index, другой слот, создание персонажа или retry.

`exchange_game_login` использует тот же GameConnection и его очередь. После
списка вызывает select_character один раз, ожидает ID 110 с отдельным сроком
и сохраняет summary списка при последующем отказе / ошибке. Ответ проверяется
существующим полным decoder. В summary остаются только код, размер и признак
полного разбора; player records / строки / вектор не выводятся. После проверки
соединение закрывается; game_session_ready остаётся false.

Локально прошли 34 теста: 17 game-login probe, 5 selected-game runner и 12 flow.
Socketpair проверяет номера кадров и точное тело выбранной записи, отказы и
таймаут без повтора; повреждённый ответ не попадает в ошибки. Это локальная
проверка orchestration, не native port ID 110 или семантический consumer позиции.

Задание: `F:/PhoneExit Resources/Vampir/knowledge/requests/a38cf2fa3e009c12ca3d757f5c1b7e5c91b007a6fad2eac447240dcd15a99edf/manifest.json`.
Следом — одна живая проверка явного индекса 0 через прежний рабочий JP-маршрут.

## Первая живая попытка и лимит уведомлений

После ID 109 сервер прислал серию сопутствующих пакетов. Проверку остановил
локальный лимит 32 пакета, до разбора ID 110. Login и список снова дали code 0,
одну запись; выбор был отправлен. Принятие выбора и позиция не установлены.
Счётчики send / receive 1022 / 1922 неполные, так как текущий pump прерван.
Sample IDs: 17, 8, 27, 602, 1781, 29054, 8240, 120, 8378, 8388;
повторяется ID 120. Семантика этих пакетов здесь не назначается.

Отчёт: `F:/PhoneExit Resources/Vampir/live-login-observations/76e96122bd6eff4f857d496d6b90e289a1aed8621243da89cb1863756274e794/manifest.json`.
SHA256: `76e96122bd6eff4f857d496d6b90e289a1aed8621243da89cb1863756274e794`.
Процессы попытки и временный listener завершились; новый вход до проверки
этого результата не запускался.

Локальный observer исправлен: sample сохраняет только первые 32 ID, а обработка
ограничена 4096 сопутствующими пакетами и 128 различными ID за попытку.
Дополнительно остаются сроки, byte budgets и ограничение работы каждого pump.
В summary добавлены общий счётчик, bounded counts по ID и флаг усечения sample;
тела пакетов не сохраняются. Переполнение имеет отдельный статус
other_packet_budget_exceeded, без повторного выбора.

19 socketpair-тестов прошли, включая ID 110 после 83 сопутствующих пакетов и
остановку на пакете 4097. Это устраняет наблюдённую локальную причину обрыва,
но не доказывает серверное принятие ID 109. Следом — один новый живой вход
по просьбе пользователя с тем же явным индексом 0.

## Повторная живая проверка: выбор принят

По явной просьбе пользователя выполнен один повтор через samsung SM-A205F / JP
с новым маршрутом и свежим GMC2, server 256 / group 253, ClientVersion 261105,
launcher SDK flow, metadata 312 байт. Индекс 0 относится к свежему списку.

- Game Version, Login и CharacterList — code 0; одна запись, preferred index 0.
- ID 109 отправлен один раз; получен ID 110, result code 0.
- Тело ID 110 — 4724 байта, целиком принято строгим portable decoder без хвоста
  и ошибок. Это подтверждает совместимость данного body, не всех форм новой версии.
- Обработано 17 сопутствующих пакетов, в том числе четыре ID 602 и два ID 8234.
  Sample не усечён. Семантика уведомлений этим не устанавливается.
- Send / receive — 1022 / 4080 байт, счётчики полные; ошибок соединения нет.
  Размер decoded body может превышать receive bytes из-за транспортного сжатия.
- Сокет закрыт после ответа. Временный JP-маршрут остановлен с code 0.

Отчёт: `F:/PhoneExit Resources/Vampir/live-login-observations/72be7b37cb738adea576a54c58f45ce09ea5ab76709e6813f96ff79495937d8e/manifest.json`.
SHA256: `72be7b37cb738adea576a54c58f45ce09ea5ab76709e6813f96ff79495937d8e`.

Вход, список и серверный выбор бота подтверждены. Поля player и spatial vector
не выводились и не сохранялись в публичный отчёт. Семантическая позиция, загрузка
мира, последующие completion packets и длительная сессия ещё не подтверждены;
game_session_ready остаётся false. Следом найти consumer вектора и необходимую
цепочку инициализации мира по готовым материалам / текущему SHA. Повторять выбор
только ради того же результата не требуется.

## Продолжение по полному эталону 4c713eb5

Эталон пользователя повторно проверен существующим bounded TCP decoder по
игровому flow 89. Полный SHA capture остаётся
`d979ae6dbe0b7825d542fdcbf9990b5e0458038d73a6147de30bc383fdf9e5ca`.
189 пакетов разобраны без ошибок и остатков. Из body не сохранялись auth-значения;
новый отчёт содержит только направления, ID, размеры и времена chunks.

После исходящего ID 109 идут серверные данные и ID 110 (4724 байта).
Далее клиент отправляет пустые ID 1006 / 30901 / 1641. Их обязательность для
мирового перехода не установлена; автоматически переносить их пока нельзя.
Затем сервер присылает **ID 202 (92 байта) без исходящего ID 201** в этой записи.
Клиент отвечает ID 203 (8 байт), получает ID 204 (30 байт), отправляет пустой
ID 205 и получает ID 206 (2716 байт). Это наблюдение одной успешной ветви,
не универсальное правило для всех переходов мира.

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Материал | SHA256 |
| --- | --- |
| official-world-timeline-20261021.json | e00cc9565b62d74c133188ac946406ad408f41ca4f4f45e2d546cddd7cc19c98 |
| official-world-window-20261021.json | 50a29270b2834a5ebdf11bf6c6f2f39db80bc614b5fbc14fc53fa4878f5a6774 |

Инструменты `check-official-world-timeline-20261021.py` и
`check-official-world-window-20261021.py` основаны на прежнем проверенном
`check-official-capture-timeline-20261021.py`: расширен список milestones и
выбран участок после ID 109. Это decode сохранённой записи, не отправка в сеть.
Времена относятся к chunks; порядок отдельных пакетов внутри chunk сохранён,
точное отдельное время прихода каждого кадра не доказано.

### Текущие функции применения и продолжения

Выгрузка `details/run-ebe2b2bfcd2d/details.json`, SHA
`049a10725e0480e710360e5e75388a3fcc792b137aa16d14e56360e97132f2c1`,
в каталоге comparison текущего EXE установила статически:

- `0x145d758a0` копирует main+8 в player+8, main+0x30 в player+0x10,
  24 байта main+0x188…+0x1a0 в player+0x20…+0x38. Затем преобразует направление
  через `0x14150b140`, применяет вложенные данные и lookup `0x14588ee70`.
  Это подтверждает сохранение raw vector, но ещё не мировой consumer позиции.
- `0x145db4070` содержит gates и альтернативные пути резервирования с handoff
  kinds 202 / 236. Нельзя отправлять его автоматически после ID 110:
  в выбранном эталоне исходящий ID 201 отсутствует.

Отдельный текущий экспорт `details/run-16b9fbd86578/details.json` показывает:

- `0x145dae4c0` переносит поля ответа в сервис и вызывает virtual +0x68 с
  **байтом packet+0x2d**. Поля +0x14 / +0x2c / +0x28 также записываются в сервис.
  Связь полного reader / регистрации ID 202 на новом EXE ещё нужно проверить.
- `0x145db4510` подготавливает пакет через `0x14584dcb0`, получает текущий
  selected player из manager+0x38/+0x40 и копирует **player+8** в пакет.
  Этот source связан выше с main+8 свежего ID 110. Для байтов 11 / 14 / 19
  (mask 0x84800) выбран handoff с kind 204; остальные идут через transport +0x38.
  Constructor / writer / ID getter следующего пакета в этом экспорте не проверены.

Эти функции прочитаны по псевдокоду и машинным инструкциям, native execution
в этом этапе не выполнялся. Старые comparison names сами по себе не переносят роль.
Следующий runtime шаг — продолжить приём после ID 110, принять / проверить ID 202,
затем сформировать ID 203 из свежего selected player. До отправки нужны current
registration / reader ID 202 и constructor / writer / getter ID 203. Адреса и поля
не брать из старого capture как значения для нового сеанса.

SHA256 второго экспорта: `4a46d71025d1c9e450e15d6b10504a617e95f740d2f09efa483359a0e1777523`.

## ID 203: native writer и переносимый body codec

Продолжение по текущему EXE, без игры / сети. Constructor `0x14584dcb0` не имеет
отдельной unwind-записи: collect оставил его в очереди. Проверен bounded leaf
до RET, 24 байта:
`488d05c1f9110448c7411000000000488901488bc1c6410a01c3`.
Он ставит vtable `0x14996d678`, обнуляет packet+0x10 и ставит byte+0x0a=1.

Таблица203: writer +0x10 → `0x1456bbdc0`, ID getter +0x28 → `0x145759180`,
name getter +0x38 → `0x145858690` с literal PktWorldMoveStart.
Таблица202 `0x14996d600` связана с literal PktWorldMoveReserveResult через
`0x145858660`; reader +0x20 → `0x1458506a0`, ID getter +0x28 → `0x145759140`.
Короткие ID getters исполнены, вернули 202 и 203.

[replay-release-world-start.py](../../../replay-release-world-start.py) исполнил
целые constructor / getters / writer текущей сборки. Writer вызывает выходной
archive virtual +0xb8 с uint64 packet+0x10, возвращает bool результата.
20 случаев проверили 0 / 1 / смешанное значение / старший бит / max uint64 и
ёмкости 0 / 7 / 8 / 9 байт. Пакет не изменяется writer, отказ не пишет данные.
Выходной archive — bounded fixture; весь native archive backend не исполнялся.

[world_move_start.py](../../../../../vampir-shared/vampir_core/world_move_start.py)
содержит неизменяемый payload и строгий body encoder `<Q`. Builder берёт raw
field +8 из принятого ID110 и требует текущий полный source SHA. Этот source
прослежен через current main+8 → player+8 → packet+0x10. Builder не доказывает
внешний gate ID202 и ничего не отправляет. Три новых теста сравнили portable
bytes с 20 native результатами, проверили source / result / uint64 / budgets.

### Reader ID202: установленная внешняя структура

`0x1458506a0` читает result u32 → packet+0x10, byte с clamp32 → +0x14,
два вложенных объекта +0x18 / +0x30, FString +0x210, bool +0x228,
byte с clamp6 → +0x229, byte с clamp2 → +0x22a и u32 +0x22c.
Это не фиксированные 92 байта: тело зависит от nested blocks и строки.
Full native reader202 пока не исполнен, runtime decoder202 ещё не добавлен.

Constructor202 `0x14584dc50` устанавливает table `0x14996d600`, создаёт nested18
через `0x145821270`, nested30 через `0x145784120`, обнуляет result и tail.
Для этих двух прямых callees уже сохранено следующее задание:
`F:/PhoneExit Resources/Vampir/knowledge/requests/77e666c927b6c29a47b00e77155a819c236386cf221ee238bca3e1219de4f1d1/manifest.json`.
Их материалы пока отсутствуют; следующий collect должен запросить только их.

Каталог comparison: `F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| world-packet-bindings/94349d9ca4b72b341fa341c7c8cffa681843f743f28ce91d20ab2ca5728d9e1b/manifest.json | 94349d9ca4b72b341fa341c7c8cffa681843f743f28ce91d20ab2ca5728d9e1b |
| details/run-3daa86310054/details.json | bb0875c2ad7ed84d7d33a72a7d34e5c6c1902cde22969feea95d8db60dad4582 |
| details/run-4acfe2f63ddf/details.json | 9c6e5a51a358cf5a9da2319019759ba64a6744c939f368683a76ed278ec0aea2 |
| world-start-writer-replay/f170ab69f9afef01346992173038a50c205f1cbf1a8ebac4c820907add971b3b/manifest.json | f170ab69f9afef01346992173038a50c205f1cbf1a8ebac4c820907add971b3b |

Native writer check добавлен в research-checks.json. Результаты сохранены через
finish. Короткие getters остались без Ghidra function object, но их source-pinned
leaf bytes и выполнение сохранены native report. Новый живой вход не выполнялся:
сначала завершить decoder202 и обработку следующего шага в той же сессии.
