# Самостоятельный клиент Vampir

Клиент развивается для входа, удержания сессии, карты, параметров персонажа
и квестовых действий. Готовность каждого из этих контрактов проверяется отдельно.

[Обновление и запуск ярлыком](../resource-tools/vampir/knowledge/RESUMABLE-UPDATE.md)
готовят пакет следующего входа. Работающий owner сохраняет закреплённый пакет;
обновление не запускает вход и не отправляет игровых команд. Профили
`prepared-next` / `prepared:<SHA>` проходят проверку доказательств перед запуском.
Новый SHA без обязательных checks отклоняется, старый профиль не подставляется.

На последнем зафиксированном исследовании 1.13.22 подтверждены отдельные функции;
поддержка целого входа ещё не объявлена.
[Границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-11322.md).
Фактический текущий статус смотреть в журнале обновлятора и API owner;
прежний отчёт об онлайне не подтверждает существование соединения сейчас.

[Главный указатель](../vampir/README.md), [открытые пакеты](TASKS.md),
[панель аккаунтов](ACCOUNT-CONSOLE.md).

[Проверка обновлятора](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTOMATIC-UPDATE.md)
подтвердила повтор без нового native replay. Для подготовленного следующего
пакета используется явный профиль `prepared-next`; неполный вход отклоняется
до запроса учётных данных и сетевого соединения.

[Общий string writer 20 → 22](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-STRING-WRITER-11322.md)
прошёл 228 native сценариев и подключён к обновлению / кэшу. Это отдельный
offline пакет.
[Archive wire](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-ARCHIVE-WIRE-11322.md)
добавил 109 native сценариев. Preparation, framing, ответы и полный вход
продолжают требовать своих проверок.

[Version 20 → 22](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-VERSION-11322.md)
получил generic prepare и VersionResult / input buffer adapters, 191 новый native
случай. OS / SDK / helper values, response handlers и целый вход этим не допущены.

[LoginResult nested и native string/buffer input](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-INPUT-11322.md)
подключены к автообновлению: 232 + 506 native сценариев, точные матрицы и guards.
Общий повтор 19 drivers переиспользовал 57 этапов без JVM / native replay.
Handlers / registration / response composition и целый вход остаются открытыми.

## Сохранённые записи прежних этапов

Утверждения о версии, очереди и живой сессии ниже относятся к описанному этапу.
Они сохранены для ссылок и воспроизводимости; текущие действия задаёт инструкция выше.

<details>
<summary>Исторические результаты и прежние указатели</summary>

# Самостоятельный клиент Vampir

25 октября `candidate-11316` прошёл ограниченный вход существующего персонажа
`bot-hk-test@vampir.top` на Franz 2 через HK: Select 0, ID202/204/206 0,
серверный вектор получен. 120 секунд наблюдения — 24 periodic Ping / 25 ID17,
ошибок нет. После теста соединения закрыты. Движение и квесты не выполнялись.
ID110/206 nested остаются строгими historical parsers с проверкой конкретных
live bodies; весь формат новой сборки не объявлен подтверждённым.
[Профиль и границы результата](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-ENTRY-11316.md).

25 октября на 1.13.16 через HK исправлен игровой вход `bot-hk-test@vampir.top`
на Franz 2: Game Login 0, список с одним персонажем. Geo-поля свежего GMC2
теперь включаются по текущему SHA независимо от guard TID. Initial Ping
проверен отдельно и подключён к явному кандидату; periodic heartbeat не расширен.
Выбор и вход в мир этой попыткой не проверялись.
[Причина ошибки клиента и результат](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-GEO-FIX-11316.md).

Текущая цель — удерживать существующего персонажа `bot-hk-test@vampir.top`
на Franz 2 и обрабатывать команды движения с карты / из квестов в той же сессии.
Проверки 24 и 25 октября на 1.13.16 через HK прошли SDK / lobby / Game Version,
но Game Login вернул 16 до списка. Вход в мир и движение не выполнены.
[Результат, границы и следующий шаг](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-HK-EXISTING-CHARACTER-11316.md).

Цель — вход, персонажи, позиция, перемещение и сценарии без запущенной игры.
Общий вход в проект: [README Vampir](../vampir/README.md).
Актуальный порядок работ: [TASKS.md](TASKS.md).

Добавлена [локальная панель аккаунтов](ACCOUNT-CONSOLE.md): отдельные игровые и
почтовые пароли под DPAPI, регистрация Netmarble с кодом из почты, выбор сервера
и персонажа, отключение аккаунтов и не более двух отдельных рабочих процессов.
Проверены 84 локальных теста и интерфейс. Свежий EU-каталог с названиями
12 серверов загружен через панель без VPN; Prelude 2 отображается у обоих аккаунтов.
Живая регистрация через панель и
одновременный вход двух аккаунтов в мир ещё не подтверждены.
Основной EU-аккаунт через панель получил Game Login 0 и одного персонажа;
назначение сохранено по ключу. Первая попытка входа в мир остановилась на NID,
последующий запуск получил серверную позицию и статус «В мире».
[Проверка EU-сессии и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-EU-ACCOUNT-CONSOLE.md).
Подтверждённые списки теперь хранятся по аккаунтам и серверам,
сохраняются после перезапуска и не очищаются ошибкой следующей авторизации.

В цепочке `probe-selected-game-login.py` можно явно выбрать `--direct`
вместо `--socks-port`; в Python API передать `socks_port=None`.
Этот выбор действует для NID, SDK, лобби и игры, без изменения маршрутов ОС.
Прямой вход в прежнее лобби проверен. Для региональных лобби добавлены
`--region EU`, `NA`, `SG`: тот же выбор применяется к CDN endpoint и свежему
серверному списку. Свежий EU-каталог подтвердил Prelude 2 / ID 384.
Game Version принят; Login вернул 59 / BlockedInfo до списка персонажей.
[Живой результат и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-GLOBAL-EU.md).
[Native selector и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-LOBBY-REGIONS.md).
[Прямой маршрут и результат](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-DIRECT.md).

Периодический Ping подключён явно. Новая JP-проверка после ID 206 прошла
20 секунд: четыре периодических Ping, пять ID 17, ошибок нет. Сокет и маршрут
закрыты. Длительная сессия, движение, карта и reconnect ещё не проверены.
[Проверки heartbeat и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SESSION-KEEPALIVE.md).

В атлас подключён read-only слой сессии: live цель входа показана в мире 10010 /
Blood Pool. Вывод включается / выключается, «К персонажу» выбирает мир и центрирует
карту. Проверены 120 секунд сессии: 24 периодических Ping / 25 ID 17 без ошибок.
Маркер очищен после close, endpoint и маршрут закрыты. Это снимок цели входа;
непрерывное положение, живые сущности и движение ещё не подключены.
[Запуск, проверка UI и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-MAP-SESSION.md).

## Текущее состояние

Явный `--read-quest-list` отправляет один диагностический ID 1801 с полями
0 / 0 после ID 206. Он требует наблюдение, не совмещается с подтверждением
обучения и не повторяет запрос после неизвестного результата. В живой проверке
HONOR JP получен ID 1802 code 100; успешного списка нет, смысл отказа неизвестен.

Живой ответ выявил ошибку прежнего decoder: настоящий constructor создаёт
PktItemChangeList по +0x40, а replay задавал PktQuestData. Прежний вывод о
полном списке с группами отозван. Исправленный decoder поддерживает верхние
квесты / assets и пустые item changes; непустые изменения явно отклоняются.
Настоящий constructor / reader проверен на 27 телах и 131 коротком префиксе.
[Исправление, живой отказ и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LIST-CORRECTION.md).
[Фабрика пакетов и неизвестный штатный вызов](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-FACTORY.md).

Повторный вход через Redmi JP без отправки команды подтвердил сохранённое
изменение Tutorial 1001: raw0c / raw10 / state теперь 2 / 1 / 2 вместо 0 / 0 / 1.
Наблюдение 20 секунд прошло без ошибок; сокет и маршрут закрыты.
Это состояние обучения, выбор квеста и движение ещё не подключены.
[Повторный вход, поля ответа и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-PERSISTENCE.md).

Последняя живая проверка через новый Redmi M2006C3LG / JP прошла Login 0,
список / выбор и вход в мир с ID 206 code 0. После свежего ID 9905 сервер
принял одну команду обучения 1001 / 2: ID 9904 code 0, `accepted`.
Сокет и маршрут закрыты. Выбор квеста и автоматическое движение ещё не проверены.
[Живое подтверждение и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-ACK-ACCEPTED.md).

Добавлена явная диагностическая команда `--ack-initial-tutorial` в
`probe-selected-game-login.py`. Она требует `--read-world-start`,
`--read-world-finish`, выбора персонажа и `--observe-world-seconds`.
По умолчанию команда выключена. После успешного ID 206 и свежего ID 9905
этого соединения разрешена одна отправка ID 9903: tutorial 1001, step 2,
raw18 = 0. Локальный фильтр требует единственную запись 1001 со state 1,
raw0c 0 или 1, raw10 0 и flag false; возраст снимка — не больше 10 секунд.
Это диагностическая политика для наблюдавшегося начального состояния,
не воспроизведение неизвестного cached-поля Tutorial +0x50.

Очередь, полная передача кадра сокету и ответ сервера различаются. ID 9904
принимается как результат только после полной отправки и при совпадении
1001 / 2: code 0 — `accepted`, другой код — `rejected`. Ранний или чужой
ответ не подтверждает действие. Таймаут, обрыв и завершение наблюдения
при ожидаемом ответе дают `unknown`; повторной отправки нет, в том числе
для code 4223. Передача байтов сокету сама по себе не доказывает их обработку.

Локально проверена цепочка входа → ID 206 → ID 9905 → ID 9903 → ID 9904
через socketpair, а также частичная отправка, отказ, отсутствие ответа,
лимит очереди и очистка при обрыве. Живой сервер принял эту команду через
новый Redmi JP. Две прежние попытки через HONOR / Redmi JP остановились
на Game Login 58 / BlockedIp до отправки ID 9903.
[Сводки попыток и исправление диагностики каталога](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-INITIAL-TUTORIAL-ACK.md).
[Отдельная проверка привязки и прямого канала Pixel](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-PIXEL-CHANNEL.md).
Подтверждение шага не является кликом QuestPanel_PanelTouch,
не выбирает квест и не доказывает запуск автоматического движения.
[Основание полей запроса](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-REQUEST-WRITER.md),
[ответа](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-RESULT.md)
и [начального перехода](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STARTUP.md).
Проверки без авторизации и игровых действий:

```powershell
$env:PYTHONPATH='phone-exit/bots/vampir-shared;phone-exit/bots'
python -X utf8 -m unittest test_vampir_initial_tutorial_ack test_vampir_game_connection test_vampir_game_login_probe test_vampir_selected_game_login test_vampir_headless_send_drain.SocketPumpTests test_vampir_headless_send_b.OutboundStateTests
```

После замены телефонов 22 октября бот прошёл живые Login / список / выбор,
ID 204 → ID 205 → ID 206 code 0 через JP / TECNO TECNO KJ5n. Конечная серверная
целевая позиция получена; ошибки отсутствуют. Соединение и маршрут закрыты.
[Отчёт и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-WORLD-FINISH.md#живой-id-206-после-замены-телефонов).
Добавлен явный `--read-world-finish` вместе с `--read-world-start`,
`--read-character-list` и `--character-index`: после успешного ID 204 он
однократно отправляет ID 205 и ожидает полный ID 206. Это отдельная headless
политика подтверждения перехода без 3D streaming, а не исполнение engine callbacks.
Без нового флага прежняя остановка после ID 204 сохраняется.

`WorldEntryFlow.target_position` связывает мир из ID 204 с конечным вектором
из ID 206. Это серверная целевая позиция до коррекций движка; проекция на карту
и длительная готовность сессии ещё не подтверждены. При отказе, неверном ответе,
таймауте или закрытии приватные данные очищаются, повторной отправки нет.
Диагностический runner сохраняет только признак получения позиции, без координат.
[Native доказательства, локальные и живые проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-RELEASE-WORLD-FINISH-POSITION.md).

Ниже — история предыдущих отказов и исследований; текущий результат смотреть
также в [главном README](../vampir/README.md).

Актуальное продолжение после обновления 1.13.14: compiled tag исправлен,
SDK / лобби / Game Version приняты на JP и HK; Game Login вернул 16.
Затем добавлен один ранний Ping из свежего ответа лобби и текущего UTC для
проверенного нового EXE. Локальный порядок Version → Ping → Login → список
проверен. Живая JP-попытка с Ping снова дала Login 16; получен ID 17. Отдельная
диагностика по запросу пользователя отправила список ID 101 после отказа Login,
но за 10 секунд ID 102 не пришёл. Полный предварительный обмен и периодический
Ping остаются открытыми. Временные маршруты закрыты.
[Источники, проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-CLOCK.md#подключение-первого-ping-к-runtime).

Предыдущие этапы:

NID / SDK и выбранное лобби проходят вход. Реальный список серверов разобран;
Game Version принят. Прежний NID flow дал InvalidState 16; новый launcher flow
через два JP-телефона и HK дал BlockedIp 58 на Franz 2 / ID 256.
После следующей замены телефонов launcher flow на новом JP дал InvalidState 16;
со вторым новым JP прямой транспорт не установился.
Запрос персонажей не отправлялся. Рабочая сессия бота пока не получена.

21 октября пользователь создал Okly на Franz 2 и вошёл в мир официальным
клиентом. После закрытия игры бот через тот же выбранный JP-телефон снова
получил InvalidState 16. Три ключа устройства совпали с текущим хранилищем
Windows; причину отказа это сравнение пока не установило.

В последних попытках выбранное лобби ответило 10036. Отдельный native mapper
связал его с IsInspect / техническими работами; этот отказ возникает до Game
Login и не объясняет прежний InvalidState 16. Свежая страна и частичная metadata
подключены, но их достаточность для игрового входа пока не проверена.

Есть bounded codecs и состояния для списка / выбора персонажа, потокового
приёма, отправки и смены ключа. Они проверены локальными/native-сценариями;
полная цепочка на сервере после успешного Game Login ещё не пройдена.

## Где продолжать

- [Вход и устройство](../resource-tools/vampir/knowledge/topics/auth.md).
- [Сеть и runtime](../resource-tools/vampir/knowledge/topics/network.md).
- [Персонажи и позиция](../resource-tools/vampir/knowledge/topics/characters.md).
- [Текущие вопросы](../resource-tools/vampir/knowledge/questions.json).
- [Правила и поиск по функциям](../resource-tools/vampir/knowledge/README.md).

Рunners `probe-selected-game-login.py` и связанные probes — исследовательские
проверки, не готовый автономный бот. Источники и актуальные ограничения
описаны в тематических страницах. Секреты — только во время запуска,
локальные профили не коммитить. Запуск live probe требует действующего
явно выбранного транспорта и свежих проверенных snapshots.

`--auth-flow launcher` явно включает NID credential → launcher/token →
launcher/sign-in. Автоматического fallback нет. [Реальная проверка](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

`--language-code 1` явно выбирает английский язык в Game Login.
`--lobby-context sdk-with-joined-country` передаёт совпавшую свежую страну SDK / NID;
`sdk-with-partial-metadata` дополнительно собирает подтверждённые поля
metadata из текущих источников. Это неполный набор, не копия старой авторизации.
Для проверенной сборки 1.13.14 добавлен постоянный I_TID самого бота:
Windows CoCreateGuid, проверенный native формат, локальное SQLite-состояние.
Он переиспользуется при следующих входах; TID установленной игры не читается,
её SaveGame не меняется. Живая JP-проверка: metadata 262 байта, SDK / лобби /
Game Version приняты, Game Login снова 16. Временный маршрут закрыт.
[Происхождение полей и сравнительные проверки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) содержит прежний полный README,
включая старые команды и результаты. Старые статусы не заменяют текущую сводку.

</details>
