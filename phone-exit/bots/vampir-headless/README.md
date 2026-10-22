# Самостоятельный клиент Vampir

Цель — вход, персонажи, позиция, перемещение и сценарии без запущенной игры.
Общий вход в проект: [README Vampir](../vampir/README.md).
Актуальный порядок работ: [TASKS.md](TASKS.md).

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
