# Самостоятельный клиент Vampir

Цель — вход, персонажи, позиция, перемещение и сценарии без запущенной игры.
Общий вход в проект: [README Vampir](../vampir/README.md).
Актуальный порядок работ: [TASKS.md](TASKS.md).

## Текущее состояние

Актуальное продолжение после обновления 1.13.14: compiled tag исправлен,
SDK / лобби / Game Version приняты на JP и HK; Game Login вернул 16.
Затем добавлен один ранний Ping из свежего ответа лобби и текущего UTC для
проверенного нового EXE. Локальный порядок Version → Ping → Login → список
проверен; новая live попытка ещё не выполнена. Полный предварительный обмен
и периодический Ping остаются открытыми.
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
`sdk-with-partial-metadata` дополнительно собирает шесть подтверждённых полей
metadata из текущих источников. Это неполный набор, не копия старой авторизации.
[Происхождение полей и сравнительные проверки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) содержит прежний полный README,
включая старые команды и результаты. Старые статусы не заменяют текущую сводку.
