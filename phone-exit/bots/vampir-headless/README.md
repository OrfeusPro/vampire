# Самостоятельный клиент Vampir

Цель — вход, персонажи, позиция, перемещение и сценарии без запущенной игры.
Общий вход в проект: [README Vampir](../vampir/README.md).
Актуальный порядок работ: [TASKS.md](TASKS.md).

## Текущее состояние

NID / SDK и выбранное лобби проходят вход. Реальный список серверов разобран;
Game Version принят. Прежний NID flow дал InvalidState 16; новый launcher flow
через два JP-телефона и HK дал BlockedIp 58 на Franz 2 / ID 256.
Запрос персонажей не отправлялся. Рабочая сессия бота пока не получена.

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

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) содержит прежний полный README,
включая старые команды и результаты. Старые статусы не заменяют текущую сводку.
