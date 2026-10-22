# Квесты, обучение, покупки и фарм

## Установлено

Есть графы Quest → Task → Action, связи обучения и UI, условия, ограничения,
награды и локальные проверки последовательностей экранного бота.
[Квестовые зависимости](../evidence/scenarios/QUEST-DEPENDENCIES.md),
[условия](../evidence/scenarios/CONDITION-PREDICATE.md),
[покупки](../evidence/scenarios/SHOP-REPLAY.md).

Данные содержат provenance таблиц и записей. Наличие строки или ссылки не
доказывает активное задание персонажа, выдачу награды или успешную покупку.
Слепые повторы действий со списанием ресурсов недопустимы без проверки результата.

## Открыто

Первый сетевой сценарий: выбрать место → построить путь → переместиться →
включить автобой → следить за здоровьем / целью / разрывами. Он ещё не выполнен.
Live состояние заданий, серверные переходы и контроль боя требуют успешной
сессии и позиции. Готовые графы использовать повторно, не извлекать заново без
изменения источников. NPC / навыки / предметы — [отдельная тема](game-data.md).

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Vampir: готовность типов условий](../evidence/scenarios/CONDITION-GATE.md)
- [Vampir: клиентская проверка ContentsLockCondition](../evidence/scenarios/CONDITION-PREDICATE.md)
- [Vampir: обновление контекста блокировок](../evidence/scenarios/CONDITION-STATE.md)
- [Vampir: имена числовых ContentsLockCondition](../evidence/scenarios/CONDITION-TYPES.md)
- [ContentsLock: поля загрузчика и вызовы проверки](../evidence/scenarios/CONTENTS-LOCK-FIELDS.md)
- [ContentsLock: условия открытия квестов и связи с наградами](../evidence/scenarios/CONTENTS-LOCKS.md)
- [Живое чтение состояния обучения](../evidence/scenarios/HEADLESS-LIVE-TUTORIAL-STATE.md)
- [Ожидающее действие квестовой панели](../evidence/scenarios/HEADLESS-QUEST-PANEL-ENTRY.md)
- [Подсказка обучения и запрос завершения шага](../evidence/scenarios/HEADLESS-TUTORIAL-ACTION-ROUTE.md)
- [Выбор строки и локальный переход обучения](../evidence/scenarios/HEADLESS-TUTORIAL-STEP-ADVANCE.md)
- [Reader состояния обучения ID 9905](../evidence/scenarios/HEADLESS-TUTORIAL-UPDATE-READER.md)
- [Vampir: разрешение обработки результата пакета](../evidence/scenarios/PACKET-RESULT-GUARD.md)
- [Vampir: зависимости квестов, обучения и интерфейса](../evidence/scenarios/QUEST-DEPENDENCIES.md)
- [Условия наград и геометрия из данных клиента](../evidence/scenarios/REWARDS-AND-LAYOUT.md)
- [Полная цепочка данных и исполнение Vampir](../evidence/scenarios/RUNTIME-CHAIN.md)
- [Проверка магазинного Guide на сохранённых кадрах](../evidence/scenarios/SHOP-REPLAY.md)
- [Vampir: регистрация обработчиков и события готовности](../evidence/scenarios/UNLOCK-REGISTRATION.md)
- [Vampir: от результатов разблокировки к списку разрешений](../evidence/scenarios/UNLOCK-RESULTS.md)
