# Персонажи, выбор и вход в мир

## Установлено

Прослежены LoginResult handler, lifecycle selection service, запрос списка,
codecs ответа и переходы выбора / world move. Для сложных коллекций есть
bounded native-сценарии; семантика проверенной ветви отделена от неизвестных
полей и активного состояния сервера.
[Граница запроса](../evidence/characters/HEADLESS-CHARACTER-LIST-BOUNDARY.md),
[decoder выбора](../evidence/characters/HEADLESS-CHARACTER-SELECT-DECODER.md),
[world start](../evidence/characters/HEADLESS-WORLD-MOVE-START-PIPELINE.md).

21 октября пользователь создал Okly на Global 2 / Franz 2 и вошёл в мир
официальным клиентом через JP; на экране видны уровень 1 и Blood Pool.
[Наблюдение](../evidence/network/HEADLESS-OFFICIAL-CLIENT-JP.md).

## Открыто

Бот ещё не получил реальный список персонажей: Game Login отклоняется раньше.
Создание и вход официальным клиентом подтверждены; выбор ботом, world position
и живое перемещение бота не выполнены.
Наличие decoder или видимого Class Selection не доказывает создание персонажа.
После принятого Game Login получить список существующих персонажей и выбрать
созданного Okly. Автоматически создавать ещё одного персонажа не требуется.

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Список и выбор персонажа: owner и ограниченные body codecs](../evidence/characters/HEADLESS-CHARACTER-CODECS.md)
- [После LoginResult: сброс состояния и отдельный запрос персонажей](../evidence/characters/HEADLESS-CHARACTER-LIST-BOUNDARY.md)
- [Прямой caller slot 90 → CharacterListRead](../evidence/characters/HEADLESS-CHARACTER-LIST-CALLER.md)
- [ID102: вложенные схемы, обработчик и предпочтительный индекс](../evidence/characters/HEADLESS-CHARACTER-LIST-EXTENSIONS.md)
- [ID110: непустые массивы, 20 октября 2026](../evidence/characters/HEADLESS-CHARACTER-SELECT-COLLECTIONS.md)
- [Ответ выбора персонажа: таблицы и общий декодер](../evidence/characters/HEADLESS-CHARACTER-SELECT-DECODER.md)
- [ID110: производный менеджер и переопределённый метод](../evidence/characters/HEADLESS-CHARACTER-SELECT-DERIVED-MANAGER.md)
- [Обработчик ответа выбора персонажа](../evidence/characters/HEADLESS-CHARACTER-SELECT-HANDLER.md)
- [После ID110: условная отправка PktOptionSet](../evidence/characters/HEADLESS-CHARACTER-SELECT-OPTION-SEND.md)
- [Продолжение ID110: отдельный менеджер и обход получателей](../evidence/characters/HEADLESS-CHARACTER-SELECT-POST-MANAGER.md)
- [ID110: минимальное тело и raw spatial vector, 20 октября 2026](../evidence/characters/HEADLESS-CHARACTER-SELECT-RESULT.md)
- [ID109: реальные callers, источники полей и кадр](../evidence/characters/HEADLESS-CHARACTER-SELECT-SEND.md)
- [Внешность: поиск definition и ключ числового JSON-поля](../evidence/characters/HEADLESS-CREATE-APPEARANCE-ENTRY.md)
- [Внешность: входы генератора JSON и VoiceType](../evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-INPUTS.md)
- [JSON внешности: числовые ключи, культура и переносимый builder](../evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md)
- [Внешность: native map insert / update и фильтр preset](../evidence/characters/HEADLESS-CREATE-APPEARANCE-MAP.md)
- [Внешность: создание owner и сброс перед preview](../evidence/characters/HEADLESS-CREATE-APPEARANCE-RESET.md)
- [Внешность: preset → ползунок → float в записи owner](../evidence/characters/HEADLESS-CREATE-APPEARANCE-SLIDER.md)
- [BoneGroup F / M: точные имена файлов текущего PAK](../evidence/characters/HEADLESS-CREATE-BONEGROUP-DIRECTORY.md)
- [Текущие BoneGroup F / M: группы и ID внешности](../evidence/characters/HEADLESS-CREATE-BONEGROUP-RESOURCES.md)
- [Выбор класса: тип из тега и ID найденной строки](../evidence/characters/HEADLESS-CREATE-CLASS-LOOKUP.md)
- [Источник класса и начальной внешности](../evidence/characters/HEADLESS-CREATE-CLASS-SOURCE.md)
- [Текущая таблица классов и Carnage](../evidence/characters/HEADLESS-CREATE-CURRENT-CLASSES.md)
- [Текущие пресеты Carnage: ссылки, значения и неполные defaults](../evidence/characters/HEADLESS-CREATE-CURRENT-PRESETS.md)
- [CharacterCustomizeUI: constructor scale 1000 и путь создания CDO](../evidence/characters/HEADLESS-CREATE-CUSTOMIZE-SCALE.md)
- [Пол: Male 0 → M, Female 1 → F](../evidence/characters/HEADLESS-CREATE-GENDER-PATHS.md)
- [Живой контроль создания: остановка на SDK и исправление wrapper](../evidence/characters/HEADLESS-CREATE-LIVE-PREFLIGHT.md)
- [Пресет: немедленное завершение, очередь и шаблон asset](../evidence/characters/HEADLESS-CREATE-PRESET-COMPLETION.md)
- [Пресеты внешности: обнуление новой памяти и граница копирования defaults](../evidence/characters/HEADLESS-CREATE-PRESET-DEFAULT-COPY.md)
- [Пресет внешности: initializer, базовые constructors и postconstruct](../evidence/characters/HEADLESS-CREATE-PRESET-INITIALIZER.md)
- [Обычный объект пресета: constructor, перенос defaults и модельная проекция](../evidence/characters/HEADLESS-CREATE-PRESET-OBJECT.md)
- [Целый producer создания: класс, ник, внешность и ID 104](../evidence/characters/HEADLESS-CREATE-PRODUCER.md)
- [Целое чтение запроса создания персонажа](../evidence/characters/HEADLESS-CREATE-REQUEST-READER.md)
- [Запись запроса создания и переносимый encoder](../evidence/characters/HEADLESS-CREATE-REQUEST-WRITER.md)
- [Ответ создания ID 104: целый handler и решение runtime](../evidence/characters/HEADLESS-CREATE-RESULT-HANDLER.md)
- [ID 104: чтение результата создания](../evidence/characters/HEADLESS-CREATE-RESULT-READER.md)
- [Создание в сессии: пустой список, одна отправка и неизвестный исход](../evidence/characters/HEADLESS-CREATE-SESSION-FLOW.md)
- [Worker создания и постоянный журнал попытки](../evidence/characters/HEADLESS-CREATE-WORKER-JOURNAL.md)
- [Пустой список и отдельный запрос создания персонажа](../evidence/characters/HEADLESS-EMPTY-LIST-CREATION-ENTRY.md)
- [Выбор персонажа после принятого списка](../evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md)
- [Vampir: живое завершение входа в мир](../evidence/characters/HEADLESS-LIVE-WORLD-FINISH.md)
- [Завершение входа и путь позиции на текущей сборке](../evidence/characters/HEADLESS-RELEASE-WORLD-FINISH-POSITION.md)
- [ID110: объект персонажа и поиск справочной записи](../evidence/characters/HEADLESS-SELECTED-PLAYER-RECORD.md)
- [Selection service: события и границы перехода](../evidence/characters/HEADLESS-SELECTION-LIFECYCLE.md)
- [Сервис выбора: derived slots и CharacterSelect handoff](../evidence/characters/HEADLESS-SELECTION-SERVICE.md)
- [Selection state: native lookup и граница реальных данных](../evidence/characters/HEADLESS-SELECTION-STATE-LOOKUP.md)
- [Selection service: state2 и отложенное действие](../evidence/characters/HEADLESS-SELECTION-STATE-TRANSITION.md)
- [Кто читает состояние сервиса выбора](../evidence/characters/HEADLESS-SELECTION-STATUS-CONSUMER.md)
- [Состояние сервиса после выбора персонажа](../evidence/characters/HEADLESS-SELECTION-STATUS.md)
- [WaitingEndNotify → CharacterListRead: подтверждённый инициатор](../evidence/characters/HEADLESS-WAITING-END-CHARACTER-REQUEST.md)
- [Владелец загрузки и запрос завершения перемещения](../evidence/characters/HEADLESS-WORLD-FINISH-OWNER.md)
- [Условие смены уровня: сравнение LevelPath](../evidence/characters/HEADLESS-WORLD-LOAD-PREDICATE.md)
- [ID206: полный декодер и чтение до обработчика](../evidence/characters/HEADLESS-WORLD-MOVE-FINISH-DECODER.md)
- [ID206: минимальное тело ответа и границы чтения](../evidence/characters/HEADLESS-WORLD-MOVE-FINISH-READER.md)
- [Запрос завершения перемещения: ID 205](../evidence/characters/HEADLESS-WORLD-MOVE-FINISH-SEND.md)
- [Ответ завершения перемещения и состояние сервиса](../evidence/characters/HEADLESS-WORLD-MOVE-FINISH.md)
- [ID204: чтение, обработчик и продолжение перемещения](../evidence/characters/HEADLESS-WORLD-MOVE-START-PIPELINE.md)
- [Начало перемещения: ID204 и параметры загрузки](../evidence/characters/HEADLESS-WORLD-MOVE-START.md)
- [Вызов владельца из функции движка](../evidence/characters/HEADLESS-WORLD-OWNER-DISPATCH.md)
- [Фабрика владельца через GameInstance](../evidence/characters/HEADLESS-WORLD-OWNER-PROVIDER.md)
- [Классы владельцев загрузки и данные GameMode](../evidence/characters/HEADLESS-WORLD-OWNER-RESOURCES.md)
- [Raw 2 → World.Id 2 → уровень CharacterSelect](../evidence/characters/HEADLESS-WORLD-STATE-LABEL.md)
