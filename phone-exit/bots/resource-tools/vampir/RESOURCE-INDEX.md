# Vampir: где искать данные

## GMC2 GET/header evidence, 19 октября

16 native header/method captures с source bytes/offsets/SHA, constructor name
prefix и build getter. Общий offline request plan совпал с captures.
[Источник/инструмент/границы](HEADLESS-GMC2-HEADERS.md).
Device/player getters synthetic, HTTP transport/auth не исполнялись.

## GMC2 URL assembly evidence, 19 октября

26 native fixtures: source offsets/bytes/SHA, getters, actual ASCII append,
явные allocation/copy/growth shims. Общий ASCII helper совпал по строкам.
[Инструмент/отчёт/границы](HEADLESS-GMC2-URL.md).
Active values/RequestGMC2 HTTP/response ещё не установлены.

## SDK bootstrap values, 19 октября

Native getters/initializers: SDK version5.2.11, BuildCode labels A/B/C,
256 входов byte проверены; source bytes/offsets/callsites сохранены.
[Отчёт/инструмент/ограничения](HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Game AppVersion/SDKZone — другие поля; active BuildCode не установлен.

## Публичная CDN-конфигурация и module descriptors, 19 октября

Отдельные immutable snapshots: реальный HTTPS CDN body (6000 bytes), разобранный
общим ядром, и четыре descriptor payload из base/patch. Zone=real/server REAL;
NnNetwork/NkPatchRuntime LoadingPhase=Default, descriptor слои совпали.
[CDN source/SHA/offline replay](HEADLESS-PUBLIC-CDN.md),
[module source/SHA/JSON pointers](HEADLESS-MODULE-DESCRIPTORS.md).
Active settings, module order и игровая сессия ещё не установлены.

Главная точка входа разработки: [README модуля](../../vampir/README.md).

Обновлено 19 октября 2026. Основная библиотека:
`F:/PhoneExit Resources/Vampir`. Данные клиента Windows — cooked-ресурсы,
а не исходный проект игры. Совпадение версии с Android не подтверждено.

## Startup callback конфигурации, 19 октября

Найден владелец FNnNetworkVar и immediate callback branch registration helper.
Восемь native fixtures подтверждают callback до registry insertion; есть
factory/vtable/source offsets и отдельная статическая patch init chain.
[Отчёт/инструмент/границы](HEADLESS-CONFIG-STARTUP.md).
Module/PAK/GConfig order и active INI ещё не доказаны.

## Game config основного архива и patch, 19 октября

Отдельный producer recover-base-game-config.py получил 12425 подтверждённых
путей основного ProjectRED-Windows.pak и два Game INI. Base 1.12.14/real/True
отличается от patch 0.1.1/dev/False; WindowsGame.ini совпал.
Оба snapshot сохранены отдельно. Порядок runtime-загрузки ещё не установлен.
[Source/SHA/сравнение/воспроизведение](HEADLESS-PAK-CONFIG-RECOVERY.md).

## Подтверждённый каталог pakchunk0 и Game config, 19 октября

Generated key callback и plaintext SHA1 main/full directories подтвердили
каталог 593 directories/7067 paths для archive SHA 7c1efc7b… . Это реальные
имена из PAK directory, не observed strings прежнего record scan. Отдельный
immutable snapshot содержит directory.json, DefaultGame.ini и WindowsGame.ini.
[Source/SHA/границы/исправление record hash basis](HEADLESS-PAK-CONFIG-RECOVERY.md).
Остальные архивы и прежние связи этим ещё не переиндексированы.

## Индексы обновлённых ресурсов, 19 октября

Построены свежие SHA-bound индексы всех 35 изменённых/новых архивов:
127 375 записей, ограниченный разбор без каталога PAK. Из pakchunk1 заново
извлечены 1565 CSV: 1267 точных совпадений со старым содержимым, 298 без
точного совпадения. Старые данные сохранены. [Результат, SHA и границы](CLIENT-RELEASE-INDEX.md).
U02 частичен; производные графы/карты ещё не обновлены, совместимость не доказана.

## Быстрый указатель

| Что нужно | Файл относительно библиотеки | Что подтверждено |
|---|---|---|
| Источники архивов и их изменения | `pc-pak-inventory.json`, `pak-extracted/<архив>/source.json` | Путь, размер, время изменения, выборочный отпечаток архива |
| Записи внутри PAK | `pak-extracted/<архив>/entries.json` | Номер записи, смещение, признаки формата и доступные внутренние пути |
| Все картинки и варианты | `archive-image-catalog.json` | Источник и хеш каждой экспортированной картинки |
| Предварительный выбор версии картинки | `archive-image-latest.json` | Выбор по наибольшему суффиксу `_sN`; сверка с телефоном обязательна |
| Карты | `map-image-catalog.json` | 1422 изображения; это не готовые маршруты |
| Атлас географии | `maps/atlas/index.json`, `maps/atlas/index.html`, `maps/atlas/worlds/` | 254 мира, 154 настройки, точки/NPC/квесты/порталы; [MAP-ATLAS.md](MAP-ATLAS.md). Nocturne Map10/11: native-проекция и 7 областей старого кадра; свежий Android/маршруты ещё не проверены |
| Скрины на большой карте | `maps/atlas/screenshot-study/index.json`, `coverage.jpg` | Один участок Krvna Nest: 463 детали, проверочный p95<1.3px; worldXY не доказаны |
| Rate callbacks и размещения добычи | `code-clues/loot-record-links.json`, `maps/loot/npc-locations.json` | 2 пустых callback, 4227 размещений 776NPC, точные фильтры Item/NPC+World; вероятность не доказана |
| Native-загрузка rates и обратные источники | `code-clues/loot-rate-evidence.json`, `maps/loot/item-origins.json` | Load3 таблиц/CRTatoi, 793Item/35211 цепочек; знаменатель шанса ещё не доказан |
| Предметы и добыча NPC | `maps/loot/index.json`, `maps/loot/index.html`, `item-icons-float/index.json` | 941NPC/793Item, 5827 предметов/3615 картинок. [NPC-LOOT.md](NPC-LOOT.md); rates сырые, не проценты |
| Общая карта Nocturne | `maps/nocturne-world.json`, `maps/nocturne-world.png` | 25 плиток, 10240×10240; происхождение плиток и проверка швов |
| Просмотр карт и интерфейса | `index.html`, локально http://127.0.0.1:17945/ | Поиск и галерея; сервер должен быть запущен |
| Деревья объектов интерфейса | `ui-layout-study/index.json`, указанные там JSON | 81 пакет WidgetBlueprint, включая WBP из TutorialUI; имена, типы и диапазоны сериализации |
| Открытые таблицы | `table-study/index.json`, `index-pakchunk1-Windows.json` | 125 CSV ProjectRED и 1565 CSV pakchunk1; SHA256, номера записей и смещения |
| Зацепки в собранном коде | `CODE-CLUES.md`, `code-clues/shipping-strings.json` | Загрузчики Quest/Tutorial CSV, поля задач и контролов, смещения строк в EXE |
| Зависимости и реальные строки квестов | `QUEST-DEPENDENCIES.md`, `quest-graph/index.json` | 1353 квеста, 5944 задачи; привязки TutorialStep к TutorialUI и WBP |
| Требования и награды | `REWARDS-AND-LAYOUT.md`, `quest-graph/rewards.json` | 1348 групп, 5759 записей наград; требования завершения квестов |
| Открытие контента и квестов | `CONTENTS-LOCKS.md`, `quest-graph/contents-locks.json` | 269 блокировок, 330 условий; числовая семантика ещё не восстановлена |
| Размеры и привязки из слотов | `REWARDS-AND-LAYOUT.md`, `ui-geometry/canvas-slots.json` | 2013 Canvas-слотов, 2 исключения; абсолютная геометрия ещё не подтверждена |
| Предварительные кандидаты квестовых ресурсов | `quest-data-candidates.json`, `quest-script-study/index.json` | Поисковые зацепки, а не доказательство наличия сценария |
| Кадры и координаты учебных действий | `phone-tests/index.json` | Копии диагностических кадров с SHA256; ручные и автономные действия различать |
| Исполняемый сценарий и шаблоны | Репозиторий: `phone-exit/bots/vampir/` | Фактическая логика бота; не восстановленный исходный код игры |

## Квесты и таблицы: найденные зацепки

Все номера ниже — поле `entry`, а не байтовое смещение. Точные смещения,
SHA256 распакованных CSV и отпечаток исходного PAK находятся в `table-study/index.json`.
Внутренние имена этих CSV неизвестны: зашифрованный индекс не расшифровывался.

- `ProjectRED-Windows-6080.csv`: Key/ValueType/Value. Настройки
  `Quest.StartQuestInfoId = 110110`, `Quest.LastQuestInfoId = 211910`,
  `Quest.GiveUpButtonUnlockQuestID = 110510`. Диапазон ID не доказывает,
  что все промежуточные числа являются заданиями или задают порядок прохождения.
- `ProjectRED-Windows-6078.csv`: пять строк описаний классов, поля
  `StartQuestId`, `HideGuideEffectQuestTaskId`.
- `ProjectRED-Windows-6099.csv`: английская локализация интерфейса, включая
  `MAINMENU_QUEST`, `QUEST_PROGRESS_VALUE_STATE_MINI`, `TUTORIAL_SKIP_POPUP_DESC`.
  Тексты интерфейса не задают последовательность действий квеста.
- `ProjectRED-Windows-6097.csv`: английская таблица заголовков.
- `ProjectRED-Windows-6106.csv`: английские сообщения ошибок.
- `ProjectRED-Windows-6201.csv`: 19 строк правил типов зон, поля
  `PossibleTutorialStart`, `OnEntryAutoCombat`, `EnableQuestType`,
  `LockOpenMap`, `WidgetInvisibleList`. Значения требуют отдельной интерпретации.

Данные заданий найдены в pakchunk1: Quest 1448, QuestTask 1454,
QuestTaskAction 1455, Tutorial 1551, TutorialStep 1555, TutorialUI 1556,
WorldSpot 1573. Схема и соединения: QUEST-DEPENDENCIES.md и quest-graph/index.json.
Английские имена квестов — запись 498, учебные подсказки — 543.
Текущий квест нельзя определять только по начальному ID из конфигурации:
исполнение графа и чтение стадии персонажа ещё не реализованы.

## Интерфейс: что читается, а что ещё нет

В `pakchunk500-Windows` найдены:

- entry 9164 — `WBP_TutorialUI`: `ButtonSkipRight`, `ButtonSkipLeft`,
  `CanvasPanelSkip`, `CanvasPanelWait`;
- entry 9152 — `WBP_TutorialFocusUI`;
- entry 9150 — `WBP_TutorialFocusFitEffectT`, `ButtonBlockTypeFit`;
- entry 9148 — `WBP_TutorialFocusDialogT`.

У JSON сохранены внутренние пути, ссылки на источник, имена экспортов,
размеры, диапазоны и SHA256. Поля layout сериализованы без проверенной схемы
unversioned properties: `geometry_schema_verified=false`. Имена кнопок помогают
найти ресурс, но пока не дают надёжных координат на разных экранах.
Рабочие нажатия определяются по кадру и шаблонам; координаты не переносить
из cooked-данных догадками.

## После обновления игры

Проверка магазинного сценария на кадрах: [SHOP-REPLAY.md](SHOP-REPLAY.md),
`phone-tests/shop-901030/bot-replay.json` (32 случая с хешами кода, шаблонов
и скриншотов). Прогон использует bot.py, а не подставленные found-флаги.
Кадра успешной покупки пока нет: результат остаётся неизвестным, повторы запрещены.

Пресеты масштаба и настройка: [UI-SCALE.md](UI-SCALE.md),
`ui-geometry/ui-scale-reference.json`: EOptionType::DisplayUIScale137 →
Option1429/record81 → OptionGroup32300 → SubTab32000 → MainTab30000;
константы 68/records329–353, подписи 488/record67. 25 коэффициентов в 5 профилях.
Default AOS=4, Win=2; активный масштаб телефона и DPI-кривая пока не установлены.
Ограниченный поиск конфигурации сохранён в `code-clues/ui-scale-config/index.json`.

Собственные размеры SizeBox: `code-clues/ui-properties.json` (16 свойств
из нативного массива EXE) → `ui-geometry/size-boxes.json` (2943 контейнера,
исключений 0 после разбора наследуемых полей) → `ui-catalog/<вариант>.json`, поля container_geometry
и size_constraints. Порядок извлечения и ограничения: [UI-CATALOG.md](UI-CATALOG.md).
Значение размера без bOverride не считать включённым ограничением.
ScaleBox: `ui-geometry/scale-boxes.json` (203 контейнера, исключений 0).
Нативные схемы общих свойств Widget и WidgetTransform также находятся в
`code-clues/ui-properties.json`; явные свойства подключены к контролам каталога.

Дополнительные производные отчёты (15 октября):

- `code-clues/native-enums.json`: 2020 групп, 11792 имени/числа с PE-смещениями;
  [NATIVE-SEMANTICS.md](NATIVE-SEMANTICS.md).
- `quest-graph/shop-tasks.json`: оба задания NpcShopBuy, категории, NPC,
  товары, цены, условия и неразрешённый ContentsLockKeyword=76.
- `ui-geometry/canvas-slots.json` и `panel-slots.json`: 4063 принятых слота;
  `topology.json`: порядок детей 1945 родителей из исходных массивов ссылок.
  [REWARDS-AND-LAYOUT.md](REWARDS-AND-LAYOUT.md) описывает ограничения схемы.

Эти отчёты расширяют первоначальный разбор имён экспортов выше, но не
подтверждают абсолютные координаты элементов на Android.

1. Сохранить прежнюю библиотеку; для нового снимка задать
   `PHONEEXIT_VAMPIR_RESOURCES` на новую папку.
2. Выполнить команды из README: инвентаризация → изображения → сборка карты →
   интерфейс → CSV → галерея. Сопоставить `source.json` старой и новой версии.
3. Сравнить внутренние пути и хеши содержимого. Номера записей и смещения
   могут измениться; не использовать их как постоянные идентификаторы.
4. Сверить шаблоны и карту с актуальным экраном Android. Обновить этот указатель
   и `bots/vampir.md`, указав фактические проверки и оставшиеся ограничения.

Полный SHA256 архива отличается от `sample_sha256`: последний вычислен только
по началу и концу архива. Ни один из них не заменяет проверку версии Android.

Nocturne XY→рельеф: `maps/atlas/projection.json`,
`code-clues/map-projection-evidence.json`, инструмент `build-map-projection.py`.
Происхождение/порядок/33 теста: [MAP-ATLAS.md](MAP-ATLAS.md).

Большая карта всех 36Nocturne-контекстов: `maps/atlas/nocturne.json`,
`nocturne-manifest.json`, главный `index.html`; прежний просмотр 254 миров —
`world.html`. Экспорт `nocturne-overview.png`10240×10635.
Инструменты `build-world-map.py`, `world-map*.js/html`, `render-world-map.py`.
Происхождение, 51 тест, исправление zoom и 25 плиток: [MAP-ATLAS.md](MAP-ATLAS.md).

Карточки NPC:`maps/atlas/monster-manifest.json`,`monsters/<ID>.json`,
`monster-verification.json`; сборщик `build-monster-details.py`.BattleCSV1545,
native-связь BattleGroupId, количество/условные цепочки: [NPC-LOOT.md](NPC-LOOT.md).
