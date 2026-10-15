# Vampir: зацепки в собранном коде

15 октября 2026. Источник:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
Размер 198145536 байт, полный SHA256:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

Метод: чтение ASCII/UTF-16LE из EXE без запуска, изменения или чтения памяти.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/shipping-strings.json`.
Смещения ниже — десятичные смещения строк в файле, не адреса функций.
Имена функций подтверждают ссылки в клиенте, но не раскрывают реализацию.

## Квесты

| Смещение | Строка | Зацепка |
|---|---|---|
| 161103160 | `Quest.csv` | Ожидаемое имя таблицы |
| 161103224 | `FRdQuestInfoManagerTemplate::Load` | Загрузчик |
| 161103376 | `PreQuestId` | Связь с предыдущим заданием |
| 161103528 | `QuestInitParam` | Параметр инициализации |
| 161105254 | `Quest/101_Quest_Main_Krvna00.xlsx` | Ссылка на авторский XLSX в диагностике; самого файла пока нет |
| 161114792 | `QuestTask.csv` | Задачи внутри задания |
| 161115016 | `TargetSpotInfoId` | Ссылка на точку |
| 161115040 | `AutoQuest` | Поле автоматического выполнения |
| 161115168–161115216 | `QuestActionPosX/Y/Z`, `QuestActionRadius` | Позиция и радиус, пока без численных значений |
| 161116438 | `World/WorldSpot.xlsx` | Источник описаний точек |
| 161116826 | `World/Area.xlsx` | Источник областей |

Другие таблицы: QuestSequence.csv (161112024), QuestTaskAction.csv (161113776),
QuestLimit.csv (161109848), QuestType.csv (161117088). У последовательности
встречается ActId, у действия — TaskId. Связи нужно подтвердить строками данных.

В EXE перечислены состояния EQuestState: Locked, NotStarted, Progressing,
Failed, Completable, Completed. Типы EQuestTaskType включают VisitNpc,
VisitPlace, KillMonster, Teleport, CutScene, Tutorial, UIEnter, ItemUse,
NpcShopBuy и другие. Перечисление типов не даёт текущего состояния персонажа.

## Обучение и контролы

| Смещение | Строка |
|---|---|
| 161255488 | `TutorialStep.csv` |
| 161255744 | `TutorialId` |
| 161255760 | `ServerProcessRequest` |
| 161255784 | `TaskParam` |
| 161255800 | `SkipButtonMove` |
| 161255816 | `SkipButtonHide` |
| 161255832 | `ArrowHide` |
| 161255848 | `CloseAllPopUp` |
| 161257424 | `TutorialUI.csv` |
| 161257656 | `WBPName` |
| 161257664 | `ControlName` |
| 161257680 | `ControlIndex` |
| 161257696 | `BlockType` |
| 161257712 | `DisableDim` |

Это зацепка для связки «этап обучения → WBP → именованный контрол».
В ui-layout-study уже разобраны WBP_TutorialUI и связанные виджеты.
Сами строки TutorialStep/TutorialUI и схема геометрии ещё не получены.

Диагностика менеджера: FRdTutorialManager::ClearTutorialStep() (163966016),
StopTutorial() (163966144), Server Tutorial Step > Client Tutorial Step
(163966400), Tutorial Id : %d , Step : %d (163966552),
FRdTutorialTaskBase::_CheckActivateStep() (163966752), UIKey : %s (163966840).
Строка о серверном шаге указывает на сравнение состояний; условия и протокол
синхронизации не восстановлены.

## Поиск самих значений

**Дополнение: таблицы найдены в pakchunk1-Windows.pak.** Предыдущий поиск
ниже охватывал пять других архивов, поэтому дал отрицательный результат.

`table-study/index-pakchunk1-Windows.json` содержит 1565 открытых CSV.
Главные записи: Quest 1448, QuestTask 1454, QuestTaskAction 1455,
Tutorial 1551, TutorialStep 1555, TutorialUI 1556, WorldSpot 1573.
Английская локализация: Quest 498, QuestTask 502, TutorialStep 543.
В индексе есть смещения, SHA256 и отпечаток исходного архива.
Названия таблиц установлены по схеме и диагностике загрузчиков; исходные
имена файлов из зашифрованного индекса PAK не читались.

Проверенные зависимости и пример обучения:
[QUEST-DEPENDENCIES.md](QUEST-DEPENDENCIES.md).
Машинный граф: `quest-graph/index.json`, короткие примеры: `early-quests.json`.
Старая формулировка о ненайденных значениях относится к первому проходу.

find-quest-tables.py проверил 16180 незашифрованных декодируемых записей
в ProjectRED-Windows, pakchunk0, pakchunk0_s1, pakchunk0_s2 и pakchunk100.
Точных ключей из списка скрипта не найдено; ошибок декодирования 0.
Результат: `code-clues/quest-table-search.json`.

Это ограниченный отрицательный результат: зашифрованные записи, uasset,
текстуры и записи вне 128 байт–64 MiB пропущены. Данные могут иметь бинарный
формат без названий колонок, находиться в другом архиве или загружаться отдельно.
Нельзя заключать, что таблицы отсутствуют или обязательно зашифрованы.

Расширенный проход завершён: 106 архивов, 149004 проверенные записи,
4 совпадения в pakchunk1, ошибок декодирования 0. Отчёт:
`code-clues/quest-table-search-all.json`. Затем из pakchunk1 извлечены все
1565 открытых CSV, включая TutorialUI, найденный по схеме колонок.

Следующий шаг после построения графа: проверить числовые типы учебных задач,
дочерние контролы и геометрию, затем использовать граф для подтверждаемого
распознавания стадии на телефоне. Наличие таблиц не означает, что этот механизм
уже встроен в бота. Координаты в пикселях не заполнять догадками.
