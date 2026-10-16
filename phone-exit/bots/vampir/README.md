# Vampir — главный файл разработки

**Начинать здесь при любом продолжении работы над ботом Vampir.**
Обновлено 16 октября 2026. Исполняемая точка входа — `bot.py`, документационная
точка входа — этот файл. Здесь хранится карта проекта, подробности — по ссылкам.

**При продолжении читать [таблицу задач TASKS.md](TASKS.md):** выполненные работы,
частичные результаты, оставшиеся проверки и критерии завершения. После каждой
работы обновлять соответствующую строку; историю сохранять в журнале.

## Текущее состояние и следующий шаг

На Pixel 5 · JP установлена **1.0.22**, настройки редакции 4 применены.
Новый персонаж Zizak дошёл до уровня 6, задания 14. Покупка для Guide прошла:
75 Gold, одна бутылка. Бот на паузе из-за распознавания золотого фона завершённого
Guide; повторной покупки не было. Учёт персонажей разделён контекстом в данных.
Подробности: [PURCHASE-CONTEXT.md](PURCHASE-CONTEXT.md).

Кандидат **1.0.23**: варианты завершённого Guide и общий исполнитель действий
[QUEST-AUTOMATION.md](QUEST-AUTOMATION.md). 24 учебных правила и получение награды
используют общую проверку геометрии, ожидание, ограничение попыток и резерв до IPC.
Полный прогон прошёл: 239 тестов за 129,366 секунды. Живая проверка выполняется.
1.0.23 собрана, подписана и опубликована; установить пока не удалось: после
восстановления локального gateway Pixel отображается offline. Последнее состояние
телефона — пауза на 1.0.22 после покупки. Следующий шаг — проверить сборку на сохранённом reserved, затем продолжить
квесты. Полного универсального распознавания любых окон пока нет.

### История проверок

Кандидат **1.0.20** — [PASSIVE-HUD.md](PASSIVE-HUD.md): короткое наблюдение
уже подтверждённого автоквеста без нажатий. СвежиеHUD+auto_on,нетучебногоSKIP/
известныхпопапов;полныйпоисккаждые12сек. Неизвестныймаркерможетожидатьполного
поиска,немедленнаяреакцияналюбойновыйпопапнеобещается. Desktopкороткийпуть
845–878ms/36match вместо2559–3096ms/68match. Полныйпутьещёмедленный.


На Pixel5 установлена **1.0.19**,редакция3 применена. Ботпродолжаетработать:
Zizak **5-гоуровня**,KrynaNest. Послеобщегообработчикасумкисвежийкадрпоказывает
HUDбезинвентаря,quest_auto_running,errornull. Подробности [BAG-EXIT.md](BAG-EXIT.md).
Прошли2новыхкадровыхтеста+5роутера+25квестовыхрегрессий. ПолныйобычныйHUDпоиск
пока6833ms;оптимизацияповторныхучебныхшаговнеравнабыстромуHUDциклу.

СценасSKIPзакончиласьсама;общийskipбезподтверждениятипаэкранавключатьнельзя.
ДляCutsceneUI/MediaUIнайденыButtonSkip и геометрия,ноэтонедостаточнодля
отличенияотSKIPобучения. ОтдельнаязадачаV61,источникисохранены.

На Pixel5 установлена **1.0.18**, редакция3 применена. Свежий кадр после
исправления:Zizak **3-го уровня**,задание6 «To a safe location / Talk to Damir».
После завершения4002 бот продолжил цепочку без ручных игровых нажатий.
 Бот прошёл Adrenaline
по рамке (1.0.17), затем сам выполнил завершающий Tooltip4002018 и вернулся
к заданию3 «Talk to the Elottarvizian». Ошибка цели устранена. Последний статус
running,error=null;действиеquest_skip_scene1048ms.24 учебных привязки.
Проверки: полный прогон1.0.17 —215 тестов; затем2новыхкадровыхтестаBuff
и46регрессионных(квесты/каталог/связи)прошли. Не называть это полным217-прогоном.
Источники и ограничения: [ADRENALINE-FRAME.md](ADRENALINE-FRAME.md).
Кадры/статусыzizak-level1-2026-10-16; следующий короткийпрогон
zizak-after-drain-2026-10-16. Покупкиостаютсявыключены.

Новый прогон16октября:Zizak1→2уровня наPixel5. Общая1.0.15 сама прошла
начальныйдиалог,задание1,сюжетнуюсцену и обучениеDrain доAdrenaline в задании3.
Покупкивыключены. ИмяПК — только метаданные. Кадры вzizak-level1-2026-10-16.
Drainнаодномкадреscore0.816непрошёлпорог,нопозжепрежняя1.0.15распозналаи
продолжила. Установленная1.0.16добавляетточныевариантытекста75/100/125%,безснижения
порога/сменыисходногодействия4002004;4вариантакадрапрошли. Полнаяранняяцепь
ещёнепроверена;последнийкадрAdrenaline. Верификацияпри повторе—вручную.

На Pixel5 установлена **1.0.16**,213 тестов прошли. [ENHANCE-EXIT.md](ENHANCE-EXIT.md)
описывает быстрый маршрут окнаEnhance. Поиск наAndroid935ms(полныйtick1543ms
приcapture602ms). ЗатемиграразорваласессиюKICKOUT_FOR_INSPECT,ботподтвердил
сообщениеивсталнапаузу;титулподтверждёнкадром. УспешныйвозвраткHUDпосле
стрелкинеподтверждён. Пользовательсообщил,чтоожидаетсяповторноеподтверждение
телефона. Верификациюнеавтоматизировать,несчитатьодноразовой;автовходпонакругу
невключать. Следующаяживаяпроверкапослеручногоподтвержденияпользователем.

На Pixel5 установлена **1.0.14**,208 тестов прошли. [RECOGNITION.md](RECOGNITION.md)
описывает первый общий механизм: приоритет ожидаемого/предыдущего шага по данным
клиента,кеш только внутри кадра,поздняя проверкаHUD. Все кандидаты остаются для
запасного поиска;универсального классификатора любых окон ещё нет. Desktopповтор
известных шагов504–539ms;первое/неизвестное состояние наPixel5 пока5915–9495ms.
Не выдавать это за целевой цикл1сек во всех состояниях.

23 учебных привязки.1.0.13 сама открыла сумку,следующие выбор/описание/свиток
проверены диагностическими одиночнымиtap.1.0.14 сама выполнила финальный4007012:
потрачено2500Gold,броня+1,обучение завершилось. После него окноEnhance осталось
открытым,бот поставлен на паузу;следующий шаг — общий выход по связям UI,
затем продолжить квест. Доказательства tutorial4007-2026-10-16/result-plus1.jpg
иresult-status.json библиотеки. Полный автоматический проход всех четырёх
новых шагов наAndroidне проверен,только16масштабных кадровых случаев.

История: на Pixel5 · JP была установлена **1.0.12**, применена редакция3. После ручной
верификации устройства бот прошёл титул и GameStart выбранного персонажа,
загрузил мир, закрыл Guide-награду и продолжил задание18 Leave Shadow Grove.
Прогон остановлен на новом обучении4007; доказательства в библиотеке
phone-tests/quest-run-2026-10-16/. Полный проход поздних заданий не подтверждён.

Один универсальный entry.py для всех персонажей: общий титул и выбранный
персонаж, без профиля/фильтра имени или сервера. CharacterSelectUI.ButtonStart,
контроль124,Slot48,связи и кадр в character-entry-reference.json. Сервер/аккаунт/
персонаж бот не переключает. На ПК имя изменено на наблюдаемоеOrfPro(UgPhone),
это метаданные телефона, а не отдельный модуль.202 теста и кадровые варианты
входа75/100/125%+сдвиг прошли. Сборка/подпись/SHA проверены,пакет опубликован.

Квесты включены; покупки временно отключены quest_shop_enabled=false до
разделения учёта разных персонажей. Старый журнал не удалён. Обработчики
KICKOUT_FOR_INSPECT и idle подтверждены на телефоне в1.0.9/1.0.10.

Источники текущего состояния игры и границы доступа: [LIVE-STATE.md](LIVE-STATE.md).

**Приоритет: первоначальный прогон квестового сценария**, а не полный разбор клиента.
Порядок и границы: [FIRST-RUN.md](FIRST-RUN.md), задачи V38–V41.
Сначала собрать и проверить имеющиеся обработчики, затем пройти текущий участок
на Pixel 5. Если встретилось непонятное окно или действие — сохранить кадр,
статус и последний подтверждённый этап, найти связь в существующем индексе;
углублять исследование клиента только для этого препятствия.

Последнее исследование V37: [MESSAGE-NAMED-SLOT.md](../resource-tools/vampir/MESSAGE-NAMED-SLOT.md).
Схема наследования свойства59, анимация и dispatcher отложены до практической
необходимости. Неподтверждённые связи не становятся правилами клика.

На Google Pixel 5 · JP установлен Vampir **1.0.14**, Phone Exit 0.8.13,
Android-пакет игры `com.netmarble.thered`. OCR/ML Kit не использовать.
Игровые действия выполняются на телефоне, ПК управляет профилями и пакетами.

**Правило пользователя: сначала искать в данных клиента и их связях, затем
реализовывать и сверять с экраном.** Полный порядок закреплён в корневом AGENTS.md.
Для попапов начинать с UI-CATALOG.md и ui-catalog/index.json.

Подписанный пакет **1.0.8 опубликован в приватном каталоге и установлен**
на Pixel 5 · JP 16 октября 2026. SHA256 удалённого ZIP проверен.
Профиль первого запуска получен и применён, редакция2. Живой запуск распознал
`Connection terminated for safe gameplay` и перешёл в паузу:
`waiting_connection_terminated_inspect`, `source_text:KICKOUT_FOR_INSPECT`, error=null.
Пользователь подтвердил, что окно пока остаётся. Нажатий подтверждения и повторного
входа не выполняли. Короткий квестовый прогон V39 ожидает возврата в игровой мир;
это проверка обработчика сообщения, не прохождение квестов.
Доказательства: библиотека `phone-tests/first-run-2026-10-16/`.
Магазинный Guide901030 и журнал покупки входят в пакет; полный цикл покупки
на Android ещё не проверен. Ранее работали по сохранённым кадрам; текущий запрос
пользователя разрешил эту живую проверку.
Исправлены независимая проверка цифр суммы и синхронизация каталога
журнала. Полный offline-прогон bot.py: 32 сценария, включая 75/100/125%,
смещение, неверные/пропавшие значения и перезапуск после подтверждения.
Это не живая покупка и не подтверждение завершения квеста; см. SHOP-REPLAY.md.
Журнал хранится в `files/bots/vampir/vampir-purchases.json` вне версий пакета;
неизвестный результат блокирует повтор покупки даже после перезапуска/обновления.
Автоматической смены персонажа/сброса журнала пока нет: повтор того же задания
на другом персонаже этого телефона требует отдельного подтверждённого учёта.

Полная найденная цепочка данных включена в `quest-runtime.json`: 1353 квеста,
5944 задачи, 3892 записи действий игры, 139 учебных шагов, 94 UI-ключа.
**Полная цепочка данных не означает готовое прохождение всех квестов.**
Визуально поддержаны 18 учебных действий, пропуск подтверждённого диалога,
получение Guide-наград и несколько проверенных окон. Серверные действия из
таблиц бот не исполняет. На неизвестном экране ввод приостанавливается.

Последние подтверждения: персонаж дошёл до уровня 6, квеста 14; обучение
Bloodshape связано с Quest 110530 → Task 110530005 → Tutorial 4009.
1.0.5 сама выполнила Equip; 1.0.6 добавила выход из оставшегося окна.
1.0.7 установлена и запущена с обработкой Guide-наград; итог этого запуска
перед новым действием проверить по свежему статусу/кадру, не по старому тексту.
Последний целевой прогон `test_vampir*.py`: 180 тестов прошли
(включая PE, UI, пресеты масштаба и покупки).

Вход также исследуется по макетам: [ENTRY-FLOW.md](../resource-tools/vampir/ENTRY-FLOW.md),
`ui-geometry/entry-reference.json` в библиотеке — 10 окон / 20 вариантов.
Найдены отдельные ButtonStart титульной панели и выбора персонажа, выбор сервера,
состояния загрузки и ручной авторизации. `launch_buttons` пока пуст:
автоматический проход входа не включён без привязки к экрану/персонажу.
Ссылка TitleUI → TitlePanelUI подтверждена явным полем UserWidget в двух архивах.
Общий decoder проверил 958 отложенных панелей, нашёл 957 явных путей;
runtime-видимость и необработанные свойства из этих ссылок не выводятся.
Первые нативные ветви входа: [NATIVE-ENTRY.md](../resource-tools/vampir/NATIVE-ENTRY.md),
`code-clues/entry-code.json` — проверенные ссылки и инструкции с unwind-цепочками.
Внутренний Sequence не отождествлять с ELobbyState; GUI-переходы ещё не доказаны.
Кнопки титульной панели связаны с нативными полями и сравнениями:
[ENTRY-BUTTONS.md](../resource-tools/vampir/ENTRY-BUTTONS.md), 11 контролов / 12 сравнений.
Видимость элементов и полный путь события этим ещё не подтверждены.
Индекс ссылок кода на окна: [NATIVE-UI-LINKS.md](../resource-tools/vampir/NATIVE-UI-LINKS.md).
Поиск `query-native-ui.py WBP_Имя` возвращает источники и проверенные инструкции
без нового сканирования; перед выдачей сверяются хеши источников.
Получение и показ входных окон разделены в [ENTRY-WINDOWS.md](../resource-tools/vampir/ENTRY-WINDOWS.md).
Возвращённый объект окна и проверка bInitialized не означают его видимость
или готовность персонажа; семантика проверок UI-менеджера ещё уточняется.
Уточнение: проверка перед презентацией сама обрабатывает список окон и вызывает
методы найденного окна. Это не чистый IsVisible; см. [UI-MANAGER.md](../resource-tools/vampir/UI-MANAGER.md).

Каталог runtime referenceRevision=4 дополнен группами наград и ContentsLock,
двумя магазинными задачами и нативными именами типов. Перед покупкой shop.py
проверяет соответствие задаче, предмету/цене/количеству и SHA источников.
Семантика неизвестных условий блокировок не исполняется.

ContentsLock соединён с квестами и наградами: 269 блокировок, 330 условий,
109 ссылок квестов, отсутствующих блокировок/групп нет. Типы проверок,
сравнения и логика групп пока не восстановлены; evaluator не включён.
Барьер 110540 требует Guide 901030 Importance of Supplies с магазинной задачей,
а не только выдачи предыдущих наград. См. CONTENTS-LOCKS.md ниже.

Числовые типы задач, действий и наград теперь подтверждены массивами enum в EXE:
задача 901030010 — NpcShopBuy. Найдены категория 3, вкладка 5 и восемь товаров
с ценами и условиями. Обработчик одной покупки подготовлен в локальной 1.0.8;
живой результат ещё не подтверждён. Разобрано 4063 слота UI, порядок детей найден
для 1945 родителей на первом этапе. После расширения на весь найденный UI:
71985 слотов, 35632 родителя, 1764 уникальных ресурсных пути; 363 пути попапов.
Абсолютные координаты и runtime-видимость не доказаны. См. UI-CATALOG.md.

Следующая работа: локальная сборка → первый ограниченный прогон → фиксация
конкретной остановки. Полный evaluator ContentsLock и геометрия всех окон
не являются условием первого прогона. Правило поиска в источниках перед
изменением каждого обработчика сохраняется.

## Где код и за что он отвечает

| Файл | Назначение |
|---|---|
| [bot.py](bot.py) | Вход движка: foreground, запуск игры, захват, загрузка каталога, нормализация масштаба |
| [messages.py](messages.py), [IDLE-CONFIRM.md](IDLE-CONFIRM.md) | Явные ключи сообщений, однократное подтверждение и проверка результата |
| [entry.py](entry.py), [TITLE-ENTRY.md](TITLE-ENTRY.md) | Универсальный вход с текущим выбором аккаунта/сервера игры; Android-переход ещё не подтверждён |
| [quests.py](quests.py) | Распознавание этапов, ввод, ожидание результата, допустимая вариация кликов и задержек |
| [shop.py](shop.py), [shop-reference.json](shop-reference.json) | Покупка для конкретного Guide, сохранение неизвестного результата без повторного списания |
| [SHOP-REPLAY.md](../resource-tools/vampir/SHOP-REPLAY.md) | Прогон настоящего bot.py на кадрах, исходные/отрицательные случаи и границы проверки |
| [ui-window-reference.json](ui-window-reference.json) | Текстовые ключи, источники и отдельно помеченные кандидаты ресурсов окон |
| [vision.json](vision.json) | Шаблоны, области поиска, привязки к TutorialStep, известные окна |
| `templates/` | Снимки только проверенных элементов; не массовый экспорт всех ресурсов |
| [quest-runtime.json](quest-runtime.json) | Генерируемая полная цепочка; не редактировать вручную |
| [tutorial-reference.json](tutorial-reference.json) | Генерируемые привязки 18 действий к CSV с SHA256 и смещениями |
| [manifest.json](manifest.json) | Версия модуля, совместимость движка/настроек, разрешённый пакет |
| [defaults.json](defaults.json), [settings.schema.json](settings.schema.json) | Независимые настройки Vampir; без профилей других игр |
| [../test_vampir.py](../test_vampir.py) | Запуск, загрузка, распознавание готовности, смена разрешения |
| [../test_vampir_quests.py](../test_vampir_quests.py) | Последовательности, задержки, лаги, границы кликов, награды и защита от слепого ввода |
| [../test_vampir_source_links.py](../test_vampir_source_links.py) | Целостность ContentsLock, групп условий, сохранение флагов и отсутствие выдуманной семантики |

## Где источники и все связи

Библиотека на диске: **`F:/PhoneExit Resources/Vampir`**.
Установка клиента для исследования:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
Это собранный Unreal-клиент/cooked-ресурсы, не исходный проект разработчика.
Версия данных Windows пока не доказана равной версии Android.

| Что требуется | Читать в репозитории | Данные относительно библиотеки на F: |
|---|---|---|
| Быстро найти любой ресурс | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md) | `RESOURCE-INDEX.md` |
| Как повторить извлечение | [README инструментов](../resource-tools/vampir/README.md) | `RESOURCE-PROVENANCE.md` |
| Ссылки в собранном EXE | [CODE-CLUES.md](../resource-tools/vampir/CODE-CLUES.md) | `code-clues/shipping-strings.json` |
| Числовые типы, товары и условия покупки | [NATIVE-SEMANTICS.md](../resource-tools/vampir/NATIVE-SEMANTICS.md) | `code-clues/native-enums.json`, `quest-graph/shop-tasks.json` |
| Объявленные связи таблиц | [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md) | `code-clues/table-dependencies.json`, `quest-dependencies.md` |
| Квест → задача → обучение → контрол | [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md) | `quest-graph/index.json`, `early-quests.json` |
| Требования и награды | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `quest-graph/rewards.json` |
| ContentsLock и ранний барьер квеста | [CONTENTS-LOCKS.md](../resource-tools/vampir/CONTENTS-LOCKS.md) | `quest-graph/contents-locks.json`, `early-unlock-chain.json` |
| Геометрия Canvas-слотов | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `ui-geometry/canvas-slots.json` |
| Панели и порядок дочерних элементов | [REWARDS-AND-LAYOUT.md](../resource-tools/vampir/REWARDS-AND-LAYOUT.md) | `ui-geometry/panel-slots.json`, `topology.json` |
| Все найденные окна, попапы и контролы | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `ui-catalog/index.json`, JSON вариантов окон |
| Размеры самих SizeBox и флаги применения | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `code-clues/ui-properties.json`, `ui-geometry/size-boxes.json` |
| Наследуемые свойства и ScaleBox | [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md) | `ui-geometry/scale-boxes.json`, `container_geometry.decoded.inherited_properties` в каталоге |
| Пресеты UI Scale, default и поиск DPI | [UI-SCALE.md](../resource-tools/vampir/UI-SCALE.md) | `ui-geometry/ui-scale-reference.json`, `code-clues/ui-scale-config/index.json` |
| Имена и дерево экспортов UI | [inspect-ui.py](../resource-tools/vampir/inspect-ui.py) | `ui-layout-study/index.json` и JSON каждого пакета |
| Полные CSV и происхождение | [extract-tables.py](../resource-tools/vampir/extract-tables.py) | `table-study/index-pakchunk1-Windows.json` и `index.json` |
| Карты и картинки | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md) | `archive-image-latest.json`, `map-image-catalog.json`, `maps/` |
| Что исполняется, а что пока справочник | [RUNTIME-CHAIN.md](../resource-tools/vampir/RUNTIME-CHAIN.md) | `RUNTIME-CHAIN.md` |
| История и живые проверки | [../vampir.md](../vampir.md) | `PROJECT-STATE.md`, `phone-tests/` |

Главные записи `pakchunk1-Windows`: Quest 1448, QuestTask 1454,
QuestTaskAction 1455, **Reward 1475**, Tutorial 1551, TutorialStep 1555,
TutorialUI 1556, WorldSpot 1573. Английские тексты: Quest 498,
QuestTask 502, TutorialStep 543. Это номера записей, не смещения в байтах.
После обновления игры номера могут измениться: использовать хеши/схему.

## Порядок изменения сценария

1. Найти строку задания/обучения и её зависимости в графе. Сохранить ID,
   условия, источник и хеш. Для наград проверить и требования квеста, и Reward.
2. По TutorialUI найти WBPName → WidgetName → ControlName/ControlIndex/TargetId.
   По экспортам/слотам проверить геометрию; неизвестные родительские размеры,
   DPI, анимацию или видимость не подменять предполагаемыми координатами.
3. Снять свежий кадр, проверить подсказку и цель, добавить контролируемый обработчик.
   Предыдущий ID или координаты не являются разрешением следующего клика.
4. Связать действие с исходной строкой через build-tutorial-bindings.py.
   Сохранять ограничения, флаги и минимальные ожидания. Проверить случай задержки,
   временной потери цели, повторного кадра и смены размера экрана.
5. Запустить проверки. Увеличить версию; опубликованную версию не перезаписывать.
   Собрать подписанный пакет, затем установить/проверить на выбранном телефоне.
   Новые зависимости движка требуют APK. Секреты не писать в команды документации.
6. Обновить этот файл при изменении состояния/путей и подробный журнал результатов.
   Отдельно указать ручные действия, автоматические действия и непроверенные случаи.

## Основные команды из корня репозитория

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-native-enums.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-quest-graph.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-reward-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-canvas-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-panel-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-topology.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-ui-properties.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-size-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-scale-boxes.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-catalog.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-templates.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-binding.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-window-bindings.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-deferred-panels.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-entry-reference.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-scale-reference.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ui-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-shop.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-runtime-chain.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-tutorial-bindings.py
python -m unittest discover -s phone-exit/bots -p 'test_*.py'
powershell -NoProfile -File phone-exit/pc/build-bot-package.ps1 -Bot vampir
```

Генераторы используют библиотеку на F:, проверяют исходные хеши и не должны
молча менять данные игры. Для новой версии клиента сначала выполнить процедуру
из README инструментов. Массовые PNG/PAK остаются вне пакета и репозитория;
в модуль включается только необходимый производный справочник цепочки.

Обычный переход через easing: [UI-TRANSITION.md](../resource-tools/vampir/UI-TRANSITION.md).
Связаны настройка callback, tick и его завершение; полная отмена/reset
и соответствие Android ещё не доказаны.

Класс перехода связан с WBP_FaderUI через superclass imports и native vtable:
[FADER-CLASS.md](../resource-tools/vampir/FADER-CLASS.md). Одноимённый ImageFader
в WBP_MediaUI относится к другому native-классу.

ContentsLockCondition: [CONDITION-TYPES.md](../resource-tools/vampir/CONDITION-TYPES.md).
Native-конвертер подтвердил11 имён типов и связь со330 CSV-условиями;
Type1=CompletedQuest. Runtime evaluator ещё не включён.

Подтверждённые имена11 типов включены в quest-runtime.json referenceRevision3;
330 условий сохраняют исходные значения, неизвестные сравнения и AND/OR
не исполняются. Изменение источников блокирует сборку каталога до пересверки.
