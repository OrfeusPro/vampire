# Атлас Vampir

17 октября 2026. Продолжение V13: единый справочник географии и локальный
просмотрщик. Главный указатель: [README бота](../../vampir/README.md).

## Полученный результат

Библиотека: `F:/PhoneExit Resources/Vampir/maps/atlas/`.
`index.html` — просмотрщик, `index.json` — индекс и источники,
`tables.json` — полные исходные строки выбранных таблиц,
`worlds/<World.Id>.json` — связи и данные конкретного мира.
Массовые данные остаются вне Git, APK и опубликованного модуля.

Сборка проверила SHA256 всех 17 CSV, 1422 PNG, собранного Nocturne и EXE,
из которого ранее извлечены диагностические объявления связей. Проверены
совпадения хешей 25 плиток сборки Nocturne с текущим каталогом изображений.
В индексе сохраняются путь PAK, его версия формата/отпечаток, entry,
байтовое смещение CSV, SHA256, исходная схема и число записей. У каждой строки
есть `provenance.table/entry/csv_record`; номер CSV — номер записи с учётом
заголовка, не физическая строка при многострочных значениях.
Версия Windows-данных не доказана равной установленному Android.

| Таблица | entry pakchunk1-Windows | Записей |
|---|---:|---:|
| World | 1568 | 254 |
| Map | 1394 | 154 |
| WorldSpot | 1573 | 588 |
| Area / AreaBox | 9 / 10 | 501 / 1460 |
| Waypoint | 1566 | 69 |
| NpcSpawn / Npc | 1546 / 1544 | 61307 / 5285 |
| GadgetSpawn / Gadget | 1542 / 1541 | 1685 / 744 |
| QuestTask | 1454 | 5944 |
| QuestName_en / QuestTaskName_en | 498 / 502 | 1689 / 8339 |
| WorldType | 1574 | 19 |
| MapIcon / MapIconLayer | 1570 / 1571 | 51 / 30 |
| NavigationTestCase (рабочее название по схеме) | 1576 | 5160 |

`tables.json` содержит и записи без разрешённой связи с миром.
Повторяющиеся ID локализации сохранены массивами; произвольный выбор последнего
перевода не выполняется. 59 различных MapResource. Папка текстур сопоставляется
точно и с учётом регистра; Fog не смешивается с базовой картой.

## Связи и их границы

- World.MapId → Map.Id → точный родительский путь текстур MapResource.
  Это структурное сопоставление полей и ресурсов. Native-загрузчик карт,
  порядок нумерованных плиток и преобразование координат не восстановлены.
- WorldSpot.WorldInfoId → World.Id; QuestTask.TargetSpotInfoId → WorldSpot.Id;
  QuestTask.AreaInfoId → Area.Id; Area.TeleportSpot → WorldSpot.Id;
  Area.Waypoint → Waypoint.Id; Waypoint.TeleportSpot → WorldSpot.Id;
  Waypoint.GadgetSpawnInfoId → GadgetSpawn.Id. Для объявленных связей сохранены
  точные строки диагностики и EXE-смещения из `table-dependencies.json`.
- NpcSpawn/GadgetSpawn.WorldInfoId связывает размещения с миром; исходные
  группы, quest-visible поля, радиусы, периодичность, ограничения и условия
  сохранены без вычисления серверного состояния. NpcSpawn.NameEN берётся из
  связанной Npc-записи, без OCR. PositionGroupId не раскрыт; базовая позиция
  не всегда доказывает действительное место появления.
- Порталы сохраняют CostType/CostParam/CostValue, TeleportUse, DefaultActivate,
  тип, GadgetSpawnInfoId и полную запись назначения. Это данные возможных
  переходов; доступность персонажу и списание валюты не исполняются.
- Навигационные тестовые случаи — входные координаты и имя файла навигации.
  Отсутствуют результаты/пути; выдавать пары sx/sy → ex/ey за рёбра нельзя.
- GroundDistance/CenterX/CenterY/MapTextureReadingStandard сохранены сырыми.
  Их имена сами по себе не доказывают формулу мир → пиксели.

Координатная схема показывает исходные X/Y отдельно от картинки. X направлен
вправо, Y вниз только как оси схемы. Наложения точек на текстуры нет.
Круги NPC — записи размещения, не текущие живые существа. Цели квестов на схеме
показываются по связанному TargetSpot, а QuestActionPos и радиус доступны
отдельно в исходных данных. Все задачи сохранены, даже без точки на схеме.

## Обнаруженные проблемы (91 запись)

- 80 NavigationTestCase ссылаются на отсутствующие World.Id; записи сохранены.
- 6 тестовых миров ссылаются на отсутствующий Map.Id=3.
- 5 MapResource `Dungeon/Abyss/AbyssofCreation_01..05` не имеют точного
  родительского пути текстур: есть кандидаты `AbyssOfCreation_01..05`.
  Разницу регистра не исправляем автоматически.

Это проблемы/неполнота снимка данных, не 91 ошибка выполнения бота.
Полные исходные ID и строки — `index.json:issues`.

## Воспроизведение

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-map-atlas.py
python -m unittest discover -s phone-exit/bots -p test_vampir_map_atlas.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/query-map-atlas.py --world 10012
python -X utf8 phone-exit/bots/resource-tools/vampir/query-map-atlas.py --spot 10012023
python -X utf8 phone-exit/bots/resource-tools/vampir/query-map-atlas.py --quest 110150
python -m http.server 17946 --bind 127.0.0.1 --directory 'F:/PhoneExit Resources/Vampir'
```

Адрес просмотра: `http://127.0.0.1:17946/maps/atlas/index.html`.
Сервер только на loopback; остановка Ctrl+C в его терминале.
Путь библиотеки переопределяется `PHONEEXIT_VAMPIR_RESOURCES` либо `--root`
у генератора/запроса. Запросы проверяют хеш производного JSON; для сверки
с изменившимися CSV/PNG/EXE повторить сборку. Автоклики отсутствуют.

## Проверено / следующий этап

9 отдельных тестов прошли: SHA, дрейф схемы, неполные строки CSV,
дубли ключей, варианты переводов, границы групп текстур,
запросы spot/quest и отказ при изменении производного JSON.
Полная сборка на библиотеке прошла. В браузере проверены Nocturne,
слой NPC, поиск Quest110150 и просмотр исходной записи, фильтр BloodFortress,
масштаб150% и возврат к100%. Дополнительно прошли5 прежних тестов связей;
сверены хеши всех254JSON миров и tables.json, живые локальные запросы
Quest110150 → Spot10012023 → World10012. Отчёт: maps/atlas/verification.json.
Изменений Android-модуля/версии и публикации не было.

Локальный управляющий API `127.0.0.1:17842` при проверке 17 октября недоступен
(connection refused). Это не доказывает offline самого Pixel5.
Сохранённый `phone-exit/.tools/vampir-world-map.jpg` показывает Krvna Nest,
но не является свежей калибровкой. Нажатий в игре не выполняли.

Чтобы завершить V13 для автономной навигации, требуется:

1. Подтвердить native-формулу и порядок плиток либо выполнить калибровку по
   нескольким доказанным точкам, со сверкой на независимых точках.
2. Проверить ту же карту, DPI/масштаб, видимость, положение персонажа и
   преобразование экранных координат на свежих кадрах Android.
3. Восстановить проходимость/переходы и ограничения, затем проверить движение
   и результат. Прямую линию между точками не считать проходимым маршрутом.
4. После этого интегрировать выбор точек/маршрутов в модуль и панель ПК,
   собрать и проверить на телефоне. Сейчас `navigation_ready=false`.


## Совмещение прежнего скрина с большой картой, 17 октября

Проверены93 уникальных изображения из библиотеки phone-tests и корневых
vampir*.jpg/png в .tools. Среди них один уверенный World Map:
`phone-exit/.tools/vampir-world-map.jpg`, SHA256
`6993646efeec8d89b770cf82b50f50d51e3e312a4ca81472e895e31950cc3e20`.
Это исторический Pixel5/JP кадр1280×720 около Krvna Nest.

Он сопоставлен с полной картой Nocturne10240×10240 через SIFT рельефа,
фильтр повторных точек и RANSAC similarity. 474 уникальных соответствия,
463 согласованных; обучение и проверка разделены по клеткам снимка.
Медиана проверки0.3775px большой карты,95-й процентиль1.2467px.
Это проверочные клетки того же кадра, не второй независимый кадр Android.
Поддержанная изображением область занимает около0.889% площади атласа.
Фон всей карты взят из ресурсов клиента; он не объявлен весь проверенным Android.

Результат в `maps/atlas/screenshot-study/index.json`: SHA исходного кадра/атласа,
матрица screenshot_to_atlas, полигоны поддержки и метрики. Рядом сохранены
копия исходника, RGBA-фрагмент с patch_origin, такой же crop из ресурсов,
сравнение рядом и coverage.jpg с мятным контуром на большой карте.
Все три представления доступны в списке текстур атласа, группа «Скриншоты».
Исходные изображения игры и скрин не изменены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/register-map-screenshot.py phone-exit/.tools/vampir-world-map.jpg phone-exit/.tools/vampir-world-current.jpg
python -X utf8 phone-exit/bots/resource-tools/vampir/build-map-atlas.py
```

Последний HUD-кадр отклонён по отсутствию заголовка карты. Новые корректные
кадры добавляются по SHA к прежним наблюдениям той же версии атласа;
проверяется сохранённый оригинал и хеш фрагмента. При смене атласа не смешивать
наблюдения: использовать новый снимок библиотеки. Скрипт не предполагает,
что сдвиг/масштаб карты на следующем кадре останутся прежними — оценивает заново.
5 тестов прошли: сдвиг/масштаб, выбросы, чужие точки, узкая концентрация,
недопустимый поворот. Это привязка изображений, не worldXY и не путь движения.
Клик по выбранной NPC-записи на координатной схеме теперь даёт ссылку на
[каталог добычи](NPC-LOOT.md); сама схема по-прежнему отдельно от текстуры.


## Мир XY → Nocturne и источники предмета, 17 октября

Для Map.Id10/11 получена отдельная проверяемая проекция. Она применяется к36
мирам с этими MapId (17488 исходных NPC-размещений). В `maps/atlas/projection.json`
сохранены параметры, матрица, границы, точные записи Map и проверка старого кадра.
`navigation_ready=false`, `fresh_android_verified=false`.

Формула для исходного атласа10240×10240:

```text
pixelX = 5120 + worldX * 10240 / 615000
pixelY = 5120 + worldY * 10240 / 615000
world bounds = [-307500, -307500, 307500, 307500]
```

Это преобразование таблиц в пиксели изображения; координаты клика на телефоне
из него автоматически не следуют. Оси не переставлены, обе положительны.
Входные параметры: Map CSV entry1394, records3/4, GroundDistance615000,
CenterX/Y0, MapTextureReadingStandard1, MiniMapTextureCount/WorldMapTextureCount5.
Версия ресурсов и SHA таблицы находятся в индексе атласа.

### Код клиента и воспроизводимость

Инструмент `build-map-projection.py` проверяет EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`,
Capstone5.0.6,21 опорную инструкцию и3 текстовых ключа. Полные декодированные
unwind-фрагменты с SHA/offset и цепочка полей сохранены в
`code-clues/map-projection-evidence.json`:

| Участок | Наблюдение |
|---|---|
| `0x145aa53e0` | ModifyValue: GroundDistance→float+0x20, CenterX→+0x24, CenterY→+0x28; текстовые ключи проверены |
| `0x1464bdfa0` | Центр→widget+0xb10/b18, GroundDistance→+0xb00/b08, размер текстуры/расстояние→масштаб+b20/b28 |
| `0x1464cc9a0` | XY значка минус центр, умножение на положительный масштаб, запись пары координат |
| `0x1464c42f0` | Для standard1 индекс массива смещается на count/2 |
| `0x1464c44f0`→`0x146721ae0` | Сборка имени плитки и `/UI/Resource/Texture/Map/%s` |

Это данные и код собранного клиента Windows, не исходный C++ проект.
Остальные режимы карты и версия Android этим не проверены.

### Независимая сверка старого кадра

Использована прежняя матрица рельефа screenshot→atlas, без подгонки по значкам.
Для GadgetSpawn10011001,10011101,10011102,10011104–10011107 мировые координаты
переведены в атлас и обратно на сохранённый кадр. Все7 прогнозов попали в
вручную просмотренные прямоугольники соответствующих значков. Прямоугольники,
исходные CSV-записи и рассчитанные координаты сохранены в projection.json.
Это проверка областей значков, не субпиксельная точность; все7 находятся на
одном историческом кадре Krvna Nest. Вся Nocturne на Android не проверена.

Gadget20001 имеет MapIconId8001, отсутствующий в доступной MapIcon CSV.
В ней есть903/IMG_MapIcon_LiftGadget, но связь8001→903 ещё не доказана.
Геометрическое совпадение группы подъёмников не выдаётся за завершённую
семантическую цепочку этого значка.

### Просмотрщик и проверка

Кнопка «Карта с точками» накладывает выбранные слои на Nocturne. «Вся карта»
показывает весь атлас, «Вписать точки» — участок выбранного мира. Для остальных
MapId фон не применяется. Записи NPC в одинаковой исходной позиции объединены
числом на отметке; список сохраняет каждую запись и её условия отдельно.

Поле «Источники предмета» принимает ID из каталога5827 предметов, связывает
item-origins→NPC→npc-locations и оставляет соответствующие миры/записи.
Для Item12013000:175 NPC в наградах,8 миров с размещениями; World10017 —
39 записей в3 разных координатах. Это исходные позиции, не39 одновременно
видимых NPC: радиусы, группы позиций, события и условия появления не вычисляются.
Шанс выпадения по-прежнему неизвестен. Ссылки из карточки предмета и записи
размещения NPC открывают нужный фильтр/мир/запись атласа.

Браузером проверены рельеф, фильтр12013000, сброс, пустая выборка Item1,
отключение фона для World20001 и переход NPC200052→spawn100177067→World10017.
Свежий снимок: `maps/atlas/projection-preview.png`. Отчёт:
`maps/atlas/projection-verification.json`. Прошли33 теста:4 проекции+9 атласа+
5 совмещения+10 добычи+5 размещений. JS обеих страниц прошёл syntax check.
Новых игровых действий, сборки/публикации Android-модуля не было.

Порядок сборки при уже готовом атласе и screenshot-study:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-map-projection.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-map-atlas.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-npc-loot.py
```

При смене CSV/таблиц/атласа сборка отказывается принять старую проекцию.
Убрать старый projection.json из рабочего каталога в архив исследования,
пересобрать базовый атлас, заново проверить native-код/кадр и создать проекцию.
Исторические поля world_coordinates_verified=false в исходном
nocturne-world.json описывают этап сборки плиток; актуальная проверка отдельно
в projection.json, а не изменением происхождения исходного изображения.


## Единая большая Nocturne, 17 октября — все контексты и связи

Главная страница `maps/atlas/index.html` теперь открывает всю Nocturne и все
36 подтверждённых по Map10/11 контекстов вместе. Прежний просмотрщик254 миров
сохранён как `maps/atlas/world.html`; неподдержанные большие карты не накладываются
на Nocturne. Другие миры доступны по ссылке «Миры и подземелья».

Инструмент `build-world-map.py` строит единую сцену `nocturne.json` и
`nocturne-manifest.json` с SHA256. Браузер проверяет хеш сцены, исходные JSON
мира загружает для карточки с проверкой их SHA. 24071 разных ключей отметок:

| Слой | Записи |
|---|---:|
| NPC | 17488 размещений /1785 разных NPC ID |
| Области | 172 подписи на карте /177 названий в данных |
| Мировые точки | 207 |
| Порталы | 40 |
| Остальные объекты | 629 |
| Квестовые цели по TargetSpotInfoId | 5535 |

Все605 AreaBox сохранены:281 контур сYaw0 рисуется по желанию,322 с ненулевым
Yaw оставлены в исходных данных до доказательства точки вращения. Ещё2
(в том числе40006) имеют обратные Min/Max: автоматически местами не менялись.
5 областей без подтверждённой позиции подписи также сохранены в отдельном списке:
War in the Shadows, Prelude to Dusk, Wheel of Destiny, Abyssal Rift, Bezdan Sanctuary.
Сверены множестваID всех исходных размещений/точек/областей/объектов/AreaBox,
проверено отсутствие потери записей при объединении и уникальность ключей сцены.

### Связи и происхождение

Дополнительно прочитаны проверенные поSHA CSV385 (AreaName_en,553 записи) и481
(NpcName_en,5518 записей). В localizations сохранены варианты названий, entry и
номер CSV-record; полного SHA/пути/PAK-offset достаточно в sources.localization.
Переводы с одинаковымID не подменяют друг друга.

NPC→NpcReward→Reward→Item используется из ранее проверенного item-origins;
в карточке показаны все связанные предметы с изображениями, число цепочек и
ссылка на полные условия в каталоге. Сохраняются отсутствующие/неоднозначные
иконки; FloatRGBA имеет отметку о непроверенном цвете. Вероятности не выдуманы.
Item12013000 на Nocturne:110NPC/130 размещений/4мира. Прежние175NPC/8миров
относятся ко всему каталогу, включая подземелья.

Область связана с исходным Waypoint; портал связан по GadgetSpawnInfoId с
исходным размещением и по TeleportSpot с точкой прибытия. В карточке стоимость,
валюта и TeleportUse. Можно показать линию к точке назначения: она выражает
ссылку таблицы и не является маршрутом движения. Проверка: портал10011001,
1000Gold→Spot10011001. У этого Spot найдено116 квестовых задач.

5535 задач связаны с точными WorldSpot и сохранёнными Quest/Task names.
Карточки областей/точек показывают связанные задачи; поиск охватывает названия,
NPC, Task/Quest/Spawn ID. Опция «Поиск во всех слоях» позволяет находить
квесты при выключенном слое. Каждый результат доступен отдельной кнопкой;
близкие отметки на карте раскрываются списком, без слияния разных NPC/миров.

### Большие изображения и увеличение

В обзоре используется2048px preview, при увеличении подгружаются только
видимые исходные плитки2048px (кеш до10 невидимых/видимых плиток). Геометрия
всех плиток задаётся той же матрицей, что и общий атлас. Изменение масштаба
удерживает позицию под курсором. Панорамирование, клавиатура, поиск,
контексты, подписи и границы работают на одной сцене. Начальный вид — все слои.

По замечанию пользователя исправлена ошибка увеличения: `atlas_rect` из
assemble-nocturne.py — **[left,top,right,bottom]**, а неx/y/width/height.
Ранее правый/нижний край ошибочно использовался как размер, что растягивало
и перекрывало плитки. Теперь размер =right-left /bottom-top. Независимая
проверка всех25 декодированных плиток дала попиксельное совпадение с crop
полной карты. Отчёт `tile-verification.json`; тесты ловят ошибку на плитках
вне начала координат. Увеличение проверено на Krvna Nest в браузере.

Отдельный `render-world-map.py` создаёт `nocturne-overview.png`10240×10635
(полотно10240×10240 плюс подпись/легенда), небольшойJPG для просмотра и
`nocturne-overview.json` с SHA и связью со сценой. В PNG включены все24071
записи, объединённые в2535 отметок;119 неперекрывающихся подписей областей.
Полный набор172 подписей доступен в интерактивном виде и JSON. Это экспорт
данных, не изображение всех одновременно присутствующих персонажей.

### Проверка и сборка

40 Python-тестов и11 Node-тестов прошли (51 всего): прежние33 +7 построения
общей сцены +11 клиентских фильтров/групп/геометрии плиток. JS syntax проверен.
Браузер: общий обзор,29 предметовNPC200052 (первые18 иконок загрузились18/18),
фильтр12013000,пустойItem1,портал→точка прибытия→116квестов,поиск во всех
слоях,исправленное увеличение. Свежие снимки world-map-preview.png и
world-map-zoom-checked.png. Отчёт `world-map-verification.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-npc-loot.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-map-atlas.py
python -X utf8 phone-exit/bots/resource-tools/vampir/render-world-map.py
```

При наличии проверенной projection.json сборка атласа автоматически запускает
build-world-map.py и сохраняет прежнюю страницу какworld.html. Для обновления
только общей сцены/просмотрщика достаточно build-world-map.py. После изменения
данных экспортер запускается заново. Пакеты/приложения не устанавливались,
игровые действия/новыйAPK/публикация не выполнялись. Навигация остаётся
`navigation_ready=false`; свежийAndroid и все иные MapId не откалиброваны.


## Карточка выбранного монстра, 17 октября

В большой карте выбор NPC открывает дроп с иконками, количеством из исходной
строки и всеми условными цепочками. Для каждой карточки доступно «Все источники».
Повторные размещения одногоNPC не требуют выбора в группе; разныеNPC с одинаковым
именем остаются отдельными кнопками сID,уровнем и числом предметов.

Добавлены HP,AttackPower,DefensePower из Battle CSV1545 (5205строк).
Цепочка Npc.BattleGroupId→Battle.GroupId подтверждена native-диагностикой ссылки
в table-dependencies.json (offset161052610),её байты иSHA EXE проверяет
`build-monster-details.py`. Это клиентские базовые характеристики. Не выводится
придуманная семантика для Aggressive/Attribute/Type. Прочие боевые параметры и
ID навыков доступны в раскрываемой исходной записи. Для1785NPC найдены Battle;
у2NPC несколько вариантов — показаны все,ни один не выбран автоматически.

Рядом с дропом показаны исходные строки опыта/золота/других наград. Их значения
не объявлены гарантированными. ДляNPC200052 Void Chronicler:HP24318,атака1537,
защита0;29предметов;опыт12040,Gold158–192,EventDiamond1. Это значения строк
клиента,не итог за каждое убийство. Проценты по-прежнему неизвестны.

Иконки/количество не объединяют условные исходы:например,InvasionCoin имеет
варианты1–2 и10,они не складываются. Количество указано как «Кол-во в строке»;
множители вложенных групп и условия получения ещё не вычислены. По каждой
цепочке сохранены RewardRate,Rate,AcquisitionGroupType/MethodType,RewardGroup,
NpcRewardId,Reward-chainID и происхождениеCSV. Отсутствие строк отображается
как «Дроп:данныхнет»,не как доказанное отсутствие добычи.

Размещения выбранногоNPC доступны отдельным списком,радиусы/квестовые условия
видимости читаются из NpcSpawn и сохраняются вместе с остальными полями.
Новые данные загружаются по выбору монстра: `monster-manifest.json` и
`monsters/<NPC-ID>.json` сSHA. Не требуется загружать все1785карточки сразу.
Сборщик общей карты автоматически вызываетbuild-monster-details.py.

Проверены все1785карточек/23329цепочек,соответствиеBattleGroupId иSHA;
43Python+13Node-тестов (56всего),JSsyntax. Отчёт `monster-verification.json`.
Расширенная карточкаNPC200052 сHP/опытом/золотом/дропом проверена браузером.
После компактного оформления и добавления боевой исходной записи браузер
отключён вWork settings:финальный вариант визуально повторно не проверен.
Нет новых игровых действий,APK или публикации. Актуальные шансы/модификаторы
сервера и живые условия появления не подтверждены.


### Исправление пустого дропа обычного монстра,17.10

Скрин пользователя показалNPC100201042 Thirsty Vagrant,World10020:
прямых NpcReward нет. Его NpcSpawn.AreaInfoId=100201040,аAreaRewardCSV11
содержит строки сGroupId100201040:Exp27577,Gold165–202,EventDiamond1,
RewardGroup70310400→34предмета (развёрнуто темже проверенным item_origins).
Это совпадение ключа области,не доказательство механики награды за убийство.

В карточку добавлен отдельный раздел «Награды области» с явным статусом
candidate_group_id_match_only. Не подменяет прямой дропNPC;выбирается строго
поAreaInfoId конкретного размещения,не по имени/близости/другим размещениям.
Предметы показаны сиконками/количеством/цепочками,источники остаютсяCSV11/Reward.
Кнопка обратного поиска подписана «Прямые NPC-источники»:каталог пока не
индексирует кандидатов области как доказанные источникиNPC.

326NPC имеют такие кандидаты (точноечисло см.area-reward-verification.json).
Все1785SHA карточек/GroupId/цепочки сверены;43Python+14Node тестов (57).
ДляпользовательскогоNPC:0прямыхпредметов,34предметавкандидатенаградобласти.
Браузер остаётся отключён вWork settings,финальныйUI непроверен визуально.
Чтобы доказать действующийдроп,нужно проследить native-применениеAreaReward
или сверить награды вживойигре;проценты всёещё неизвестны.


### Разделение области и NPC,17.10

Повторная проверка:все323GroupId AreaReward совпадают сArea.Id;все941GroupId
NpcReward совпадают сNpc.Id. Пересечений групп нет. Native-загрузчики ранее
доказаны раздельно;новый поиск getter-строк сохранён в
code-clues/reward-scope-discovery.json. Правило применения/сложения наград
заубийство этим не доказано. Отчёт:maps/atlas/reward-scope-audit.json.

Разделены интерфейс и индексы:«Личные записиNPC» фильтруетNPC,«Записи области»
фильтруеттолькоArea-точки,не объявляет монстров жителями подтверждёнными
источниками. Карточка области показывает еёAreaReward-кандидаты,карточкаNPC
держит их отдельнымраскрываемымразделом (открыт поумолчаниюеслиличныхстрокнет).
Опыт/золото области не смешаны сличными. Вцепочках области ключиarea_id/
area_reward_id/area_reward_provenance,не npc_id. Новый area-rewards.json
загружается отдельно,сSHA,содержитобратныйItem→Areaиндекс. Ссылкафильтра
сохраняетrewardScope=area. NPC100201012 с текущейстраницы:прямыхстрок0,
область100201010→34предметакандидата.43Python+15Node тестов (58),все1785
карточексверены;визуальныйпросмотрнедоступен,браузеротключён вWork settings.


## Повёрнутые границы и проходимость: проверка источников, 17 октября

`build-area-box-code.py` проверяет15 нативных опорных инструкций загрузчика
AreaBox145c3dae0/ModifyValue145c54720 и vtable149962150. MinPos и MaxPos
хранятся строками record+0x10/+0x20; Yaw — float32+0x30.
Callbacks slot10/18/20 у этой базовой записи ведут в ret0 1413fe190.
Это не потребитель трансформации; точка вращения и знак поворота не установлены.
Отчёт code-clues/area-box-code.json SHA57863ac765209acaf127f2025afbbb76e5de1269997571621b6a9df12c31fd54;
EXE SHA c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
Поворот вокруг центра/начала координат в отрисовку не добавлен.

`map-readiness.py` проверяет tables.json по SHA индекса, координаты/MinMax/Yaw,
все исходные пары NavigationTestCase и ссылки на World. Сохраняет исходные записи
с CSV provenance, не переставляет обратные Min/Max, не рисует предполагаемый полигон.
Все карты:1460 AreaBox =686 допустимых нулевых Yaw +772 неподтверждённых поворота
+2 обратных/невалидных MinMax. Nocturne по-прежнему322 неподтверждённых поворота.
CSV10 SHA500c169afa60ffa2efe8538abffbe11f16c99eb2d6b408756ed92fc53239fbc9.

NavigationTestCase CSV1576 SHA7e96903163b9625f53e738a9a723673b05f1d59b1a14efa19c93c96dddd27359:
5160 пар, все координаты конечны;80 ссылаются на отсутствующий World.Id.
27 navFileName;1732 пары используют Nocturne_Nav.bin. Схема содержит только
caseKey/worldInfoId/navFileName/sx/sy/sz/ex/ey/ez — нет ожидаемого маршрута или
результата pass/fail. При поиске *_Nav.bin в F:/PhoneExit Resources/Vampir
найдено0 извлечённых файлов. Это НЕ утверждение об отсутствии навигации в
установленной игре/архивах. Проверка маршрутов не запущена; walkable=null,
routes_verified=0, navigation_ready=false. AreaBox.Type/PlayerBlockType,
портальные ссылки и линии текстуры не принимаются за граф проходимости.

Отчёт maps/atlas/geometry-readiness.json SHA93e79b7efb86655407c31456eb4ae22b67ab526f058c61bee4f2562da3d958a0.
При наличии area-box-code.json сверяются EXE/anchors/vtable/ret0; ссылка/SHA отчёта
и summary включены в scene.geometry_audit. build-world-map.py вызывает проверку
автоматически. На странице раскрываемый раздел «Границы и проходимость: что проверено»
и ссылка на подробный JSON. Данные относятся ко всем картам, статус страницы отдельно
называет Nocturne. DOM322/1732 и отсутствие сообщения ошибки проверены браузером.

Порядок: build-item-effect-semantics.py → build-npc-loot.py →
build-area-box-code.py → build-world-map.py.3 новых теста: сохранение поворота без
догадки о pivot, отклонение malformed/nonfinite/обратных extents, навигационные
inputs не становятся путями даже при конечных координатах. Общая проверка92 теста.
Осталось найти потребитель преобразования AreaBox, извлечь/разобрать навигационные
данные и проверить путь с ограничениями; затем свежий прогон движения на Android.


## Источники RefNavMesh и цепочка загрузки, 17 октября

`build-navigation-sources.py` читает прежние entries.json (341887 записей в общем
индексе), ищет точные пути /Game/RED/Blueprint/DataAsset/RefNavMesh/* и проверяет
нужный исходный PAK по размеру/mtime/выборочному SHA до ограниченного извлечения.
Нативный EXE SHA прежний c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
15 опорных инструкций проверены:14568ce80 строит _Nav.bin с RED/NavMesh,
14568cfc0 строит _WPRefNav с /Game/RED/Blueprint/DataAsset/RefNavMesh;
LoadWPRefNavMeshData1455e4c40 вызывает последний helper на1455e4e1b,
загрузку объекта1455e4e55 и сохраняет результат в[rsi+0x2c8] на1455e4e94.
Строки диагностики ANnRefNavDataLoader::LoadWPRefNavMeshData(),
Could not find RefNavFile и NnUtilRefNavi::IsPathConnected() сохранены с байтами,
offset/xref. Наличие обоих helper НЕ доказывает полный выбор ветвей или одинаковые
форматы. Функция проверки связности14568f5c0 найдена, но не исполнялась.

15 записей содержат ссылки RefNavMesh:14 заголовков pakchunk100-Windows и1
упоминание в большом уровне pakchunk1000_s3-Windows entry1141. Последнее не считается
обновлённым WPRefNav: paths включают импорты. Nocturne-заголовок pakchunk100
entry886 offset806912,743 байта SHA767a039f69e99736f8e2ea9ce9131e2d9b08c79582f387161eafc8ab3b596191,
содержит класс NnDataAssetRefNavMeshHeader. Соседняя запись887 offset807708,
2939 байт SHA3a7164c053939f0ce6f39660dcbe944158fb25cae7b300f5806795470110e013,
содержит20 путей /Game/__ExternalActors__/RED/Level/Field/Nocturne/... .
Её принадлежность заголовку НЕ доказана одним соседством: role=adjacent_record_candidate_only,
pair_relation_verified=false, для ссылок relation_verified=false. В индексированных
paths совпадений для20 ExternalActors нет. Индекс неполон — это не отсутствие
данных в игре. Детали исходного PAK и SHA каждого индекса сохранены в отчёте.

Результат maps/navigation-study/index.json SHA
f9d4895c936da4297338b0205f77396a27ebcd6f2c14d1ec279ccad5eccee853;
извлечённые записи рядом pakchunk100-Windows-Nocturne-ref-886.bin/-887.bin.
Предыдущие scratch Nocturne-ref-886.bin/-887.bin не входные данные сборки.
map-readiness.py проверяет SHA EXE, anchors/literals и извлечённые файлы отчёта,
затем сохраняет ссылку/SHA в geometry-readiness.json. Статус карты сообщает15 записей
RefNavMesh, рядом ссылка «Исследование навигационных ресурсов».
Все пути остаются неизвестными: routes_verified=0, navigation_ready=false.

Сборка: build-navigation-sources.py → build-world-map.py (последний автоматически
вызывает map-readiness.py).13 Python-тестов navigation/readiness/worldmap и21Node
проверка прошли, node --check прошёл, SHA цепочки nav-report→geometry→scene сверены.
Визуальная проверка нового статуса не состоялась: local browser use disabled in
Work settings. Android и исполнение игры не проверялись. Следующий шаг: схема
NnDataAssetRefNavMeshHeader/пакетных exports→внешние chunks→данные полигонов/связей,
затем воспроизвести IsPathConnected; поворот AreaBox пока не установлен.


## Экспорт Nocturne_WPRefNav и20 заголовков частей, 17 октября

Это уточняет предыдущий статус adjacent_record_candidate_only. Переиспользован
проверяющий cooked-package reader inspect-ui.py:exports. Asset886 и body887
содержат один export Nocturne_WPRefNav типа NnDataAssetRefNavMeshHeader,
offset743,size2935,SHA b13d25fe34c33c380b7f3d3d71dc453ef9e6d55296a2730b7631c1b8c13940bb.
Размер asset743+export2935+сигнатура4 полностью покрывает2939 байт body;
ссылки class/import/name и диапазон export проверены. Поэтому принадлежность
887 этому пакету подтверждена, role=verified_package_export_body,
pair_relation_verified=true. SHA asset/body и PAK источники прежние.

Новый decode-navigation-header.py читает наблюдаемую unversioned-схему с полным
учётом байтов. Outer header индексы1/2/3, NumMaxTiles24056, NumChunks20,
array count20. Каждая запись имеет ChunkRef,AssetFilePath,Bounds; refs0..19,
все paths /Game/__ExternalActors__/RED/Level/Field/Nocturne/Nocturne/... .
Bounds —6 double координат и1 byte valid; после всех20 записей object suffix0,
неучтённых байтов0. Запись сохраняет body_offset/serialized_size. Проверяются
count, уникальные refs, длины/терминатор/префикс пути, конечность и порядок bounds,
valid и suffix. Неизвестная схема вызывает ошибку, не догадку.

Шесть native descriptors в EXE сверены по именам/flags/offset/bytes:
1497f7048 ChunkRef+0 flag3;1497f7080 AssetFilePath+8 flag21;
1497f70c0 Bounds+0x18 flag25;1497f7490 NumMaxTiles+0x34 flag3;
1497f74c8 NumChunks+0x38 flag3;1497f7540 RefNavMeshChunkHeader+0x40 flag22.
Декодирование схемы выведено из этих метаданных и полного байтового соответствия,
а не из доступного C++ проекта. Никакой связи bounds с AreaBox или walkable polygon
не добавлено. Walkability остаётся false/unknown:20 records описывают части и
габариты, а не полигоны движения. Число tiles не равно числу проходимых клеток.

build-navigation-sources.py теперь сохраняет package/decoded_header/native_descriptors;
отчёт maps/navigation-study/index.json SHAbbf91d2c53164ffd6e3c371f7eb09257fe1819e45d4dad9333817e429a9ff4da.
map-readiness.py также проверяет bytes native_descriptors и включает decoded_chunks20
в summary; статус страницы говорит о20 разобранных заголовках. Сборка:
build-navigation-sources.py → build-world-map.py.16Python навигация/readiness/worldmap
и21Node прошли; JS syntax/SHA nav→geometry→scene проверены.

По запросу пользователя сервер17946 вновь запущен (только127.0.0.1, корень библиотеки).
Браузер снова доступен: reload карты, статус322/1732/15/20, пустой alert и отсутствие
console errors подтверждены. Снимок maps/atlas/navigation-header-checked.png просмотрен.
Это снимает прежнее ограничение визуальной проверки статуса. Свежего движения
на Android не было. Следующий шаг: извлечь payload внешних частей/полигоны/связи;
AreaBox rotation pivot и фактическая проходимость по-прежнему не подтверждены.


## Поиск payload и пакет большого уровня Nocturne, 17 октября

`search-navigation-payloads.py` ограниченно проверяет незашифрованные записи без
UAsset/texture признаков в pakchunk100 и pakchunk1000/base+s1..s5. До чтения каждого
PAK сверяются size/mtime/sample SHA. Лимиты700MiB/archive и128MiB/record,
байты/offset/entry/SHA каждого совпадения сохранены. Проверено21494 records,
2574751792 распакованных байт,ошибок0.24 совпадения:22 записи с RecastNavMesh,
1 cMSET (только кандидат сигнатуры),1 — уже разобранный header-body887 с20 tokens.
Магические байты не считаются доказанным tile header. Отчёт
maps/navigation-study/payload-search.json SHAe4c9e91bd31ca4ba46c3c1da010de8ac698d5556fc36249677bce02b91633b41.
Отсутствие VAND и неизвестных токенов в этом объёме не доказывает отсутствие
навигации в других архивах, форматах, зашифрованных записях и потоковых данных.

Существенная находка: body большого уровня Nocturne находится ПЕРЕД header,
pakchunk1000_s3-Windows entry1140 (12053221 байт),header1141 (7792556 байт).
Связь доказана таблицами импортов/экспортов,диапазонами/SHA и полным покрытием
body,а не соседством. Прежний inspect-ui.py имел предел10000exports; добавлен
необязательный max_exports, default10000 сохранён. Для этого известного уровня
build-navigation-level.py явно задаёт40000; проверено34206 exports.
Идентичность: путь Nocturne в name table плюс единственный root World Nocturne
export5709. Первый name table entry может быть импортом, не именем пакета.

Извлечены точные диапазоны115 nav-объектов:49 NavMeshBoundsVolume,
63 NnNavLinkCustomComponent,1 NavigationSystemModuleConfig,
1 NnRecastNavMesh (export3919,size551,SHA78807cf7cd174e5365cd3045520c5fb148d84e40fa47ab6efbaa604a8f813400),
1 NnRefNavDataLoader (export3920,size119,SHA0e80d21130f799d1a669245cc24197687dcf2ec0fd70efdfbb268953ca6f3eb2).
Nav export properties/custom serializers ещё не разобраны.63 компонента не
выдаются за63 ребра графа;49 volumes не являются проходимыми полигонами.
В name table уровня20 hashedExternalActors не найдены. Navigation_readyfalse.

Воспроизводимая сборка: python -X utf8 phone-exit/bots/resource-tools/vampir/search-navigation-payloads.py,
затем build-navigation-level.py. Результат maps/navigation-study/level/index.json
SHAe946a32f559be3406dfa52509283e7185447f1c39b22b9bb2656f66df00efebb;
полные asset/body и115 export-N.bin рядом. Source PAK,entryoffsets,SHA и
проверенный root World сохранены в отчёте. Старые scratchNocturne-level-body.bin/
-package.json не входные данные сборки.19целевыхPython тестов прошли: поиск
ограничивает совпадения,сохраняет offset и не подтверждает связь по магии;
прежние header/readiness/worldmap проверки повторены. Изменений UI/навигационного
движения не было. Далее: custom serializer NnRecastNavMesh и payload chunks,
декодирование NnNavLinkCustomComponent с условиями,потом проверка связности пути.


## Явные поля63 навигационных компонентов лифтов, 17 октября

Новые build-navigation-links.py/decode-navigation-links.py читают только проверенные
navigation_exports из level/index.json. Все63 NnNavLinkCustomComponent принадлежат
по export.outer объектам с именами BP_Lift_C (10),BP_Lift_Test_C (10),
BP_Lift_Type01_C (43). Имена test не доказывают активность/видимость объектов в игре.
Эти компоненты не являются обычными пешими рёбрами графа.

В EXE прежнего SHA подтверждена native property pointer array149729510:
index1→descriptor149728f90 CustomLinkId,index2→149728fd0 AuxiliaryCustomLinkId,
index6→1497290f0 LinkRelativeStart,index7→149729130 LinkRelativeEnd.
Сверяются4 descriptor prefix56bytes,имена,gen_flags25,указатели массива иoffsets.
Custom constructor145458c80 вызывает базовый145299d50 на145458c94;
базовый вызывает1452c35d0,записываетvtable145299d70,derived заменяетvtable145458ca0.
4anchors/полные fragments сохранены. Это код клиента,не доступные C++ декларации.

Наблюдаемая unversioned-сериализация ID:вложенный header index0/false иuint64,
ID сохраняется десятичной строкой без потери точности JS. Точки —3double,
не worldXY. Декодер читает лишь явно присутствующие поля1/2/6/7;zero-mask
отличает явно заданный ноль от отсутствующего значения. Отсутствующие точки,
LinkDirection/LinkEnabled и значения архетипа не подставляются автоматически.
Итог:49 явных стартов,40 концов,27 компонентов с обеими точками.
57 экспортов после известных полей имеют8 нулевых байт:сохранены как неизвестный
suffix,семантика не объявлена доказанной.6 содержат неизвестные поля14(2) или22(4):
декодирование останавливается перед ними,хранит неизвестные индексы иполныйtailhex.
Частичный разбор не превращается в сообщение «все свойства расшифрованы».

Результат maps/navigation-study/level/link-properties.json
SHA c4b909261d49b42e7e9dfd5cd54f6e8f7eb976370a466bdcea3a1d099afcdfe1:
для каждой записи точныйexport/parent/offset/SHA,decoded_prefix_bytes,
явныеproperties иunknown tail;native descriptors/constructor anchors/sourceSHA.
Новые23 целевыхPython теста (links/payloads/header/sources/readiness/worldmap) прошли.
4 новых проверки:максимальныйuint64 сохраняется строкой,неизвестныеполя/байты
не пропускаются по догадке,zero-mask не заменяет отсутствующий конец,
truncated/nonfinite векторы отклоняются.

Сборка:build-navigation-level.py → build-navigation-links.py (из корня проекта,
python -X utf8 phone-exit/bots/resource-tools/vampir/<скрипт>). Никаких маршрутов
или отметок абсолютных координат лифтов вUI не добавлено:parent transforms,
направление/включённость/движение/условия runtime не восстановлены.
Полигоны внешнихchunks не извлечены;navigation_ready=false. Следующий шаг:
свойства лифта/parent transform и архетипы,затем условия перехода иpayload полигонов.


## Размещения SceneComponent у63 лифтов, 18 октября

build-lift-placements.py заново проверяет SHA asset/body уровня изlevel/index.json,
разбирает34206exports тем жеinspect-ui.exports(max_exports40000),связывает
NnNavLinkCustomComponent.outer→Parent.index→SceneComponent.outer.
У каждого из63 Parent ровно один SceneComponent. Сохранены исходные exports
родителя иScene,offset/SHA/outer,parenttype/name вlevel/lifts/export-N.bin.
Роль RootComponent по одному имени Scene иouter не утверждается.

Нативный EXE SHA прежний c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
Проверена pointer-array prefix14912aa80 (13 descriptor pointers):PhysicsVolume,
AttachParent,AttachSocketName,AttachChildren inner/outer,ClientAttachedChildren
inner/outer,RelativeLocation,RelativeRotation,RelativeScale3D,ComponentVelocity,
bComponentToWorldUpdated,bAbsoluteLocation. Вложенные array elements не становятся
отдельными serialized properties:после исключения inner дескрипторов совпадают
index5Location/6Rotation/7Scale/10AbsoluteLocation. Имена,flags,bytes descriptors
иpointerbytes сверяет сборщик. Дескрипторы14912a480/14912a4c0/14912a500/14912a5c0.

decode-lift-placements.py читает только явно заданные5/6/7 (3double) и10(bool).
Все63 имеютRelativeLocation,57RelativeRotation,14RelativeScale3D;7 явно true
bAbsoluteLocation. У56 значение флага отсутствует,это неfalse. Поворот/масштаб
при отсутствии не подставлены из default. Zero-mask scale остаётся[0,0,0],
не заменяется на[1,1,1]. Проверяютсяfinite/bool/truncation,unknown fields остаются
нераспознаннымtail. Все63после явных полей имеют8 нулевыхбайт;они сохранены,
их семантика неизвестна. Никакой parent/root/attachment/worldтрансформации
не вычисляется,relative endpoints лифта не переведены вабсолютную карту.
Даже bAbsoluteLocationtrue не доказывает полную трансформацию/путь безroot/attachments.

Результатmaps/navigation-study/level/lift-placements.json
SHA6922585d7eb81aa925710bef7b37a44fd912afd1dc941b3a8ab1fcb7fb543026,
полные nativeprefix/descriptors,levelindexSHA,sourceEXE,63liftrelations иdecodedfields.
Сборка:python -X utf8 phone-exit/bots/resource-tools/vampir/build-navigation-level.py,
затемbuild-lift-placements.py. Прежний link-properties.json — отдельный индекс
локальных точек;для его обновленияbuild-navigation-links.py.
27целевыхPythonтестов(liftplacements/links/payloads/header/sources/readiness/worldmap)
прошли.4 новых теста отличают явные значения от omitted/default,сохраняют
unknown bytes,проверяютzero-scale иотклоняютневерныеbool/nonfinite/truncated.
UI,движение,APK не менялись. Следующий шаг:RootComponent/blueprintархетипы,
наследуемыеtransformflags,состояния/движениелифта;navigation_ready остаётсяfalse.


## Штатный корень NnLift и наследование Blueprint, 18 октября

build-lift-blueprints.py закрепляет нативный конструктор1454fd410.
На1454fd506 создаётся subobject;егоrax сохраняется в[rsi+0x3c0] (SceneRoot)
на1454fd50b,копируется вrbx1454fd512,затемтотжеrbx пишется в[rsi+0x1b8]
на1454fd531 (Actor.RootComponent). Имя Scene берётся из единственногоUTF16xref
внутриконструктора. Дополнительно1454fd69a создаёт navcomponent,
1454fd6bd сохраняет его в[rsi+0x3d8].7native anchors иполныеfragments сохранены.
Поля подтверждены descriptors14987d1e0 SceneRoot+0x3c0 и149168fe0 RootComponent+0x1b8;
SHA EXE прежнийc7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
Это доказывает штатное назначение Scene корнем NnLift,но не отсутствие
последующих Blueprint/runtime/instance overrides.

Из pakchunk100-Windows извлеченыпроверенныепары2292/2293 BP_Lift,
2296/2297 BP_Lift_Test,2298/2299 BP_Lift_Type01. Доизвлечениясверяются
size/mtime/sampleSHA PAK,затем exports/imports/ranges/SHA иполноепокрытиеbody.
Связькласса берётся из SuperIndex таблицы export,разрешённого точной импортной
записью:BP_Lift_C→NnLift (-15),BP_Lift_Test_C→BP_Lift_C (-1),
BP_Lift_Type01_C→BP_Lift_C (-1). Имяфайла илипохожееимя неиспользуется.
Записаныбайтыclass-export/import,имена,sourcePAK,entry/offset,хешиобеихчастей.
Default__ и SceneComponent exports сохранены,ноихнастройкиещёнерасшифрованы.
ОтсутствиеявныхполейScene template само по себе не доказывает identity transform:
default properties должны разрешаться поархетипам.

Результатmaps/navigation-study/lift-blueprints/index.json
SHAa9a8458d55bdcf1e0efe5b82e1fe1c7035e0323eab6a5d40c0265b2df6cc6996.
Файлы2292..2299.bin рядом (толькоуказанныевreport пары — входныеданные).
Сборка:python -X utf8 phone-exit/bots/resource-tools/vampir/build-lift-blueprints.py.
30целевыхPythonпроверок(blueprints/placements/links/payloads/header/sources/
readiness/worldmap) прошли.3новыхтеста:импорт,анепохожееимяопределяетsuper;
local/null/out-of-range super неугаданы;неверныйnameindex/несколькоклассов
отклоняются. UI/Android/движение не менялись. Мировыеточкиимаршруты пока не построены.
Дальше:CDO/архетипыBP_Lift→Test/Type01,instance overridesRootComponent/SceneRoot,
attachment graph иусловия активации/перемещения.


## Настройки экземпляров лифтов и SplineActionParams, 18 октября

`build-lift-instance-settings.py` проверяет 22 поля нативной структуры
SplineActionParams по pointer array1498184b0: Duration, EasingFunc, BlendExp,
MontageName, SocketName, FadeEnabled, FadeInTime, FadeOutTime, ParticleActorName,
HideGameUI, CameraTargetYawEnabled, CameraTargetYaw, CameraTargetYawEasingFunc,
CameraLagSpeedEnabled, CameraLagSpeed, CameraLagMaxDistance, CameraLagEasingFunc,
FinishEffect, FinishEffectSocketName, FinishEffectLocationOffset,
FinishEffectRotationOffset, FinishEffectScale. Сверяются имена/flags/descriptor и
pointer bytes. Item/Skill.Duration это не затрагивает: единицы полей этой структуры
пока не доказаны. Нативный NnLift prefix14987d440 также проверен: bAutoActivation,
SplineActionParams, SceneRoot, Spline, TriggerComponent, SmartLinkComp.
Источник — прежний EXE SHA c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.

Сдвиг нативных свойств в cooked экземплярах установлен по UStruct-префиксу
самих BlueprintGeneratedClass: после проверенных refs полей7/8/9 и нулевого
object-suffix проверяется superclass index против export table, child export
indices и собственное число полей. BP_Lift_C имеет2 поля, Test1 дополнительное,
Type01 собственных0: cumulative prefix соответственно2/3/2. Точные прочитанные
байты class prefix сохранены в class_sources, SHA частей пакетов сверены.
Это не подбор сдвига по совпадению числовых ID.

`decode-spline-action-params.py` читает только явные поля структуры: float32,
byte enum/bool, bounded FString UTF8/UTF16, исходный object index/FName и3double
vectors там, где подтверждены flags. Проверяются bool/finite/length/terminator;
неизвестный индекс отклоняется. Omitted не заменяется default; zero-struct хранит
serialized_zero=true без выдуманных значений всех членов. Числа хранят исходную
точность float32 (например1.7999999523162842), а не объявляются секундами.

Проверены63 родителя из lift-placements.json. У каждого явно заданный SceneRoot
совпал с его SceneComponent export, SmartLinkComp — с точным навигационным export.
Таким образом, ссылки экземпляров на Native.SceneRoot/SmartLinkComp теперь
подтверждены. Это ещё не разрешение Actor.RootComponent и attachment/runtime overrides.
62 экземпляра имеют явную SplineActionParams/Duration,61 BlendExp;28 CameraTargetYaw,
28 CameraLagSpeed,24 явно заданных CameraTargetYawEnabled и24 CameraLagSpeedEnabled.
8 явно bAutoActivation=false, у55 поле отсутствует; отсутствующее не становитсяtrue.
False не считается недоступным маршрутом: включение другим действием ещё не проверено.

Разбор каждого родителя останавливается перед PointLinks/прочими неизвестными
полями: полные header indices, decoded_prefix_bytes и остатокhex сохранены.
Нельзя обходить неизвестное поле предполагаемым размером ради получения ActorRoot.
Пример parent1818: SceneRoot5393,Spline5562,Trigger5498,SmartLinkComp3855;
Duration1.7999999523162842,BlendExp1.0. Для этого примера bAutoActivation не задан.

Результат maps/navigation-study/lift-blueprints/instance-settings.json
SHA1e5f2690e13b7e2a79aa7194350692c901cc407eee32f9666b83472e67758552.
Сборка после build-lift-blueprints.py и build-lift-placements.py:
python -X utf8 phone-exit/bots/resource-tools/vampir/build-lift-instance-settings.py.
34 целевых Python-теста прошли;4 новых проверяют явные duration/blend без единиц/
default, false/zero/omitted, UTF16/raw refs и отклонение неизвестных/nonfinite/
truncated полей. Нативные дескрипторы и63 пары refs проверены реальной сборкой.
Scratch spline-params-schema.json не входной источник сборки.
Далее: PointLinks, ActorRoot и attachment graph; runtime use bAutoActivation/
SplineActionParams и условия включения. Мировые endpoints/проходимость не заявлены.

## PointLinks и проверенный корень экземпляров, 18 октября

`decode-navigation-point-links.py` и `build-lift-point-links.py` продолжают
разбор с decoded_prefix_bytes из instance-settings.json, проверяя SHA входных
экспортов. Порядок 35 свойств NavigationLink подтверждён полными native
descriptors/pointer bytes: Left/Right (массив указателей VA1490c13f0), затем
33 свойства базы (VA1490c1040). Проверяются конечность координат/float,
булевы значения, длина массива, границы и неизвестные индексы.
SupportedAgents сохранён как raw_u32 с interpretation_verified=false:
размер согласуется с прочитанными записями и последующей ссылкой корня,
но собственный serializer selector и семантика разрешений ещё не восстановлены.
Остальные явные bool bSupportsAgent0..15 сохранены без решения о проходимости.

Native NnLift PointLinks/SegmentLinks подтверждены inner/array descriptors
через VA14987d470; внутренние описатели не считаются самостоятельными полями.
Полный Actor prefix из 63 указателей до RootComponent (VA1491698b0) после
исключения 4 UnderlyingType и Children inner даёт serialized index57.
С учётом 8 полей NnLift и Blueprint prefix2/3/2 индекс Actor.RootComponent
экземпляров равен67/68/67. У всех63 он явно совпал с ранее проверенным
SceneRoot export. Теперь роль корня подтверждена и для cooked экземпляров,
а не только для штатного конструктора. Runtime replacement/attachment остаются.

62 явных массива содержат по одной записи; у одного массива нет в сериализованных
полях, это не пустой массив. Все62 имеют явный Direction0; native enum
ENavLinkDirection подтверждает 0=BothWays,1=LeftToRight,2=RightToLeft.
PointLinks и SmartLink сохраняются раздельно; обе стороны в данных не гарантируют
доступный лифт. Пример parent1818: Left≈[0,-50,34],
Right=[130.87249443586825,1274.554288008882,2544.1022807974296],
затем явно прочитан Actor.RootComponent5393, равный SceneRoot.
Unknown actor fields/suffix hex сохранены; мировая система координат,
условия включения и пешие рёбра графа не назначены.

Отчёт `maps/navigation-study/lift-blueprints/point-links.json`, SHA256
`1d51283425d5e8d02c32c960b7bc24c1e60843cf4ac63c6b8e0eead57238fed2`.
Источник EXE прежний: SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Сборка после build-lift-instance-settings.py:
`python -X utf8 phone-exit/bots/resource-tools/vampir/build-lift-point-links.py`.
38 целевых Python-проверок прошли. Четыре новых проверяют явные точки и
направление без готового ребра, zero/omitted, raw selector без разрешения
движения и отклонение повреждённых/неизвестных/nonfinite данных.

## Начальные значения SceneComponent в коде клиента, 18 октября

`build-scene-native-defaults.py` проверяет SHA EXE и16 native anchors.
NnLift вызывает getter1437d4d80 (call1454fd4eb), передаёт результат в r8/r9
и создаёт SceneRoot через141746350. Getter содержит буквальный SceneComponent
и указатель wrapper1437d48b0 (lea1437d4de7). Все20 bytes wrapper проверены,
включая tail jump к конструктору143ac1400. Полные unwind fragments сохранены.

В конструкторе после вызова базы143a28f20 явно записывается null по+0xb0
(xor143ac1423, mov143ac142c). Native descriptor14912a300 подтверждает,
что это AttachParent. Константа double1.0 загружается в143ac1495 и
записывается по+158/+160/+168 (143ac1517/151e/1525), то есть в RelativeScale3D,
что подтверждено descriptor14912a500. Это начальные значения до
Blueprint/archetype/instance/runtime overrides; они не подставлены экземплярам.
Нулевые RelativeLocation/RelativeRotation и absolute flags этим исследованием
не доказаны. Отсутствие явного поля по-прежнему не считается identity transform.

Отчёт `maps/navigation-study/lift-blueprints/scene-native-defaults.json`, SHA256
`49bc12c1a9f9d76b4917f6882886cb1d6da98989ae44340eb8bdda18bfebc179`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-scene-native-defaults.py`.
Реальная сборка проверила все anchors/descriptors/literal/wrapper на закреплённом
EXE. Далее разрешение архетипов и attachments, потребитель PointLinks transform
и runtime активация. UI, игровой клиент и маршруты этим шагом не менялись.

## Прямые ссылки архетипов корневых SceneComponent, 18 октября

`decode-package-references.py` читает ссылки валидированного legacy layout:
96-byte export records и32-byte import records. TemplateIndex находится
в export+8; полные исходные записи/смещения сохранены. Назначение поля как
ссылки на template/archetype соответствует [FObjectExport в документации Epic](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/CoreUObject/FObjectExport).
Конкретный layout проверен на имеющихся пакетах по известным Class/Outer/Name,
границам и разрешению всех refs; нативный serializer этого поля ещё не трассирован.
Это уточнение границ доказательства, а не отдельное подтверждение версии движка.

`build-lift-archetypes.py` сверяет SHA трёх Blueprint-пакетов и уровня,
извлекает исходное имя пакета из FString package summary (offset36), строит
полные import/export outer paths. Циклы/неизвестные indices/неверные FName и
выходы за таблицы отклоняются. Соединение выполняется по полному пути
импортированного шаблона и пути конкретного экспорта; имена классов/размещений
не служат заменой ссылке. Сохранены все6 SceneComponent templates, их export
SHA, header fields и остаток сериализации. У всех6 нет явных свойств.

Все63 SceneComponent уровня разрешены до `/Script/NnFramework.Default__NnLift.Scene`:

| Непосредственный Blueprint Scene template | Экземпляры |
|---|---:|
| /Game/RED/Blueprint/Lift/BP_Lift.Default__BP_Lift_C.Scene | 9 |
| /Game/RED/Blueprint/Lift/BP_Lift_Test.Default__BP_Lift_Test_C.Scene | 8 |
| /Game/RED/Blueprint/Lift/BP_Lift_Type01.Default__BP_Lift_Type01_C.Scene | 46 |

Test и Type01 Scene ссылаются на Scene базового BP_Lift; базовый Scene —
на native Default__NnLift.Scene. Другие три шаблона DefaultSceneRoot_GEN_VARIABLE
ссылаются на `/Script/Engine.Default__SceneComponent` и не подменяют фактический
корень экземпляров. Экспорты родителей1835/1836/1837 сохранили имена BP_Lift/BP_Lift_Test,
но их ClassIndex соответствует BP_Lift_Type01_C; template ссылки также Type01.
Поэтому прежние10/10/43 по префиксам имён — не распределение фактических классов.
Распределение классов по ClassIndex здесь9/8/46.

Отсутствие полей подтверждает отсутствие явных overrides в этих Blueprint
Scene templates, но не задаёт итоговые native CDO/post-construction defaults.
[Epic описывает автоматическое обнуление UObject перед конструктором](https://dev.epicgames.com/documentation/unreal-engine/unreal-object-handling-in-unreal-engine);
это общая модель движка, а не проверка всех последующих изменений в данном клиенте.
Она не использована для заполнения omitted rotation/flags экземпляров.
Runtime attachment, движение и условия включения остаются неизвестными;
мировые endpoints и рёбра проходимости ещё не построены.

Отчёт `maps/navigation-study/lift-blueprints/archetypes.json`, SHA256
`200c7aba676f551c753a6fabe5fe99a4587650f2734c9d85a8876ceb16c7d092`.
Сборка после build-lift-blueprints.py/build-lift-placements.py:
`python -X utf8 phone-exit/bots/resource-tools/vampir/build-lift-archetypes.py`.
42 целевые Python-проверки прошли;4 новых защищают выбор пути через import outer,
missing target без подбора по имени, циклы/неверные имена, границы и расхождение
export layout. Реальная сборка разрешила63 цепочки; UI/Android не менялись.

## Нативный потребитель границ PointLinks, 18 октября

`build-lift-bounds-code.py` сохраняет18 проверенных native anchors,4descriptors,
полные фрагменты функций и конкретную запись vtable. Конструктор1454fd410
назначает таблицу149880d80 (lea1454fd432/store1454fd439), её slot199 указывает
на14550d6c0. Символьное имя метода не назначается по одному номеру слота.

Метод читает количество по+3e8 (14550d749), массив по+3e0 (14550d772),
шагает по0x70 bytes (14550d779) и включает обе3double точки в min/max
границы (14550d77f..14550d813). Native descriptors14987d370/1490c1370/
1490c13b0 подтверждают PointLinks+3e0, Left+40, Right+58; это не поиск
по похожим числам. Затем14550d9fa читает Actor.RootComponent+1b8
(descriptor149168fe0),14550da0c выбирает storage корня+1d0 и последующие
инструкции читают блоки+0/+10/+40/+50. Этот потребитель сужает поиск
перевода локальных bounds; точная layout/формула/своевременность обновления
storage, отдельные world endpoints и выгрузка навигационных связей ещё
не подтверждены. Вычисление bounds не доказывает доступность перехода.

Отчёт `maps/navigation-study/lift-blueprints/bounds-code.json`, SHA256
`c807faed7693fd7d8536dd00c2d5921c84de767f02ab53b1845fdbf29fb3580d`.
EXE прежний c7552efd…; все offsets/bytes/полный SHA сохранены в report.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-lift-bounds-code.py`.
Реальная сборка прошла с проверкой18anchors/4descriptors/слота таблицы.
UI/координаты карты/пеший граф этим шагом не менялись.

## Именованные мировые getters и запись кэша SceneComponent, 18 октября

`build-component-transform-code.py` проверяет SHA клиента,4 native binding
name/function пары,32 anchors,4 property descriptors и полные bytes трёх
leaf getters без unwind записей. Полные unwind fragments остальных функций
сохранены в report. Имена привязаны по указателям на буквальные native names,
а не назначены функциям по сходству offsets.

| Имя в native registration | File offset пары | Exec wrapper | Вызываемый getter |
|---|---:|---:|---:|
| K2_GetComponentLocation | 0x91315f0 | 1437d7ac0 | 143ae5a60 |
| K2_GetComponentRotation | 0x9131600 | 1437d7b00 | 143ae5a80 |
| K2_GetComponentScale | 0x9131610 | 1437d7b40 | 143ae5b30 |
| K2_GetComponentToWorld | 0x9131620 | 1437d7b80 | 143ae5b50 |

[Документация Epic USceneComponent](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Engine/USceneComponent)
описывает эти getters как мировые location/rotation/scale/component-to-world.
Сама связь имён с конкретными bytes проверена в EXE SHA c7552efd….
GetComponentToWorld копирует96bytes начиная с component+1d0; location getter
читает3double по+1f0/+1f8/+200, scale — по+210/+218/+220.
Таким образом, ранее найденное чтение RootComponent+1d0 потребителем bounds
теперь связано с именованным мировым преобразованием. Формат вращения в первых
32bytes пока не переведён в формулу; целая96-byte структура сохраняется отдельно
от24-byte возвращаемых мировых Euler-углов.

Обновление прослежено через1425a78a0: relative rotation+140/+150 преобразуется
через1414fd980 в32-byte rotation storage, затем в call143af8c00 передаются
AttachParent(+b0), AttachSocketName(+b8) и ссылка на rotation storage.
В143af8c00 проверены чтения RelativeLocation+128/+138, RelativeScale3D+158/+168,
собственного AttachParent+b0 и ветка null→143af94de. При отсутствии родителя
translation остаётся из relative location, scale копируется из relative scale,
rotation берётся из переданного storage. После сравнений с кэшем ветка записи
143af9619..143af9644 сохраняет шесть16-byte блоков по+1d0/+1e0/+1f0/+200/+210/+220.
В report не заявлена готовая формула attached-parent/absolute flags, полный
жизненный цикл обновлений или актуальные значения живого игрового объекта.

Отчёт `maps/navigation-study/lift-blueprints/component-transform-code.json`, SHA256
`9364547805fcac87f2485c8fba80b58e1e0f225c01f5ed1709f40e7c004ab56c`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-component-transform-code.py`.
Реальная сборка прошла с проверкой4bindings/32anchors/4descriptors/leaf boundaries.
Это проверка кода клиента; игровые endpoints/проходимость ещё не вычислены.
Далее1414fd980 (rotator conversion), native CDO/post-construction значения
SceneRoot и потребитель отдельной точки. UI/Android этим шагом не менялись.

## Формулы и предварительный слой лифтов, 18 октября

`lift-transform-math.py` реализует pitch/yaw/roll→XYZW и scale→rotate→translate.
`build-lift-rotation-evidence.py` сравнил195 вращений, включая57 явных из
экспортов компонентов, с изолированной эмуляцией1414fd980 и vector trig
helper148796aa0→148799250. Максимальная ошибка quaternion5.551115123125783e-16.
Дополнительно195 синтетических transforms проверены через native bounds
consumer14550d6c0: min/max восьми преобразованных углов локального AABB,
negative/nonuniform/zero scale; ошибка1.1641532182693481e-10.
Начальный AABB клиента[(0,0,-10),(0,0,10)] установлен по константам инструкций
14550d6cf/14550d6da и включён в сравнение.

Функция сокращает углы по360, умножает на pi/360. Половинные SP/CP,SY/CY,SR/CR
дают X=CR·SP·SY−SR·CP·CY, Y=−CR·SP·CY−SR·CP·SY,
Z=CR·CP·SY−SR·SP·CY,W=CR·CP·CY+SR·SP·SY.
Порядок входа/градусы соответствует [Epic TRotator](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Core/TRotator).
Эмулятор Unicorn2.1.4 закреплён с SHA wheel в requirements-native.txt;
разрешены только адреса проверенных функций,100000instructions/2seconds на случай,
file-backed страницы EXE/отдельные stack/input/output. Единственный пропущенный
call1414fdaad→148796040 — stack-cookie check после вычислений. Код самой
тригонометрии эмулируется; игра/ОС/API/imports/живая память не используются.
Inputs/results/page SHA/model SHA и offsets/bytes/fragments сохранены в
`maps/navigation-study/lift-blueprints/rotation-evidence.json`, SHA256
`77c127bd60b1988480a88eccc398f98c33c72dfd112611aa931b867e1bd4e78e`.

`build-lift-map-preview.py` проверяет текущий EXE SHA, исходные exports/SHA,
повторное декодирование Scene properties/PointLinks bytes, ActorRoot reference,
model/rotation-evidence и общие placements/archetypes/settings snapshots.
Отдельный слой не получает World.Id по ближайшей Area/NPC и не добавляет ребро
навигационного графа. Сначала были14 связей по полностью явным transforms,
после подтверждения начальных настроек стало57 (см. ниже). UI выключен
по умолчанию: список63 лифтов, пунктирные связи, нажатие на origin/endpoints,
карточка A/B/X/Y/Z/разница высот/native direction/исходные записи и URL?lift=1818.
Камера учитывает ширину карточки. Это conditional preview: world_transform_verified
и world_coordinates_verified=false, runtime_walkability_verified=false,
walkable=null. Предполагаются отсутствие parent transform/смещения уровня/
изменений после загрузки; эти предположения явно показаны и ещё не подтверждены.

## Начальные значения клиента и расширение до57 связей, 18 октября

`build-lift-initial-values.py` повторно проверяет scene-native-defaults и SHA
EXE,26 anchors,3 descriptors NavigationLink, полные фрагменты NnLift constructor
и копирования base link,42bytes leaf constructor1438369b0. В NnLift constructor
PointLinks+3e0/count+3e8 сначала обнуляется (r14=rsi+3e0, edi=0), затем добавляется
одна запись stride0x70. Стековые координаты задаются из проверенных констант
1454fd6c9→[0,-50] и1454fd6d8→[50,0], zero block1454fd6e7.
Store1454fd748/755/762/76f задают Left[0,-50,0], Right[0,50,0].
Base link constructor1438369e4 записывает word0x200 по+28, то есть Directionbyte0;
копирование1438368dc/8e0 переносит byte+28 в добавленную запись. Смещения
Left+40/Right+58/Direction+28 сверены с native descriptors.

Все3 Blueprint default objects проверены по SHA/exports: TemplateIndex base
ведёт к `/Script/NnFramework.Default__NnLift`, Test/Type01 — к базовому CDO.
Их unversioned headers не содержат PointLinks property index8/9/8 с учётом
подтверждённых Blueprint prefix counts. Все6 Scene templates по предыдущей
проверке без явных полей. Native scale1×1×1 доказан constructor stores
SceneComponent+158/+160/+168. Это подтверждённые начальные значения до
construction/post-load/runtime изменений, не итоговое игровое состояние.

Preview допускает их только как отдельные `initial_fields`, при совпадении
sources/settings/archetypes/native terminal. Исходная placement не мутируется.
Явные параметры имеют приоритет, включая zero scale и пустой массив PointLinks.
Отсутствующий массив может наследовать одну начальную запись — случай1821.
Другие параметры записи, кроме доказанных endpoints/Direction, не заполняются.
Omitted rotation не заменяется0.

Результат:57 расчётных связей,14 полностью явных и43 с initial fields;
49 отсутствующих scale записаны как native initial (6 ещё без rotation),
один массив PointLinks унаследован. Не рассчитаны1819/1835/1826/1864/1875/1876:
нет подтверждённого вращения. Карточки отмечают начальные параметры и дают
ссылку на их доказательства. Другие лифты при выборе затемнены.

Отчёты:

- `maps/navigation-study/lift-blueprints/initial-values.json`, SHA256
  `4daa827aab3ff04713031bf7ada5d9e8370d3b292481b1bad18a23825887655b`.
- `maps/atlas/lift-preview.json`, SHA256
  `341731ad0e697157337d93ceaecb69ce0bfcdfd15ccafe45fa647abe865b3017`.

Порядок: blueprints/placements→instance-settings→point-links/archetypes→
build-lift-initial-values.py; rotation-evidence должен соответствовать модели,
затем build-world-map.py→lift-preview. Scene содержит file/SHA/summary preview,
браузер проверяет SHA. Source SHA и bytes/offsets сохранены в отчётах.
55 целевых Python+21Node/JS syntax прошли. Тесты защищают оси/знаки/формулу,
separate initial provenance без мутации, приоритет explicit0/empty array,
наследование missing array при сохранении неизвестного rotation.
В браузере проверены1818(scale),1821(scale+links),1819(unknown rotation),
reload поURL/zoom/нажатие на отметку,0console errors. Снимки
`maps/atlas/lift-preview-checked.png` и `lift-inherited-checked.png`.
Далее native default rotation/привязки/смещение уровня/условия активации.
Эти57 связей не объявлены проверенными маршрутами и не используются ботом
для автоматического прохождения.
После успешных проверок57links браузер отключён в настройках Work. Последняя
косметическая правка прозрачности соседних лифтов/отступов A/B прошла JS syntax,
но повторно визуально не проверена; сохранённый снимок сделан до этой правки.

## Ветка обнуления перед конструктором компонента, 18 октября

`build-object-zero-init-code.py` проверяет SHA EXE,24anchors и полные unwind
фрагменты четырёх функций. Продолжена ранее доказанная цепочка создания Scene:
141746350 вызывает1417cd8a0 (14174640f), тот вызывает1417e0fc0
(1417cdbcd), затем вызывается1417e0420 (1417e10c4).
Это конкретный путь native default-subobject construction.

В allocation функции ветка1417e0bbb..1417e0bce передаёт destination=rdi,
edx=0 и размер из stack+64 в r8. Длины сохраняются из+58 class storage
в1417e050a/050e и1417e055a/0561; полный контроль пути/размера для каждого
вида повторного создания пока не завершён. Вызов1487a2e25 —6-byte indirect
jump через IAT148945848. PE import directory/OriginalFirstThunk разрешает
его в VCRUNTIME140.dll!memset. Сохранены descriptor/thunk/name/dll offsets
и bytes. Разрешитель ограничивает таблицы/строки, проверяет terminator до
выбранного thunk, отклоняет ordinal.

Исключения: test r12b1417e0bbe и jump1417e0bc1 могут обойти memset;
устанавливающая r12b ветка1417e099e присутствует в полном отчёте. После
возврата allocation общий constructor path читает callback из class+0xb0
(1417e10ed), вызывает его1417e1238, затем выполняет finalization1417c61a0
(1417e1240). Zeroing branch не доказывает, что последующие constructor/base
callbacks/finalization не изменят RelativeRotation. Нулевое итоговое вращение
не заявлено, шесть omitted значений не заполнены.

Отчёт `maps/navigation-study/lift-blueprints/object-zero-init-code.json`, SHA256
`c50c969756def9763dd5c82efede055d32835ac3e0d5a38d9162331df46ef757`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-object-zero-init-code.py`.
Native source EXE SHA прежний c7552efd… (полный в report). Реальная сборка
прошла;59 целевых Python-проверок успешны.4 новых проверяют точный именованный
import, unaligned/after-terminator target, ordinal/unterminated strings,
invalid directory. UI/математика/слой57links не менялись; навигационный граф
по-прежнему не имеет подтверждённых маршрутов.
Следующий участок: base constructor callbacks и finalization1417c61a0,
потом итоговые initial rotation и проверка frame/attachments.

## Копирование шаблонных свойств после конструктора, 18 октября

`build-object-template-copy-code.py` проверяет43 native anchors, SHA EXE,
полные unwind fragments,2Scene vtable slots и bytes пустого callback.
1417c61a0 при отсутствии initializer template может читать class+110
(1417c626d/6288/628d/6294); ветка1417c62b7 передаёт управление1417d7840.
Там initializer flag+11 управляет основной property initialization:
template берётся из initializer+8 (1417d79fe), при null из class+110
(1417d7a0e), объект назначения — initializer[0]. Call1417d7a20 вызывает
1417d4d10. Отдельный16-byte-stride цикл subobjects использует тот же copier
в1417d7a92, то есть инициализация Scene не сводится к memcpy всего родителя.

В copier destinationobject=r14, sourceobject=rbp. Одна из проверенных ветвей
читает runtime property offset по+44, множители длины по+30/+34,
формирует source=template+offset,destination=object+offset и при flagbit30
выполняет raw copy (1417d4dfd..1417d4e35). Точная6-byte trampoline1487a2e19
разрешена через PE import table в VCRUNTIME140.dll!memcpy; исходные
descriptor/thunk/name/dll bytes/offsets сохранены. Альтернативная ветка
вызывает property virtual slot+100 (1417d4e48). Другие copy-loop branches
и class virtual+398 также сохранены в полном фрагменте.

Это runtime FProperty layout, не56-byte compile-time native registration
descriptor. Их offsets/flags нельзя считать взаимозаменяемыми; конкретный
runtime FProperty RelativeRotation и источник24bytes CDO здесь не восстановлены.
Поэтому generic property-copy branch не означает доказанный default0rotation.

Post-init calls:1417d7c2c использует subobject vtable+58,
1417d7c88 — object vtable+50. Scene ctor143ac140e/1415 назначает table14912fde8;
её slot+58→1413fe190 содержит `ret0`, slot+50→143a537b0 вызывает1417d7d10
и условно переходит1438002a0 после чтения component+90. Дальнейшие вызовы
и callbacks пока не объявлены не влияющими на rotation/attachments.

Отчёт `maps/navigation-study/lift-blueprints/object-template-copy-code.json`, SHA256
`e81a960fc6bd16d00369814e6cfddbf7e778b4d6e911f1d55cb942672cb9aef1`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-object-template-copy-code.py`.
Реальная сборка прошла, source EXE SHA c7552efd… полный в report.
UI/граф/57conditional links не менялись;6rotations остаются unknown.
Далее конкретный источник native Scene CDO/runtime properties и callbacks;
только затем разрешение оставшихся initial rotations и attachment/frame.

## 18 октября — размещение подписей без перекрытий

В world-map.js раньше occupied учитывал только другие подписи, причём
без полного фонового padding и верхнего/нижнего ограничения. Слишком
плотные подписи/значки делали обзор нечитаемым. Теперь чистая функция
WorldMapModel.placeLabels получает измеренные CSS-pixel размеры текста
с padding, видимые маркеры и прямоугольник открытой карточки. Порядок:
выбранная область, экранныеX/Y, исходныйkey. Каждый кандидат проверяется
справа/слева/сверху/снизу, затем со смещениями24..120px. Между прямоугольниками
4px зазор, по краям4px. При отсутствии места скрывается только подпись.
Длинные подписи получают многоточие вместо сжатия canvas maxWidth.
Отнесённые более20px подписи связаны тонкой линией с исходной точкой.

Все маркеры/исходные записи и поиск сохраняются; это размещение надписей,
не изменение игровых координат, границ или связей. Счётчик названий
добавлен в viewScale. Никакой новой игровой связи/семантики не введено.
Существующие Area.label/point.key и проекция используются без изменения.

Проверены30Node tests, включая плотное размещение/отступы/неизменность
входа/повторяемость/приоритет выбранного/смену стороны у края. JS syntax
пройден, source/deployed world-map.js/model совпадают. Живая проверка
встроенного браузера: общий94% —59из172подписей,240% —49из120подписей
в окне; всего24071запись. Снимки05-labels-overview.png/06-labels-zoom.png
в phone-exit/.tools/ux-audit-321001. Пересечения соединительных линий
между собой не запрещены; видимость надписей зависит от масштаба и размера
окна. Остальные разрешения отдельно не проверены. Навигационная готовность
и неизвестные вращения остаются без изменений.
