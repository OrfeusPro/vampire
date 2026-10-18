# Справочник характеристик

## Непроцентные специальные масштабы

18 октября: разобрана compact dispatch таблица в formatter145dda3a0:
код145dda4ed вычитает315, unsigned range-check≤150; затем151byte selectors
145dda798 и4target RVAs145dda788 выбирают реальные instruction boundaries.
Targets145dda51b/145dda5f3/145dda684/145dda698. Данные jump-table сохраняются
как data anchors, а не декодируются инструкциями.

IsPercentage проверяется **раньше** switch и имеет приоритет. При false:

| OperationType | Параметр | float32 scale | Дробный формат | Суффикс |
|---|---|---|---|---|
| 315 | Max Weight Capacity | 0.01 (100→1) | %.2f | нет |
| 453 | Monster Suppression | 0.001 (1000→1) | %.1f | нет |
| 454–459 | Status Effect Hit Chance по редкости навыка | 0.1 (10→1) | %.1f | нет |
| 460–465 | Status Effect Resistance по редкости навыка | 0.1 (10→1) | %.1f | нет |

В этих ветках integer shortcut использует тот же fmodf/abs≤1e−8 predicate,
но suffix literal `%s`, **не `%s%%`**. Специальный масштаб не равен процентному
типу. Физические единицы веса (кг и т.п.) и смысл1единицы suppression не
угадываются. Вне315…465 unsigned-range-check ведёт в unscaled branch.
По всем185текущим CSV1427 records:76percent,14scaled_number,95integer/unscaled.
Это классификация маршрута отображения int32, не полный формат итоговых
строк/локализации и не Stat→Stat computation.

Воспроизведение:
`python -X utf8 phone-exit/bots/resource-tools/vampir/build-stat-format-routes.py`
→ `build-catalog-pages.py` (после прежних proof build шагов).
Инструмент расширяет StatFormatEmulator, статически проверяет switch,
literal constants/templates, исполняет **реальный dispatch и scaling**.
2307cases:1665по185табличным rows,14unit examples,628boundary/flag-precedence
cases на151switch IDs и6внешних/предельных int32 IDs ×2flags ×2values.
fmodf остаётся явным shim; CRT formatting/allocations не исполняются.

Отчёт `code-clues/stat-format-routes.json`:19anchors/11fragments, tables/
constants data anchors,185rules и все cases. build-attributes.py повторно
сверяет CSV/EXE/code/data SHA и добавляет display_format каждому параметру,
display_routes сproof URL/SHA; schema6.14специальных карточек теперь
показывают масштаб и число знаков, остальные статсвязи/формулы не меняются.

9Python+7Node=16tests прошли, включая38distributed native replay cases,
3прямые проверки приоритета percent/range boundary и проверку table bytes.
JS syntax/HTTP/deployed/data+proof SHA пройдены. UIversion20261018-display-routes.
Visual QA остаётся. Current attributes.json SHA:
`143cafa2e83d616348690a2628c4845924f6fb058dbe5cee77e3aaf0bef4d2d2`;
routes proof SHA `a9a1dca3ce1e75315973c847d9d1b3a61550bd40196056c89361b6be9be212d1`.

## Процентная ветка отображения восстановлена

18 октября: при поиске consumer детализации проверены pointer references
на handler146767e10 и соседние реализации; новая цепочка применения
StatDetailDataList не доказана. Перспективнее оказался уже найденный
вызов145eacdab→145dda3a0: это форматирование значения OperationType.

`build-stat-format-evidence.py` воспроизводит и сохраняет
`code-clues/stat-format-evidence.json`.10anchors/11fragments связывают:
CSV loader IsPercentage → byte record+0x8c (`145af0d2b`),
lookup145b03700 → CMP byte[record+0x8c],0 (`145dda3eb`). Если ненулевой:

1. signed int32 аргумент изEBX → float32 (`145dda400/404`);
2. float32 multiplication на0.01 (`145dda407`, constant14898d13c bytes0ad7233c);
3. fmodf(scaled,1.0), abs remainder, compare сfloat32≈1e−8;
4. при remainder≤threshold — integer branch сCVTTSS2SI и`%s%%`;
   иначе decimal branch c`%.2f`, затем тот же suffix`%s%%`.

Константы/форматные строки закреплены bytes/SHA. CRT import1487a2f03
подтверждён через IAT как api-ms-win-crt-math-l1-1-0.dll!fmodf.
Эмулятор выполняет настоящую branch/scaling code145dda3eb до трёх terminal
адресов, fmodf заменён явным Python math.fmod+float32 shim сdenominator1.
CRT text formatting/allocations/весь formatter не исполнялись.

Важная граница дизассемблирования: .pdata range145dda3a0…145dda82f содержит
switch data послеRET145dda787. Code span явно145dda3a0…145dda788;
таблицы не считаются инструкциями. Непроцентная ветка имеет отдельный
switch и scales; её правила здесь не реконструированы и не распространяются
на остальные109строк. В частности, код не доказывает, что все raw значения
или raw64bit packet payloads измеряются в сотых процента.

76записей CSV1427 имеют IsPercentage=1. На всех185записях проверены9int32
значений0/1/3/50/100/150/−1/−100/16777217:1665native cases, включая пропуск
процентной ветки109строк.100→scaled1/integer,150→scaled1.5/decimal.
Отображение100→1%,150→1,50% объяснено в карточках процентных характеристик;
значок% теперь имеет соответствующую title-подсказку. Формулы исхода боя
и Stat→Stat граф этим не расширялись. Масштаб отображения установлен,
реальное изменение шанса/урона от прироста стата остаётся неизвестным.

Порядок сборки после предыдущих proof инструментов:
build-stat-format-evidence.py → build-catalog-pages.py. build-attributes.py
сверяет source/anchors/fragments/constants и включает percentage_format;
schema5,stat_calculation_verified=false. Старые записи «масштаб неизвестен»
ниже описывают предыдущие этапы; текущий вывод ограничен этой функцией
отображения, не переносится автоматически на предметы/эффекты/пакеты.

8Python+7Node=15tests прошли. Новая проверка повторяет36распределённых native
cases+100/150 и сверяет bytes/SHA; syntax/HTTP/deployed/data+proof SHA
прошли. UIversion20261018-percent-units, visual QA остаётся. Current
attributes.json SHA `bdd42b1899873025090ac7f9813d2db3381ef3515f822d16f114f0c7b7d8e836`;
format proof SHA `7995a914b06c631d18128d404f9e33773d3b185b5ecf8530e16cf49ef3273513`.

## Новая зацепка: подробные структуры статов клиента

18 октября: найдены и связаны через **реальные vtable slots**, а не одно
соседство строк, PktStat/PktStatCategoryData/PktStatExtraCategoryData/
PktStatDetailData. Результат `code-clues/stat-packet-evidence.json`:
17anchors/16fragments,12vtable pointer anchors и literal names/provenance.

Схема памяти и вызовов IO (не готовый decoder сетевых байтов):

| Структура | Подтверждено в коде |
|---|---|
| PktStat | key dword+8, raw qword value+0x10; reader1457f0540/writer1457f4360 |
| PktStatCategoryData | category byte+8, raw qword value+0x10; reader1457f0590/writer145784940; read category clamp≤29 |
| PktStatExtraCategoryData | raw qword value+8; writer14579af70/reader145798060; отдельное поле category не найдено |
| PktStatDetailData | key+8, массив category+0x10, массив extra+0x20; reader1457f0660/writer1457f4430 |
| PktStatDetailInfoReadResult | literal StatDetailDataList, reader1456c1f20 и field-name1456cba12 |

Типы связаны name getter и read/write slots одной vtable:
PktStat1498d1b30, Category1498d2638, Extra1498d2680, Detail1498d26d0.
Сами имена внутренних полей/семантика key не придуманы; в отчёте они
обозначены key/raw payload. Подписи конкретных категорий и привязка их
чисел к экипировке/коллекциям/уровню **не найдены**. Clamp29 не доказывает
29доступных источников: значение может включать sentinel, enum пока не связан.
Формат показывает наличие категории/значения, не формулу между статами.

Есть точная строка `PktStatDetailInfoReadResultHandler::OnHandler()`:
offset0x9d67220, RIP LEA146767e14. Полностью декодированная функция146767e10
с этой строкой выполняет построение/логирование строки; переноса packet
данных в модель персонажа в ней нет. Другой обработчик/consumer не исключён.
Нельзя из этого заключать, что детализация работает в текущем клиенте,
получена с сервера или что все формулы обязательно вычисляются на сервере.

Воспроизведение:
`python -X utf8 phone-exit/bots/resource-tools/vampir/build-stat-packet-evidence.py`
→ `build-catalog-pages.py`. Требует тот же закреплённый Unicorn/Capstone,
read-only EXE/SHA. Native тела двух readers и двух writers исполнены,
primitive virtual IO подменён явными stubs.1392roundtrips:208synthetic keys
×3raw payloads для Stat и256category bytes ×3raw payloads для Category.
Payloads0,2^53+1,2^64−1 сохраняются бит-в-бит; это не float64 и не JS Number.
Плюс8случаев отказа первого/второго primitive call: native false и ранний
выход подтверждены. Всего1396readers+1396writers=2792native executions.
Настоящее wire encoding, signedness payload, nested vector allocations,
socket/login/game execution и runtime state не использовались/не восстановлены.

В карточке стата добавлено свёрнутое объяснение найденной детализации и
ссылка на proof. Никакие категории, численные значения персонажа и новые
Stat→Stat рёбра не заполняются заглушками. Граф остаётся13описательных связей.
build-attributes.py проверяет source SHA, anchors/fragments/vtable bytes и
передаёт только schema_verified=true/formula_verified=false/
live_values_available=false/category_names_verified=false.

Полный актуальный порядок для нового ресурса:
build-attribute-weight-evidence.py → build-attribute-score-context.py →
build-stat-packet-evidence.py → build-catalog-pages.py. Ранее подготовленные
native-enums/table-dependencies/item-skill-binding/CSV должны быть доступны.

7Python+7Node=14tests прошли; новая проверка повторяет12reader/writer cases
и8failure cases, независимо сверяет все bytes/SHA. JS syntax,4HTTP/source
сверки и data/proof SHA прошли. UIversion20261018-stat-detail. Visual QA
по-прежнему не выполнена. Current attributes.json SHA:
`0740c07fbc9c3420ac18c419555a7fc1b86193152f526230b3efa81bc84364ff`;
packet proof SHA `58aa8bbca328285a2e1aacda2a63652f9faaaadcff06d8ea1623f8427d914828`.

## Установлен потребитель оценки: сравнение предметов

18 октября: caller145db6fb0 найден через direct E8 callers145d2da30.
Полная цепочка в `code-clues/attribute-score-context.json`:

- Candidate owner+0x18 →145a80590 (существующая проверенная Item lookup
  binding из item-skill-binding.json повторно сверена по SHA/anchors/data).
- Проверки145db9d00/145db73c0/1455baad0 предшествуют сравнению. Их полные
  правила не восстановлены в этом этапе, в эмуляции они задаются Boolean.
- Item.EquipmentType: literal145aa2969, parsed byte write145aa29b4→info+0x61;
  caller145db7034 передаёт это поле вR8 lookup1455b5b10.
- Полученная запись слота →+8identifier →145d342d0, затем score145d2da30
  вызывается для найденного peer и candidate.145db706e CMP EAX,EBX;
  145db7075 SETG AL: **signed candidate score > peer score**, равенство false.
- Нет slot/peer: true только после всех предыдущих gates; ранее отклонённый
  candidate возвращает false. Поэтому локальный comparator не равен одному
  безусловному сравнению двух чисел.
- UI call sites1463b7775/1463b7f1e используют comparator result после
  Item info+0x50==1. Результат управляет аргументом4/1 для вызова виртуального
  метода элемента по UI owner+0xc68 (слот+0x2d8). **Имя/ресурс этого виджета,
  enum-смысл4/1 и его привязка к пикселям ещё не доказаны**; не называть
  подтверждённым конкретную стрелку/иконку «лучше».

Сборка `build-attribute-score-context.py` → `build-catalog-pages.py`.
Отчёт16anchors/16fragments, literal EquipmentType и inherited binding SHA;
native comparator исполняется целиком с9явными stub-callees (lookups,
допуск, score). Существующий handle pointer getter141482990 исполняется
из клиентских байтов.320cases =64комбинации6gates ×5пар scores, включая
равенство и signed int32 endpoints; отдельно320исполнений UI selector
1463b77ac…1463b77b5. Все совпали с ожидаемой truth table. Stubs не доказывают
живые правила допуска/выбор слота/полный score; лишь позволяют проверить
реальное ветвление comparator. Входные поля и slot-key проверены, возврат
и nonvolatile RBX/RDI контролируются. Запуска игры/OS calls нет.

Это подтверждает использование веса **в сравнении предметов**, не формулу
итоговых статов и не общую боевую мощь персонажа. Калькулятор в UI теперь
так и озаглавлен; объяснение comparison отдельно от арифметики. Рёбер к
CombatPower не добавлялось. Другие indirect uses score не исключены.

build-attributes.py проверяет новые fragments/anchors/literals/EXE SHA,
inherited binding SHA и включает item_comparison_context с proof URL/SHA.
Current attributes.json SHA:
`d3b00ccf4a925a9e8ff5dc3f56ce869b0f2169ea33d71ff6fb0b89ee8888b792`;
context SHA `e2951392a29eb0ef381d59b6a35fec98f9dc11768e267ca0f43e6c070e3b2c8d`.
6Python+7Node=13tests прошли, включая31comparator+31selector replays,
weight native replays/JS comparisons. Syntax/HTTP/deployed/data+proof SHA
проверены. UIversion20261018-item-score. Visual QA остаётся незавершённой.
Следующий отдельный след Stat→Stat: потребители StatType record+0xc;
это другой вопрос, не закрытый обнаруженным сравнением предметов.

## Native зацепка: взвешенный вклад, 18 октября

Найден и полностью дизассемблирован загрузчик OperationType.csv
`145af0430`. Literal filename145af0509, headers OperationType145af05cd,
StatType145af05e4, CombatPowerWeight145af064e; массив заголовков и word
индексов связывает StatType со вторым столбцом, CombatPowerWeight с восьмым.
Прочитанный StatType пишется dword в record+0x0c (`145af08ad`),
CombatPowerWeight читается через reader1445ef9f0,
вызов145af0d06, затем запись word в record+0x8a (`145af0d0b`).
Полные байты/инструкции, а не только эти строки, сохранены в evidence.

Конструктор node145ad69f0 задаёт vtable14999acc0 и начальный StatType0xcf;
lookup145b03700 возвращает shared info, потребитель145d2da30 обращается к
OperationType info и трижды читает **signed int16** record+0x8a, умножает
на int32 значение и суммирует вклад. Три участка:

- 145d2dc54…145d2dc79: значение вEBX;
- 145d2dd06…145d2dd2c: значение[RBX+0x10];
- 145d2ddde…145d2de04: значение[RDI+0x24].

Они исполняют MOVD/CVTDQ2PS → MULSS → ROUNDPS imm1 (floor) → CVTTSS2SI →
ADD ESI. Результат локально кэшируется в owner+0xf0, valid byte+0xf4.
**Идентичность owner, связь со всей боевой мощью персонажа, применимость
каждого стата в каждой ветке и полный вызов не доказаны.** Это численная
зацепка из реального кода, не новое ребро Stat→CombatPower и не расчёт
шанса попадания/урона. Native caller145db6fb0 вызывает145d2da30 дважды;
полный его контекст ещё предстоит разобрать.

Воспроизведение:
`python -X utf8 phone-exit/bots/resource-tools/vampir/build-attribute-weight-evidence.py`
→ `build-catalog-pages.py`. Первый инструмент требует закреплённые capstone/
unicorn в phone-exit/.tools/vampir-analysis, использует read-only EXE с SHA
c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
Отчёт code-clues/attribute-weight-evidence.json хранит16anchors/11fragments,
3блока, все861cases/2583native executions.171заполненных CSV weights
проверены на значениях-7/-1/0/1/25;14пустых не подставляются нулём.
6дополнительных случаев проверяют float32 precision, signed weights,
int32 conversion overflow и wrap накопителя. Память входов проверена
неизменной, code page read+execute, не вызываются OS/game/allocators.

Это исполнение только трёх bounded math blocks; parser/lookups/loops/cache/
callers не исполнялись. Вне int32 CVTTSS2SI возвращает INT_MIN; UI вместо
расчёта сообщает выход за диапазон, накопитель UI всегда0. Браузерный
модуль повторяет f32 rounding и floor, -0 нормализован к integer0.

Карточки содержат раздел «Найденный расчёт с весом параметра», integer
input и ссылку на proof.171параметр с весом допускает локальную проверку
арифметики,14без веса показывают отсутствие данных. Нет вывода процентов
из IsPercentage и нет обещания итоговой боевой мощности.

build-attributes.py проверяет CSV/EXE SHA, все anchors/fragments proof и
добавляет weight_math с proof SHA/flags. Текущий attributes.json SHA
f848d358a446f095225c710be189611a52fe2b246b1fc10c2827cbde154085cb;
proof SHA d2b4519ccdfa7a744703c8dd04d4a2034c4b0e1020bf88f2565a94b1b5b25365.
7Node+5Python=12tests прошли: JS сверяется со всеми857captured native cases
в поддержанном диапазоне/нулевом accumulator, Python перепроверяет bytes/SHA
и18native replays крайних случаев. Syntax/HTTP/deployed/proof/data SHA
сверены; UI version20261018-weight, визуальная проверка остаётся.

## Продолжение: StatType и противодействия

18 октября: CSV1427.StatType теперь дополнительно соединён с EStat.value
из уже извлечённого native-enums.json. Для всех181конкретных значений имя
EStat совпало с суффиксом EOperationType; это контроль согласованности,
не способ угадывания join. Строки EStat повторно сверены по ASCII+NUL
name_offset в SHA-проверенном EXE. В карточке и исходных данных есть
stat_binding: enum/value/status/native_calculation_verified=false.

Четыре OperationType2051Synergy/2052CombatPower/2057PetAdventureIntervalReducer/
2058PetAdventureBonusRate имеют StatType207=EStat::Max. Это sentinel enum,
а не один общий вычисляемый стат и не основание связывать эти четыре
параметра друг с другом. Карточки объясняют служебную привязку; строки
не скрываются. Мapped181/sentinel4, unknown0.

Граф расширен до13связей:8modifier/5opposed. Добавлены
CriticalResistanceRate↔CriticalRate,
IgnoreCriticalDamageMultiplier↔CriticalDamageMultiplier,
CharacterAntiDeadlySkillFireRate↔CharacterDeadlySkillFireRate.
Это взаимное участие в исходе боя по точным описаниям CSV486, не доказанное
вычитание значений или изменение статов противника. Фразы об неизвестных
порогах, порядке и базе расчёта сохранены в UI; formula=null.

Ограниченное исследование native имён воспроизводит
`python -X utf8 phone-exit/bots/resource-tools/vampir/study-attribute-native.py`.
Отчёт `code-clues/attribute-native-discovery.json` содержит SHA EXE, шаблоны
ASCII/UTF16LE идентификаторов, список запросов,10найденных строк с offset.
Найдены только enum EStatConvertType и его значения; ими нельзя доказать
функции преобразования или коэффициенты. Отсутствие имён функций в этом
поиске не доказывает отсутствие stripped native/server расчёта. Дизассемблирование
и исполнение самих функций расчёта статов в этом этапе не выполнены.

4Python+5Node=9тестов прошли, включая все EStat joins/bytes и четыре sentinel;
syntax/HTTP/deployed/data SHA сверены. Версия UI20261018-stat-binding.
Текущий SHA attributes.json:
`8d042da45a2c4b020a16d618ee1143c78fcfda93757ea3350ecf666f8c19d0b7`.
Предыдущий SHA ниже относится к этапу10связей, актуальный берётся из manifest.

## Карточка и дерево связей, 18 октября

Нажатие имени открывает `index.html?stat=ID`; параметры q/tab/unit сохраняются
в URL соседей и возврата. Дерево одного шага: входящие усиления слева,
выбранный стат в центре, исходящие справа. Нажатие соседнего узла меняет
выбранный стат. На узком экране блоки идут вертикально. Это локальное
представление графа, не бесконечное раскрытие всех веток; циклы не вызывают
рекурсии. Сравнения с противником вынесены отдельно, не смешаны с усилениями.

`attribute-relations.py` вызывается из build-attributes.py; schema2 содержит
10curated links:8modifier и2opposed. Источник — дословные описания CSV486,
сохранены name_source/row/provenance обеих ролей и точная evidence.statement.
Ожидаемое описание сверяется полностью; изменение вызывает ошибку сборки.
Связи не генерируются по одному сходству имён или числовых ID.

Подтверждённый объём — семантика описания клиента, **не native формула**:
HpRecoveryMultiplier→HpRecovery, MpRecoveryMultiplier→MpRecovery,
HpPotionRecoveryMultiplier→HpPotionRecovery,
MpPotionRecoveryMultiplier→MpPotionRecovery,
ItemDropRateMultiplier→ItemDropRate, MoveSpeedMultiplier→MoveSpeed,
HealMultiplier→HealValue, ReceiveHealMultiplier→HealValue.
Стрелка указывает на затрагиваемую величину/эффект, а не доказывает прямую
модификацию хранимого значения target. Для potion/heal не доказана база
множителя, порядок сложения/умножения; ReceiveHeal относится к получателю.
Это оговорено и в общем пояснении, и на соответствующих связях.

Opposed: HitValue↔DodgeValue (разница ACC атакующего/EVA цели влияет на шанс
попадания), DefensePower↔AttackPower (разница DEF получателя/ATK противника
участвует в уроне). Stored source/target технические: UI показывает связь
при выборе любой стороны как взаимодействие, не изменение одного стата другим.

У каждой связи formula=null/native_formula_verified=false/runtime_verified=false,
evidence.level=client_description. Формулы, коэффициенты, clamp/округление,
runtime активация и единицы процентов ещё не восстановлены. Для остальных
параметров отсутствие найденной связи не означает отсутствие зависимостей.
Сила/ловкость и другие базовые параметры из пользовательского примера
не выдумываются: в собранных185OperationType такой отдельной системы нет.

Проверены также конфигурации CSV61/68/162 и существующий индекс таблиц:
явной таблицы формул Stat→Stat здесь не найдено; это ограниченная проверка
индекса/конфигураций, не доказательство отсутствия формул в клиентском коде.
Настоящий native расчёт статов остаётся дальнейшим исследованием.

Текущий SHA256 attributes.json:
`39539cec127d81fe40c1025eb93e28a386e65cddf21d80d4ba4b2d4c0ed070b7`.
5Node+3Python tests прошли: точные источники/joins, изменение evidence
отклоняется, противоположные роли/направления/неизвестные endpoints разделены,
циклы не разворачиваются рекурсивно. Syntax/4HTTP-source сверки/data SHA
прошли. CSS/JS version20261018-tree. Визуальная проверка остаётся незавершённой.

ID теперь расположен сразу после имени мелким текстом в том же заголовке; нижняя строка ID удалена. CSS/JS version20261018-inline-id, syntax/HTTP/deployed сверены. Данные прежние.

По уточнению пользователя IsPercentage=1 показан знаком `%`, InvisibleStat=1 —
SVG перечёркнутого глаза рядом с названием, перед действиями. Текстовые
метки этих флагов убраны; пояснения сохранены в title/aria-label, значки
доступны Tab. Условия по исходным флагам прежние; это графика справочника,
не новая игровая связь. CSS/JS version20261018-symbols, syntax/HTTP сверены.

Оформление уплотнено по замечанию пользователя: название и SVG-кнопки
коллекций/исходных данных в одной строке; описания в hover/focus подсказке,
ID/флаги маленькими метками. Кнопка источника раскрывает прежний JSON с
aria-expanded/aria-controls. Ссылка коллекций сохраняет точный bonus ID.
Новые иконки — графика интерфейса справочника, не ресурсы игры. Данные и
игровые связи не изменены. CSS/JS version20261018-compact; syntax и HTTP
сверены, визуальная проверка по-прежнему не выполнена.

18 октября 2026. Страница `maps/attributes/index.html`, пункт общего меню
«Характеристики». Пример пользователя использован как идея колонок;
группировка взята из клиентских таблиц, не из присланного изображения.

## Источники и сборка

`python -X utf8 phone-exit/bots/resource-tools/vampir/build-catalog-pages.py`
разворачивает HTML/JS/CSS и вызывает `build-attributes.py`. Отдельный запуск
последнего пересобирает данные в `F:/PhoneExit Resources/Vampir/maps/attributes/`.
Manifest сохраняет SHA256 всех источников и результата, EXE, native diagnostics;
каждая CSV-запись содержит entry/csv_record. UI проверяет SHA данных.

- CSV1427:185 OperationType definitions, включая StatType, DisplayGroupId,
  DisplayOrder, CombatPowerWeight, IsPercentage, UnusableAttackApplyType,
  InvisibleStat. Это все строки этой таблицы, не365enum operations: enum
  также содержит действия/контроль, не определения характеристик.
- CSV1428:12групп, DisplayGroupId=GroupId; OperationTabId и GroupOrder.
- CSV485:4английских имени вкладок по Id=OperationTabId: Default/DMG/Support/
  Special. Русские подписи «Основные/Урон/Поддержка/Особые» — перевод для UI.
- CSV486:185локализованных имён/описаний; по суффиксу EOperationType.name,
  который сопоставлен с CSV1427.OperationType через enum.value.
- `code-clues/native-enums.json`, `table-dependencies.json`, установленный
  клиентский EXE; SHA сверены. Native diagnostic UTF-16LE byte checks:
  offset161062914 OperationType.DisplayGroupId→OperationTypeGroup;
  offset161060626 OperationTypeGroup.OperationTabId→OperationTab.
  Строки enum по name_offset проверены как ASCII с завершающим NUL.

CSV484.GroupId имеет другую систему IDs100/200/…; его имена НЕ присоединяются
к CSV1428.GroupId101/102/… через округление или похожие числа. Подгруппы
показаны разделителями по явной смене GroupId. CSV485 роль поддержана
заголовком/точными ID/diagnostics; binary parser binding заново не извлекался.
Cooked-таблицы/EXE — данные/код клиента, не исходный C++ проект.

## Отображение и границы

185строк: Основные42, Урон51, Поддержка12, Особые31, без назначенной группы49.
InvisibleStat=1 у2строк: включены с подписью исходного флага. УSynergy2051
нет соответствующего имени в CSV486: показан ID, описание отсутствует явно.
Никакие записи не скрываются из-за отсутствия группировки или имени.

Сортировка: числовая вкладка, GroupOrder, DisplayOrder, OperationType;
неизвестные значения после известных. Это порядок справочника по явным
полям, не новое доказательство полного runtime comparator.

Поиск в имени/описании/ID/enum/StatType; фильтры вкладки и процентного типа
пересекаются. q/tab/unit сохраняются в URL. Якорь #attribute-ID выделяет
характеристику и допускает прямую ссылку. Описания доступны при наведении/
фокусе имени, исходные поля/происхождение раскрываются кнопкой. Иконка коллекций
передаёт точный OperationType в существующий фильтр bonus. Нулевой результат
допустим: не каждому параметру соответствует коллекция.

Личные значения/шестиугольник/боевая мощь не имитируются: данных аккаунта нет.
IsPercentage отображается как тип; масштаб и формулы процентов не выводятся.
CombatPowerWeight сохранён только в исходных данных, итоговая мощь из него
не рассчитывается. Ограничения применения/InvisibleStat — поля клиента,
не проверенная серверная активация.

## Проверки

`node --test phone-exit/bots/test_vampir_attributes.cjs` —3теста:
числовые вкладки/группы/порядок, поиск/пересечение фильтров, нулевой/пустой
порядок и сохранение скрытых строк. `python -X utf8 -m unittest discover
-s phone-exit/bots -p test_vampir_attributes.py` —2теста с независимым чтением
всех строк, полных joins, локализации, SHA, native diagnostics и enum bytes.
Все5прошли; JS syntax и5HTTP200/source-deployed сверок прошли. Сервер
127.0.0.1:17946 запущен. Визуальная проверка новой страницы не выполнена:
ранее browser tool отклонил URL policy, обход альтернативным инструментом
не применялся.
