# Vampir — таблица задач

Обновлено: 18 октября 2026. Главная точка входа: [README.md](README.md).
Это единый актуальный список; подробные доказательства и история — по ссылкам.

Статусы: **Готово** — указанная работа выполнена и проверена в указанном объёме;
**Частично** — есть результат, но критерий завершения ещё не выполнен;
**Осталось** — следующий объём работы. Проверка на кадрах не заменяет Android.

## Отдельное направление: самостоятельный сетевой бот

18 октября: пользователь запросил работу без игры, 10–20 аккаунтов, Windows
с переносимым ядром Android, онлайн 2D-карту, небольшую нагрузку и обновление
данных при еженедельных выпусках. Отдельные [задачи H/U/P/A](../vampir-headless/TASKS.md)
и [журнал](../vampir-headless/WORKLOG.md); общий [индекс функций](FUNCTION-INDEX.md).
H00/H01 выполнены в ограниченном статическом объёме; H02 закрыт для 10 типов/
5 ответов (vtable/constructor/ID/IO targets и регистрация, 4 audit tests).
Далее H03 wire/context и H04 auth. Карта и экранные задачи ниже сохраняют собственные статусы.

H03a: native Ping body IO и переносимый stdlib codec готовы в ограниченном
объёме (126 native cases/5 tests), H03 всё ещё частично. Следом complete framing/
send/receive H03b; подробности в задачах сетевого бота и FUNCTION-INDEX.

H03b.2b-block: общий bounded decoder, 166 valid / 86 invalid native cases,
статическая связь второго listener stage; [доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-BLOCK-DECODE.md).
Полный receive/CRC/send queue/auth остаются в задачах сетевого бота.

H03b.2b-listener: второй native receive loop (44 cases/5 tests), общий
receive-A extractor. Container lifecycle fixtures/final capture; Dispatch/CRC ещё
не проверены. [Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LISTENER-LOOP.md).

H03b.2b-dispatch: 24 native cases/4 tests до PingResult OnHandler entry,
wrapper 8→10 и cleanup доказаны; body capture/registry fixtures.
[Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-DISPATCH.md). Receive-B/CRC/auth остаются.

H03b.2b-receiveB: 39 native cases/4 tests, keyed XOR→ID bookkeeping→Dispatch;
remove до reader, без CRC в исследованном B пути. Полная сессия ещё не готова.
[Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-RECEIVE-B.md).

H03b.2b-sendB: 40 native cases/5 tests, Ping/KeyChanged и synchronous queue copy;
общие encoders/byte-frame bounded queue. Drain/socket/auth ещё не готовы.
[Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SEND-B.md).

H03b.2b-drain: 61 native cases/5 tests, queue→Winsock send/partial handling;
portable pump прошёл real IPv4 loopback TCP. Connect/auth/session ещё не готовы.
[Доказательства](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SEND-DRAIN.md).

H04a: 24 SDK symbols/34 LEA/24 roots, 512 native escape calls, offline auth plans;
H04 остаётся partial: config/browser/response/game session не готовы.
[Доказательства](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-AUTH.md).

## Текущий приоритет экранного бота: первоначальный запуск

По решению пользователя сначала собираем имеющийся сценарий и проверяем его
на коротком участке. Исследования V20–V37 продолжаются по конкретным препятствиям,
а не как обязательный предварительный этап. Источники проверяем перед каждым
новым обработчиком. Порядок и ограничения: [FIRST-RUN.md](FIRST-RUN.md).

| ID | Работа | Статус | Критерий |
|---|---|---|---|
| V38 | Подготовить кандидат первого запуска | Готово локально | Профиль, 180 тестов, 32/32 replay, подписанный пакет 1.0.8; публикация/Android остаются V18/V39 |
| V39 | Короткий живой прогон Pixel 5 JP | Выполняется | 10–15 минут, подтверждённый переход квеста/награды, сохранённые статусы и кадры; прежде восстановить игровую сессию вручную |
| V40 | Разбирать конкретные препятствия | По результатам V39 | Для каждой остановки: кадр → имеющийся индекс → источник/контрол → обработчик → проверка результата |
| V41 | Проход входа до персонажа | Осталось | Связать найденные макеты со свежими кадрами Android и проверить последовательность; сейчас launch_buttons пуст |

## Выполненные и текущие работы

18 октября: loading/string flags связаны с initializer 14173c480, вызовы из
двух loader paths закреплены; 4 native flag cases/audit прошли. Structured
binding и adapter выполнены, rebind сохраняет embedded archive. Связанный
init→package flags→version transfer→actor tail без подмены CustomVer lookup
вернул 8/170/end443.97 recast tests прошли. Остаются native property schema/
alignment (375 взято из decoder), preload/reader factory и active tile/area
selection; проходимость не проверена. MAP-ATLAS.md/navigation_ready=false.

18 октября: native Linker version transfer в embedded archive+240 подтверждён
конструктором/vtable и 3 cases/15 lookups (170/8 и контроль 149/3, missing=-1).
4package flag cases подтверждают bits02/40; прямой preload branch передаёт
этот archive в actor serializer 1452b8ff0. Audit/97 recast tests прошли.
Следом полный preload gates/reader factory, loading и actor+29 flags, полный
UObject/schema/alignment; затем active mesh/area remapping. MAP-ATLAS.md.
routes_verified=0/navigation_ready=false.

18 октября: восстановлен источник default versions — native registrations
FortniteMain170/UE5-PrivateFrosty8. Zero-version prefixes Nocturne+34nav packages
попадают в native summary fallback на registry snapshot; scalar522/1013/0.
2 registration/4gate replays/audit/97 recast tests прошли. Registered170/8 даёт
actor end443. Далее summary→реальный export archive/flags, full property
schemas/alignment, active area remapping и live mesh selection. MAP-ATLAS.md.
routes_verified=0/navigation_ready=false; это не проверка движения персонажа.

Повтор tile codec с registered170:34 packages/19098 tiles/27249848 bytes,
validate и полное сравнение 97/170 прошли; все output buffers/records равны.
Прежняя geometry не перезаписана. Новый report и SHA — MAP-ATLAS.md.

18 октября: 68 bytes tail имеют conditional decode и 6 native branch replays;
optional flag прочитан нативно, FString заменён bounded ANSI reader, две GUID
прочитаны клиентскими инструкциями. 94 recast tests/audit прошли. Найден общий
custom-version key: tile threshold 97, actor GUID threshold 150. Version97 даёт
end411,150 —443; это разные explicit scenarios, actual versions/flags unknown.
Следом источник FArchive versions/flags, full UObject/schema/alignment и
повтор tile decode с подтверждённой версией; active area remapping остаётся.
MAP-ATLAS.md; routes_verified=0/navigation_ready=false.

18 октября: explicit nav actor properties прочитаны до 375 без поиска EOF;
остаток до candidate443 сокращён 433→68 bytes. Связаны 9saved area IDs и
SceneComp5493; есть точное согласование cell/resolution с candidate params.
90 recast tests прошли. Остаются 68 bytes superclass/actor tail, native schema
construction и active area remapping/filter selection; saved IDs не runtime.
MAP-ATLAS.md; routes_verified=0/navigation_ready=false.

18 октября: закрыта static цепочка actor→constructor vtable→shared serializer;
неподтверждённый участок локализован в superclass property serialization.
90 native descriptors/8cooked header fields закреплены и независимо сверены;
433 bytes prefix values неизвестны. 86 recast tests прошли. Следом полный
inherited cooked schema и потребление prefix без предположения offset 443;
active runtime selection/движение остаются. MAP-ATLAS.md.

18 октября: candidate nav parameters Nocturne export 3919 сопоставлены с 18430
тайлами: exact width совпал с XZ bounds без ошибки, rounded width дал 13004
minimum-corner grid mismatch.380pipeline replays с candidate params без
изменений результатов/links; 83 recast tests прошли. Остаётся доказать property
boundary/inheritance dispatch/active selection, затем live position/permissions.
Не выдавать геометрическое совпадение за runtime proof. MAP-ATLAS.md.

18 октября: общий coordinate→projection→corridor→straight pipeline в одной
VM проверен 380 native cases+380 replays; независимая геометрия/стоимость
совпала. 283 линии/24 partial/73no-projection, включая один baseline с Y+70
за extent 50.80 recast tests прошли. Следом effective active mesh/grid/filter/
permissions и сверка позиции персонажа; управление движением не подключено.
Synthetic analysis composition не выдаётся за gameplay caller; routes_verified=0.

18 октября: straight-path/funnel 145248b20 проверен 472 native cases+replays
на 236 коридорах, options0/1. Независимая геометрия поворотов/дополнительных
пересечений/спец.endpoint совпала; 76 recast tests прошли. TLS/init epoch и
epsilon — документированный synthetic environment. Следующий объём:
связать projection→query→straight на общих входах, effective live mesh/
filters/custom-link permissions и управление персонажем; routes_verified=0.

18 октября: endpoint projection 1452451b0 исполнен 192 cases+192 replays;
независимо проверены XZ clamp/detail height/nearest selection. 24 связки
исходные координаты→projection→corridor дополнительно повторены. 72 recast
tests прошли. Следом straight-path/funnel (call 14569c12f→145248b20),
effective active grid/filters и движение персонажа. Grid synthetic;
routes_verified=0, navigation_ready=false. MAP-ATLAS.md.

18 октября: external/special corridor закрыты в bounded offline объёме:
218 native cases+218 replays, 24 external pairs и 61 special point в обе стороны;
1 special без подходящей привязки. Проверены создание links/квантизация,
стоимость и disconnected/excluded controls; 68 recast tests прошли. Следом
point projection/funnel, effective filters/active tiles и живое движение.
Runtime custom-link permission callbacks не исполнены; routes_verified=0.

18 октября: полный native polygon search1452457b0 выполнен на 33 реальных
извлечённых тайлах, 121 сценарий+121 replay. Internal links также исполнены
кодом клиента; независимый обход/расчёт подтвердил связность и возвращённую
стоимость. Флаги, partial result, node/cost limits проверены; 64 recast tests
прошли. Следующий объём:
external/special corridor, point projection/funnel, effective filters и active
tile coverage; реальные маршруты остаются routes_verified=0. MAP-ATLAS.md.

18 октября: закрыты два локальных пробела навигации: base initializer/CDO
cost loop исполнен 30 сценариями+30 replays, XY-выбор ShortPath/Default —
13 сценариев+13 replays. 60 recast tests прошли. Эти проверки не выполняют
actual find-path на активной сетке и не подтверждают runtime CDO values.
Следующий объём: клиентский graph-query 1452457b0/его структура входа,
effective SupportedArea/CDO и active tile coverage; routes_verified=0.

18 октября: новое звено проверки маршрутов: native class fields780/788/790
→CDO→query helper, три запроса перед base area 10–13=1. 55 anchors/26 fragments,
16 native cases+16 audit replays; 54 recast tests прошли. Найден initializer
base impl1452b7120/slot 8e0, SupportedArea/CDO loop пока только статический.
Следом его исполнение с явными CDO inputs и проверка query caller 145688dd0
→14569bcf0; live coverage/filters/проходимость остаются. navigation_ready=false.

18 октября: книги → изучаемый навык в списке: иконка/имя/ссылка, фильтр
активных/пассивных/unknown, поиск по навыку и kind URL. 402/403 targets,
113 active/289 passive/1 unknown. Проверены все связи/149 image SHA,
12 целевых тестов/syntax/HTTP. Визуальная проверка остаётся.

18 октября: фильтр источника книг по существующим личным наградам NPC:
112/403 с npc_id, 291 без записей. Сочетается с поиском/классом/редкостью,
сохраняется в source URL и возврате. 6 тестов модели и syntax прошли.

18 октября: список книг навыков получил горизонтальные карточки как каталог
навыков: иконка/фон редкости слева, имя, редкость/ID, класс и компактные
источники-монстры. Поиск, фильтры, сортировка по редкости, ссылки и догрузка
остались прежними. Данные не менялись.

18 октября: для навыков без собственной подложки используется самый частый
точный клиентский `ImgBg` у навыков с тем же raw `Skill.Rarity`; собственный
ImgBg сохраняет приоритет. Это оформительское сходство по рангу, а не
подтверждённая игровая связь; fallback есть у рангов с точным ImgBg-образцом.
JS cache key обновлён; deployed и HTTP проверены.

18 октября: добавлен приглушённый цветовой фон по рангу для иконок навыков
без `ImgBg`; оригинальные подложки из клиента показываются поверх него.
CSS cache key обновлён; каталог собран и deployed, HTTP проверен.

18 октября: подложка навыка по единственному точному `ImgBg` растянута на
всю площадь иконки; ранг задаёт только цвет нижней линии. Из 3447 навыков
288 имеют ImgBg. CSS cache key обновлён; происхождение ресурса с SHA остаётся
в индексе клиента. HTTP/deployed сверены.

18 октября: сортировка навыков по рангу в обе стороны/алфавиту,
по умолчанию выше→ниже, внутри ранга имя. 5 Node/syntax/HTTP проверены.

18 октября: Registered-заглушки скрыты из обычного списка навыков,
доступны через служебный фильтр. 145 точных совпадений по именам;
4 Node/syntax/HTTP/deployed проверены. CATALOG-STRUCTURE.md.

18 октября: навыки NPC скрыты из списка без явного фильтра relation=npcs;
точные связи всех миров, прямые URL прежние. 3 Node/syntax/HTTP проверены.

18 октября: страница навыков получила компактные горизонтальные карточки,
явный класс и тип по проверенным книжным описаниям.3446meta entries,
97active/289passive/3060unknown; Type raw не подменён enum по числам.
Все SHA/rows, 2 Node class tests/syntax/HTTP прошли; visual QA остаётся.
Новый builder в build-catalog-pages.py; CATALOG-STRUCTURE.md.

18 октября: результат крафта расположен под названием внутри заголовка;
Min=Max отображается одним числом. Syntax/HTTP/deployed проверены.

18 октября: стоимость крафта в валюте показана справа в заголовке
рецепта, отдельно от сетки материалов. Syntax/HTTP/deployed проверены.

18 октября: материалы крафта показаны горизонтальной адаптивной сеткой
по новой разметке пользователя. Syntax/HTTP/deployed проверены.

18 октября: материалы крафта видны сразу под наградами монстров, все
рецепты без догрузки. Количества/заточка/валюта открыты, условия/JSON
закрыты; данные не менялись. Syntax/HTTP/deployed проверены. NPC-LOOT.md.

18 октября: все NPC в блоках «В наградах монстров» теперь видны сразу,
без дополнительного раскрытия; JSON прежний. Syntax/HTTP/deployed проверены.

18 октября: оформление карточки предмета — компактные характеристики,
отдельный блок монстров под ними, сетка ссылок/уровней и одна кнопка карты.
5 Node/syntax/HTTP/deployed прошли; визуальная проверка остаётся. NPC-LOOT.md.

18 октября: источники всех предметов вынесены из общего закрытого details:
видно 8NPC, продолжение/JSON сворачиваются. 13073000 уже имел 13NPC; это
исправление заметности UI, не отсутствие данных. Syntax/5 Node/HTTP прошли.

18 октября: исправлен пустой переход книги 22023005 на Nocturne — личные
источники теперь открывают все миры. Список книг показывает NPC/уровни,
карточка книги — полный список.3NPC/3 размещения 20301 и SHA проверены,
5 Node tests/syntax/HTTP прошли; visual QA остаётся. NPC-LOOT.md.

18 октября: награды страницы NPC уплотнены до сетки иконок, подробности
hover/focus, JSON по клику. Опыт/валюты перенесены под HP/атаку/защиту;
разные источники не складываются. Syntax/HTTP/deployed и тесты каталога
прошли; визуальная проверка остаётся. NPC-LOOT.md.

18 октября: уровень NPC перенесён в начало заголовка («Ур. N Название»),
повтор в метаданных убран. Syntax/HTTP/deployed JS проверены.

18 октября: JSON в подсказке награды свёрнут под details/summary,
открывается кликом; добавлено удержание подсказки при фокусе её контрола.
Syntax/HTTP/deployed проверены; новая визуальная проверка остаётся.

18 октября: уточнено оформление наград: открытая сетка иконок, информация
hover/focus; валюты/опыт под основными показателями с отдельным источником
NPC/область. Сортировка редкости и цепочки сохранены. 30 Node tests,
syntax/HTTP/SHA прошли; визуальная проверка остаётся. MAP-ATLAS.md.

18 октября: по новому скриншоту уплотнена карточка NPC: закрытые секции
дропа/области со счётчиками, единый раздел источников/ограничений, отдельные
условия размещения. 30 Node tests, syntax, HTTP и SHA четырёх UI-файлов
прошли. Визуальная проверка остаётся; исследование формулы ACC/EVA ещё
не дало подтверждённой новой формулы и продолжится отдельно. MAP-ATLAS.md.

18 октября: special display routing14 статов восстановлен по compact
switch и native2307 cases; 16 tests/HTTP/SHA прошли. Карточки показывают
315/453/454–465 масштабы без%. Тип percent приоритетен; game unit names
не угадываются. Stat→Stat/formulas остаются неизвестны. Сборка
build-stat-format-routes.py → build-catalog-pages.py; ATTRIBUTES.md.

18 октября: display units процентных статов подтверждены nativebranch:
100→1%, 150→1,50%, только IsPercentage=1.1665 native cases с fmodf shim,
15 tests/HTTP/SHA прошли; 76 карточек дополнены. Consumer StatDetailDataList
и формулы Stat→Stat по-прежнему не найдены; непроцентные спецветки ещё
не разобраны. Сборка build-stat-format-evidence.py → build-catalog-pages.py,
источники/границы — ATTRIBUTES.md.

18 октября: исследован формат детализации статов PktStat/Category/Extra/
Detail через vtables; 17 anchors/16 fragments, 2792 native reader/writer calls
с primitive IO stubs, 14 tests/HTTP/SHA прошли. Формат/источник показан в fold
карточки, имена категорий/живые данные/Stat→Stat формулы неизвестны.
След — consumer StatDetailDataList, а не аналогия по имени категории.
Сборка build-stat-packet-evidence.py → build-catalog-pages.py; ATTRIBUTES.md.

18 октября: caller score найден — candidate/slot peer item comparison;
EquipmentType+0x61 из parser, CMP/SETG signed, UI selector 4/1.320+320 native
проверок с явными stub dependencies, 13 tests/HTTP/SHA прошли. Контекст в
карточке уточнён. Общие stat formulas/character power и имя UIwidget ещё
не доказаны; следующий след — StatType consumers. ATTRIBUTES.md.

18 октября: native weight calculation найден (parser record+0x8a → три
float32 multiply/floor/add блока).861 cases/2583 исполнения/12 tests и HTTP/SHA
прошли; карточка содержит ограниченный калькулятор. Полная мощь и owner
context не доказаны; следующий след — caller 145db6fb0 и StatType consumers.
Подробности/ограничения/сборка — ATTRIBUTES.md; visual QA остаётся.

18 октября: граф характеристик расширен до 13 описательных связей; добавлены
3 противодействия (критический шанс/урон/PvP Drain). Привязки StatType→EStat
181mapped/4sentinel показаны и проверены по bytes. 9 tests/syntax/HTTP/SHA
прошли. Native discovery tool сохранён; расчётные функции/коэффициенты
не восстановлены, полное дерево и visual QA остаются. ATTRIBUTES.md.

18 октября: карточка стата ?stat=ID и дерево одного шага готовы; 10 описательных
связей с источниками (8 усилений/2 противопоставления), переходы соседей и возврат.
8 tests/syntax/HTTP/SHA прошли. Частично: численные native формулы, коэффициенты,
полный граф 185 статов и visual QA ещё не выполнены. ATTRIBUTES.md.

18 октября: ID характеристики теперь после имени; нижняя строка убрана. Syntax/HTTP/deployed проверены, игровые данные не менялись.

18 октября: текстовые флаги характеристик заменены на `%`/перечёркнутый
глаз возле имени, с пояснениями title/aria-label. Данные прежние,
syntax/HTTP/deployed сверены; визуальная проверка остаётся. ATTRIBUTES.md.

18 октября: компактные строки характеристик по замечанию пользователя;
коллекции/источник — иконки возле имени, описание hover/focus. Данные
не изменены. Syntax/HTTP/deployed сверены, visual QA остаётся. ATTRIBUTES.md.

18 октября: «Характеристики» — справочник 185 строк OperationType, явные
4 вкладки/12 групп клиента и 49 без группы. Поиск/фильтры/описания/источники,
прямые якоря и коллекции по bonus. 5 tests/syntax/HTTP/deployed прошли;
визуальная проверка остаётся, account значения не заявлены. ATTRIBUTES.md.

18 октября: по уточнению пользователя default коллекций — повышение качества
Rarity0→5, затем специальные/unknown, внутри DisplayOrder. Source/rank/name
оставлены. 8 Node/syntax/HTTP/deployed прошли. Игровой comparator не заявлен;
источники и детали — COLLECTIONS.md.

18 октября: коллекции — DisplayOrder стал порядком по умолчанию внутри
категории, совпадения сохраняют CSV sequence; редкость/имя — отдельные
sort режимы в URL.7 Node/syntax/HTTP/deployed проверки. Полный игровой
компаратор/tie-break не подтверждён; COLLECTIONS.md.

18 октября: оформление коллекций по примеру пользователя — широкие строки,
имя/бонусы слева, иконки/заточка справа, подсказки и мобильный перенос.
Данные/связи прежние; прогресс аккаунта не имитируется. Syntax/HTTP/deployed
сверены; визуальная проверка остаётся. Подробности COLLECTIONS.md.

18 октября: раздел «Коллекции» — готов в объёме справочника клиента:
4079 групп/6766 требований, все предметы/бонусы связаны; отдельный URL,
поиск/фильтры/сортировка/догрузка, иконки/заточка/количество, hover/focus
описания бонусов и исходные условия. 10 целевых tests/HTTP/deployed проверки
пройдены. Визуальная проверка не завершена после прежнего отказа browser
URL policy; прогресс/расписание/runtime не заявлены. Источники и ограничения —
COLLECTIONS.md. Навигационное исследование отложено пользователем.

18 октября: native query-filter initializer/setter chain (26 anchors/15 fragments/
10leaves), 33 native cases/12 replays. Costs clamp travel>=1/entering>=0,
excluded skips overrides; UI показывает сохранённое→применяемое значение.
50Python+8 Node/overlay/deployed checks прошли. Owner+0x400 копируется для
class-specific query filter; его фактические base arrays/active preset всё ещё
не подтверждены. Источники/порядок/shims — MAP-ATLAS.md.

18 октября: найдены/извлечены 4BP_NavQuery (7variants/15area records), native
schema/constructor costs и area IDs закреплены 48 anchors/23 fragments. Все 14PAK
parts повторно извлечены audit; 25Python+7 Node и deployed checks прошли.
Карточка показывает исходные настройки фильтров. Active runtime filter/arrays,
owner+0x400 selection, active coverage и путь остаются неизвестны. Источники/
порядок — MAP-ATLAS.md, tools build/decode/audit-navigation-filter-*.

18 октября: native area-priority builder найден через leaf setter 14523d610 ←
1452b4943.22 anchors/14 fragments, 72 native sum/sort/rank cases (50heap branches),
12 native replays прошли. Ранги уникальные 0..63 даже при равных суммах; actual
filter arrays ещё не извлечены, order11→63→10 остаётся сценарием.46Python+7 Node,
all62overlay/deployed audit прошли. Источники/ограничения — MAP-ATLAS.md.

18 октября: BV/priority study1096queries и полный native endpoint attachment/
link writer 434 пары на копиях тайлов. 7 сценариев приоритетов; 11→63→10 точно
воспроизводит обе baked points61 перехода, 9432 без связей во всех 7. Настройки
сценария подобраны по данным; runtime binding не доказан. All434 audit/28 native
replays, 50Python+7 Node/deployed checks прошли. Карточка содержит результат/
proof link. Остаются активные параметры/area priorities, side/load-order
dispatch, cluster links, Android и реальные маршруты. MAP-ATLAS.md.

18 октября: native nearest fallback без BV —6synthetic/136real queries всех 62
переходов; A61candidate/60exact baked, B62candidate/60exact baked, 3 перехода
расходятся. All136 audit/16 native replay, 38Python+6 Node и deployed map прошли.
Карточка показывает предварительную проверку поверхности. Это не полный
attachment: BV/preferred-area-priority/runtime side dispatch и путь остаются.
Визуальная проверка всё ещё не завершена (URL policy). MAP-ATLAS.md.

18 октября: recast-special-flags.py/build-recast-special-direction-evidence.py
сверены с 27 native anchors/32 fragments/11008 native cases. Bit0x80 всех 62 точек
обходит 3direction gates в обоих направлениях; в карточке пояснение/proof link.
35Python+5 Node, повторный all62 audit/manifest/deployed checks прошли.
Это ещё не полный query/attachment/runtime route; +0x41c runtime configuration,
остальные фильтры и визуальная проверка остаются. Подробности MAP-ATLAS.md.

18 октября: предварительный слой 62 особых переходов и native layout80 байт
проверены 95 целевыми tests; audit-recast-special-links.py независимо сверил все
записи/raw SHA/исходные и baked coordinates/39 пространственных совпадений,
scene/overlay SHA и 4deployedfiles. Все ID=0,61 пара endpoints отличается от baked.
Порядок/ограничения — MAP-ATLAS.md. Визуальная проверка не завершена из-за
отказа URL policy браузера; runtime attachment/направление/проходимость остаются.

18 октября: добавлен запуск карты двойным нажатием `Start-Vampir-Map.cmd`
в корне проекта → `start-map-server.ps1`. Инструкция: [MAP-SERVER.md](MAP-SERVER.md).
Проверены запуск на 127.0.0.1:17946, HTTP 200 и повторный вызов без второго сервера.

| ID | Работа | Статус | Результат / что осталось | Где смотреть |
|---|---|---|---|---|
| V01 | Индекс ресурсов и происхождение | Готово | Индексы архивов, CSV, изображений; пути, SHA и процедура повторного извлечения | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md) |
| V02 | Цепочка квестов и обучения | Готово | Справочник: 1353 квеста, 5944 задачи, 3892 действия, 139 учебных шагов, 94 UI-ключа; это данные, не готовое прохождение | [QUEST-DEPENDENCIES.md](../resource-tools/vampir/knowledge/evidence/scenarios/QUEST-DEPENDENCIES.md), quest-runtime.json |
| V03 | Награды и блокировки | Частично | Награды и ссылки соединены; найден клиентский dispatch и обычный AND с ранними исключениями. Остались gate/состояния, источники разрешений, вызовы и Android | [CONTENTS-LOCKS.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONTENTS-LOCKS.md), [CONDITION-PREDICATE.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-PREDICATE.md) |
| V04 | Нативные типы и связи | Частично | Enum и часть дескрипторов подтверждены в EXE; продолжить поиск обработчиков и условий | [NATIVE-SEMANTICS.md](../resource-tools/vampir/knowledge/evidence/game-data/NATIVE-SEMANTICS.md) |
| V05 | Каталог окон, попапов и элементов | Готово | 1764 ресурсных пути, 363 пути попапов; контролы и происхождение. Наличие в каталоге не означает поддержку ботом | [UI-CATALOG.md](../resource-tools/vampir/knowledge/evidence/interface/UI-CATALOG.md) |
| V06 | Геометрия интерфейса | Частично | Слоты, родители, SizeBox, ScaleBox и пресеты найдены; абсолютные зоны кликов, DPI, SafeZone и видимость ещё не подтверждены | [UI-SCALE.md](../resource-tools/vampir/knowledge/evidence/interface/UI-SCALE.md) |
| V07 | Вход по макетам клиента | Частично | 10 окон / 20 вариантов; ссылка TitleUI → TitlePanelUI подтверждена свойством UserWidget в двух архивах. Остались кадры Android, сервер/персонаж и переходы; launch_buttons пуст | [ENTRY-FLOW.md](../resource-tools/vampir/knowledge/evidence/interface/ENTRY-FLOW.md) |
| V08 | Исполнение квестов и обучения | Частично | 18 учебных действий; часть Bloodshape проверена на телефоне. Нужен полный проход цепочки с распознаванием текущего этапа | [RUNTIME-CHAIN.md](../resource-tools/vampir/knowledge/evidence/scenarios/RUNTIME-CHAIN.md), quests.py |
| V09 | Магазинный Guide 901030 | Частично | Обработчик, сверка источников и журнал покупки готовы локально; успешная покупка, результат и награда на Android не подтверждены | shop.py, [SHOP-REPLAY.md](../resource-tools/vampir/knowledge/evidence/scenarios/SHOP-REPLAY.md) |
| V10 | Окна сообщений | Частично | KICKOUT_FOR_INSPECT связан с точным текстовым ключом и паузой; конкретный вызываемый WBP и прочие попапы ещё связывать | ui-window-reference.json, [UI-CATALOG.md](../resource-tools/vampir/knowledge/evidence/interface/UI-CATALOG.md) |
| V11 | Устойчивость на сохранённых кадрах | Готово | Последний целевой прогон: 180 тестов; магазин: 32/32 сценария, масштабы, сдвиг, неверная сумма, повтор и перезапуск | [SHOP-REPLAY.md](../resource-tools/vampir/knowledge/evidence/scenarios/SHOP-REPLAY.md) |
| V12 | Сборка локального модуля 1.0.8 | Готово | Подписанный ZIP собран, основные файлы сверены с рабочими; публикации и установки нет | phone-exit/.tools/bot-release/vampir-1.0.8.zip |
| V13 | Карты и точки | Частично | 17.10: атлас 254 миров/154 настроек/588 точек/61307 размещений NPC; Nocturne36 контекстов/24071 отметка, исправлен zoom, карточки NPC/предметов/дропа/навыков. Native-словарь 40 FireCondition, 43 явно неизвестен; 66 тестов. Остались runtime-условия/время/урон, эффекты предметов, остальные карты, свежий Android и маршруты; MAP-ATLAS.md/NPC-LOOT.md | [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md), библиотека maps/ |

## Следующие задачи и критерии завершения

| ID | Работа | Статус | Когда считать выполненной |
|---|---|---|---|
| V14 | Продолжить связи по исходным данным | Осталось | Для очередного квеста/окна записаны исходные ID, условия, награды, WBP/контролы, геометрия, доказанные связи и оставшиеся кандидаты |
| V15 | Проверить Windows-ресурсы против Android | Осталось | Подтверждены соответствие нужных макетов/элементов и поведение на целевом телефоне |
| V16 | Полный живой цикл прокачки | Осталось | Вход → текущий этап → действия/бой → награда → следующий этап; задержки, неизвестные окна и пропуск катсцен проверены без слепых кликов |
| V17 | Длительная автономность и восстановление | Осталось | Проверены потеря связи, выключенный ПК, перезапуск, отмена, настройки, неизвестный результат действия и длительная работа |
| V18 | Выпуск следующего проверенного пакета | Осталось | Пройдены необходимые проверки, зафиксированы ограничения, пакет опубликован и версия на телефоне подтверждена |
| V19 | Ссылки отложенных вложенных панелей | Готово | Проверены 958 экспортов: 957 явных ссылок, одно свойство не задано явно, 0 ошибок; хвосты экспортов не интерпретируются. Отчёт ui-geometry/deferred-panels.json, генератор decode-deferred-panels.py; 11 тестов декодера и защиты связей |
| V20 | Нативные ветви входа | Частично | Проверены 16 ссылок на диагностику, 13 фрагментов шести корней с unwind-цепочками, пять проверок/ветвей. Кнопки связаны в V21; остаются имена Sequence, функции проверок, окна и Android. [NATIVE-ENTRY.md](../resource-tools/vampir/knowledge/evidence/interface/NATIVE-ENTRY.md) |
| V21 | Кнопки титульной панели → нативные поля и сравнения | Готово | 11 именованных кнопок из двух макетов связаны с полями и 12 сравнениями; подтверждены смещение подобъекта и слот таблицы методов. Полный путь события, видимость и Android не входят в эту проверку. [ENTRY-BUTTONS.md](../resource-tools/vampir/knowledge/evidence/interface/ENTRY-BUTTONS.md) |

16 октября 2026 пользователь разрешил первый живой прогон. На Pixel 5 · JP
подтверждены установка 1.0.8 и применённая редакция 2. Бот распознал оставшееся
окно отключения `KICKOUT_FOR_INSPECT` и сам встал на паузу без ошибки.
Пользователь подтвердил, что сообщение пока остаётся; возврат в мир нужен для V39.
Пакет опубликован, SHA удалённого ZIP проверен. V18 частично выполнена:
публикация/установка подтверждены, игровой цикл ещё нет.

## Дополнительные исследования

| ID | Работа | Статус | Результат / осталось |
|---|---|---|---|
| V22 | Индекс ссылок кода на окна | Частично | 1203 проверенные ссылки на 942 макета, включая 279 путей попапов; query-native-ui.py с SHA-проверкой. 38 кандидатов в 11 корнях требуют CFG-разбора; вызовы загрузчика/видимость ещё не доказаны. [NATIVE-UI-LINKS.md](../resource-tools/vampir/knowledge/evidence/interface/NATIVE-UI-LINKS.md) |
| V23 | Получение и показ входных окон | Частично | Шесть ссылок на пять окон, 12 прямых вызовов; сохранены проверки UI-менеджера и два accessor глобальных флагов. Остались контракты проверок, виртуальные пути, Sequence и Android. [ENTRY-WINDOWS.md](../resource-tools/vampir/knowledge/evidence/interface/ENTRY-WINDOWS.md) |
| V24 | Семантика UI-проверки перед показом | Частично | Найдены удаление, dispatch/очистка очереди, отдельный reset и синхронный путь завершения; callbacks идут до изменения state, вторая очередь может запустить новый переход. Десять корней, 24 фрагмента + leaf, 1523 инструкции. Остались обычный триггер завершения, reentrancy, контракт отмены, виртуальные методы и Android. [UI-MANAGER.md](../resource-tools/vampir/knowledge/evidence/interface/UI-MANAGER.md) |
| V25 | Обычный переход и easing callback | Частично | Tick→update→завершение→callback связан по слотам; найдены повторный запуск и пять прямых callers stop. Очистка callback отделена от выполнения. WBP_FaderUI связан в V26; остались reset→stop, имена флагов, reentrancy и Android. [UI-TRANSITION.md](../resource-tools/vampir/knowledge/evidence/interface/UI-TRANSITION.md) |
| V26 | Fader: cooked superclass → native class → методы | Готово | В четырёх вариантах прочитаны superclass imports; Fader/Media различены. Регистрация NkFaderUI связана с инициализатором и vtable слотов настройки/сброса. Только Windows; Android/видимость/reset→stop остаются в V25. [FADER-CLASS.md](../resource-tools/vampir/knowledge/evidence/interface/FADER-CLASS.md) |
| V27 | Native-имена типов ContentsLockCondition | Готово | Карта 11 типов извлечена из инициализации конвертера и связана с 330 CSV-условиями; имена включены в runtime referenceRevision3 с проверкой хешей/строк. Type1=CompletedQuest. Это имена/схема хранения; evaluator, сравнения, AND/OR и Android остаются в V03. [CONDITION-TYPES.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-TYPES.md) |
| V28 | Загрузка нативных условий | Частично | Проверены шаг записи 56, подобъект+8, пять именованных полей и пять пустых post-load методов; 22 опорные инструкции, три фрагмента. Подтверждено построение индекса GroupId → массив указателей условий, второй контейнер manager+0x60. Evaluator и AND/OR не найдены. Следующий шаг — потребители массивов групп. [CONDITION-TYPES.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-TYPES.md) |
| V29 | Клиентский предикат условий и групп | Частично | Найдены dispatch11 типов, 30 опорных инструкций и обычный AND с коротким замыканием. ForcedLock проверяется до разрешений; сохранены ранние true-ветви и gate. Helper завершения квестов зависит от состояния. Проверки Android/полей ContentsLock/вызывающих мест остаются. [CONDITION-PREDICATE.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-PREDICATE.md) |
| V30 | Поля ContentsLock и соединение со справочником | Готово | Пять полей связаны загрузчиком, 18 опорных инструкций, 24 фрагмента и 5 прямых вызовов; все 269 SaveType=2. referenceRevision4 хранит клиентский путь отдельно от evaluator. Источники состояния/назначение callers и Android остаются в V03. [CONTENTS-LOCK-FIELDS.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONTENTS-LOCK-FIELDS.md) |
| V31 | Обновление контекста блокировок | Частично |32 опорные инструкции, 15 фрагментов: сброс флагов/уровней, входной список, readiness и refresh перед пересчётом. При закрытом gate старые уровни не обнуляются. Источник массива/таблица gate продолжены в V32/V33. Остались события setter, регистрация OnHandler, getters и Android. [CONDITION-STATE.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-STATE.md) |
| V32 | Именованные результаты разблокировки → update | Готово | Два точных OnHandler-литерала, 21 опорная инструкция, 2 обработчика и 2 tail-wrapper: полная замена и добавление ID. Регистрация/guard/сериализация не входят в подтверждённый путь. [UNLOCK-RESULTS.md](../resource-tools/vampir/knowledge/evidence/scenarios/UNLOCK-RESULTS.md) |
| V33 | Инициализация и изменение готовности типов | Частично |37 опорных инструкций, 4 фрагмента и getter: reset 0..10 (true только 10), общий setter и EnterArea. Готовность не равна выполнению; Семь прямых событий связаны в V34; другие пути/callback и Android остаются. [CONDITION-GATE.md](../resource-tools/vampir/knowledge/evidence/scenarios/CONDITION-GATE.md) |
| V34 | Регистрация unlock-handler и события готовности | Частично |29 опорных инструкций: 2 регистрации в PacketDispatcher, packet-vtable/ID, 7 прямых setter-вызовов. Имена CharacterSelect/Engraving подтверждены. Полная принимающая диспетчеризация, guard и 3 неизвестных корня ещё не связаны. [UNLOCK-REGISTRATION.md](../resource-tools/vampir/knowledge/evidence/scenarios/UNLOCK-REGISTRATION.md) |
| V35 | Guard результата и сообщения из ресурсов | Частично |25 опорных инструкций, 252 инструкции кода отдельно от compact table 227; обычные 0/4503 и специальный режим различены. 5 ключей EXE→CSV405 связаны, UI-ограничения сохранены. Остались WBP, полные side effects и принимающая диспетчеризация. [PACKET-RESULT-GUARD.md](../resource-tools/vampir/knowledge/evidence/scenarios/PACKET-RESULT-GUARD.md) |
| V36 | Общий error-path → SystemMessageUI | Частично |17 опорных инструкций, 7 литералов, 11 фрагментов, 4 cooked-варианта; superclass/vtable/TextMessage+0xa00 и фон связаны. Отдельный справочник без привязки KICKOUT; 176 тестов прошли. Абсолютная геометрия/анимация/Android и принимающая диспетчеризация остаются. [SYSTEM-MESSAGE-UI.md](../resource-tools/vampir/knowledge/evidence/interface/SYSTEM-MESSAGE-UI.md) |
| V37 | Именованное содержимое TextMessage | Частично | Native Name/Content→NamedSlotBinding→NamedSlotBindings связаны; 2 cooked-префикса NamedSlotContent→TextMessage и обратный Slot6 проверены. Индекс 59 схемы класса ещё кандидат, хвост opaque, топология/геометрия не включены. 180 тестов прошли. [MESSAGE-NAMED-SLOT.md](../resource-tools/vampir/knowledge/evidence/interface/MESSAGE-NAMED-SLOT.md) |

## Обработка окна отключения по новому указанию

| ID | Работа | Статус | Результат / осталось |
|---|---|---|---|
| V42 | Однократный Confirm KICKOUT_FOR_INSPECT | Готово в проверенном объёме | 186 тестов, 32/32 replay; 1.0.9 опубликована/установлена. Pixel 5 подтвердил исчезновение исходного окна и паузу без ошибки. Пропорции/DPI всех устройств не проверены; см. INSPECT-CONFIRM.md |
| V43 | Окно отключения из-за бездействия | Готово в проверенном объёме | 1.0.10 установлена; Confirm закрыл окно до титула. Явный ключ, один tap, проверка результата; IDLE-CONFIRM.md |
| V44 | Универсальный вход с титула | Готово на Pixel 5 | 1.0.11 сама открыла Character Selection после ручной верификации; имя/сервер в runtime не используются; TITLE-ENTRY.md |
| V45 | Уточнить «cannot be used» при входе | Уточнено пользователем | Требовалась верификация устройства по номеру; пройдена вручную. Точный макет ошибки не снят; бот не вводит номер/код |
| V46 | Универсальный Game Start выбранного персонажа | Готово на Pixel 5 | 1.0.12 сама нажала GameStart, загрузила мир и перешла к квестам; 202 теста, четыре варианта кадра |
| V47 | Учёт покупок при смене персонажа | Проверяется | 1.0.22: отдельный контекст применён, одна покупка 75 Gold прошла. reserved сохранён; проверяется распознавание completed в 1.0.23. UI профилей остаётся; PURCHASE-CONTEXT.md |

## Правило ведения


После изменения кода, исследования или проверки обновлять соответствующую строку:
результат, статус, ссылку на доказательство и оставшийся шаг. Новые задачи получают
следующий ID; выполненные не удаляются. При продолжении читать README и эту таблицу.
Сначала искать в данных клиента и связях; догадки явно помечать. Исторические
результаты хранить в [журнале](../vampir.md), актуальное состояние — здесь.

## Текущие препятствия обучения

| ID | Работа | Статус | Результат / осталось |
|---|---|---|---|
| V48 | Tutorial4007 открытие сумки | Готово на Pixel 5 | 1.0.13 установлена, сама открыла сумку; hud_inventory переиспользован, 19 привязок |
| V49 | Проверить runtime-состояние из логов игры | Исследовано частично | WindowsSaved/Logs пуста, ADB только USB-vivo; логи Pixel 5 не проверены. LIVE-STATE.md; не считать статические таблицы текущим состоянием |

| V50 | Общий приоритет поиска по данным клиента | Установлено, частично | recognition.py, покадровый кеш, 23 привязки; Desktop повтор 504–539 ms;RECOGNITION.md |
| V51 | Остальные шаги Tutorial4007 | Проверено на кадрах | Выбор→описание→свиток→финальная безопасная+1;16 масштабных кадровых проверок, одна попытка расхода; Финальный tap+1 проверен на Pixel 5; промежуточные переходы были диагностическими |

| V52 | Общий выход из окна Enhance после обучения | Частично, сессия прервана | 4007012 завершён,+1 получен, окно осталось; проверить владельца кнопки выхода в родительском UI, кадр и переход |
| V53 | Ускорить неизвестный/первый экран | Осталось | На Pixel 5 полный поиск 5915–9495 ms; первый роутер ускоряет повторы подсказок, не общий поиск. Нужны проверенные экранные якоря/группы без потери попапов |

| V54 | Повторная верификация телефона | Ожидает ручного действия | Пользователь сообщил о повторной проверке после KICKOUT; бот на паузе, номер/код не автоматизировать. Точный макет ожидает сверки после действий пользователя |

| V55 | Начальная цепочка нового персонажа | Выполняется | Zizak1→3, общая 1.0.18; диалог→задание 1→сцена→Drain/меню навыка→Adrenaline подтверждены. Покупки выключены; кадры zizak-level1-2026-10-16 |

| V56 | Вариант текста Drain | Установлено, бот запущен | 1.0.16, тот же шаг 4002004/рамка цели; 3 размера+сдвиг, без снижения порога. Прежняя 1.0.15 тоже прошла после смены кадра, это устойчивость, не исправление постоянной ошибки |

| V57 | Учебная цель Adrenaline по рамке | Готово на Pixel 5 | 1.0.17: шаг 4002016, GameUI→AdrenalineGaugeT/ButtonAdrenalineGauge; маска скрывает рисунок, 3 масштаба и сдвиг, отрицательная проверка без рамки. ADRENALINE-FRAME.md |

| V58 | Завершение Tutorial4002/Buff | Готово на Pixel 5 | 1.0.18 сама закрыла Tooltip4002018, вернулась к HUD/разговору; 2 новых кадровых+46 регрессионных прошли. ADRENALINE-FRAME.md |

| V59 | Прогон после завершения Drain | Подтверждён участок | После 1.0.18, Zizak дошёл до уровня 3/задания 6TalkToDamir без ручных игровых нажатий; кадр level3-quest6.jpg |

| V60 | Выход из обычной сумки | Готово на Pixel 5 | 1.0.19: после запуска сумки нет, Zizak5, KrynaNest, автоквест без ошибки; 2 кадровых+5 роутера+25 регрессий;BAG-EXIT.md |
| V61 | Пропуск недиалоговых катсцен | Частично исследовано | CutsceneUI735/MediaUI789ButtonSkip и геометрия найдены; отличение от SKIP обучения не доказано, не разрешать по тексту одному |

| V62 | Короткое наблюдение подтверждённого HUD | Проверяется | 1.0.20, без tap, свежие якоря+auto_on, маркер обучения прерывает, полный поиск 12 сек;PASSIVE-HUD.md |

| V63 | Общий исполнитель квестовых действий | Проверяется | quest_executor.py: 24 учебных правила + Guide-награда, геометрия, ожидание, резерв до IPC, неизвестный ответ без повтора; 7 новых тестов + 29 регрессий. QUEST-AUTOMATION.md |
| V64 | Планировщик по наблюдениям компонентов и условиям графа | Осталось | Связать известные семейства интерфейса с условиями задачи/награды; не объявлять серверный прогресс по одному tap, сохранить неизвестные связи |


## Продолжение карты, 17 октября 2026

| ID | Работа | Статус | Результат / осталось |
|---|---|---|---|
| V65 | Единый атлас географии Vampir | Готово как справочник | 17 CSV, 1422 PNG, SHA EXE/Nocturne; 254 мира, 154 настройки, полные размещения и связи; 9 тестов; 91 проблема источников сохранена. [MAP-ATLAS.md](../resource-tools/vampir/knowledge/evidence/maps/MAP-ATLAS.md) |
| V66 | Привязка мира к изображению и Android | Частично: изображение V68 | Native-формула/плитки либо проверенная калибровка, независимые точки, свежие кадры/DPI; локальный API17842 пока недоступен |
| V67 | Проходимость, маршруты и интеграция карты в бот | Частично: источники и предварительный слой | 63 ActorRoot/Blueprint chain проверены, 62 PointLinks; в UI63 условных размещения/14 связей по явным transforms, 49 неполных. Расчёт не считается маршрутом. Native CDO/frame/активация/граф/Android и pivot322 контуров остаются; 20 header chunks без полигонов. MAP-ATLAS.md |

| V68 | Прежние скрины на большой карте | Подтверждён один участок | 93 уникальных изображения, 1WorldMap; SIFT/RANSAC463 детали, spatialholdout p95=1.247px; покрытие/фрагмент/сравнение и 5 тестов. WorldXY и прочие области не подтверждены; MAP-ATLAS.md |
| V69 | Каталог NPC-наград, предметов и изображений | Готово в доступном объёме | NativeNpcReward. GroupId→Npc; 941NPC/793Item, 5827Item общего каталога/3615 картинок; 41FloatRGBA, 790 однозначных+2 неоднозначных+1 пропущенная иконка NPC. 6 тестов; NPC-LOOT.md |
| V70 | Численные шансы и региональные награды | Осталось | NativeLoad трёх таблиц и atoi→32bit поля подтверждены; знаменатель/число попыток/модификаторы и GroupId entry11→Area ещё не доказаны, проценты не считать |
| V71 | Закрыть пробелы иконок и цвет Android | Частично | Item 11042015/IMG_Weapon_Orb_UnCommon_16 не найден в экспорте/entries; два неоднозначных пути; цвет FloatRGBA и версия Android требуют сверки |

| V72 | Native-загрузка rates и обратный индекс предметов | Готово в указанном объёме | 3 именованных Load/6 фрагментов/PE-importatoi; 793Item/35211 цепочек, NPC/миры/сырые rates; 9 тестов NPC, все цепочки сверены. Визуальная проверка новой UI недоступна(local browser use disabled). NPC-LOOT.md |

| V73 | Rate callbacks и размещения добычи | Готово в указанном объёме | NpcReward/Reward lookup→init→copy→vtable, 24 опоры/12 фрагментов, ratecallbacksret0;4227 размещений 776NPC, фильтр Item/NPC+World, CRLF исправлен. 10+5 тестов, все строки сверены. Формула шанса не найдена;NPC-LOOT.md |

| V74 | Проверка обновлённого UI после включения браузера | Готово в указанном объёме | HTTP17946 был остановлен, перезапущен loopback; Nocturne/покрытие, Item 12013000→175NPC/244 цепочки→NPC 200052→spawn 100177067/rates видны, ошибок нет. preview-checked.png;NPC-LOOT.md |

17.10, V13 продолжение: Nocturne Map10/11 — проекция клиента и 7 областей
исторического кадра без подгонки; слой добычи Item→NPC→размещения, 33 теста
и браузерная проверка. Свежий Android/проходимость/навигация ещё остаются.

17.10, V13: общая Nocturne всех 36 миров, 24071 отметка, карточки/имена/добыча/
квесты/порталы, PNG10240×10635. Все 25 плиток попиксельно сверены после исправления
zoom; 51 тест. Подробности в MAP-ATLAS.md, свежий Android/маршруты остаются.

17.10, V13: карточка NPC с дропом/количеством/характеристиками Battle, опытом/золотом.
1785NPC/23329 цепочек/56 тестов. Финальный компактный UI требует повторного просмотра
после включения браузера; свежий Android/шансы/маршруты остаются.

17.10: по скрину обычного NPC 100201042 добавлены 34 кандидата предметов из награды
области 100201040; прямых NPC наград нет. Применение AreaReward за убийство
ещё не доказано, статус раздела явно указан; 57 тестов, браузер отключён.

17.10: разделены NPC/AreaReward в карточках и фильтре.323Area/941NPC группы
совпадают с доменами ID, не пересекаются; 58 тестов. Применение за убийство/шансы
остаются недоказанными, визуальная проверка недоступна.

17.10, V13: проверены native-потребители AreaReward/NpcReward: 15 call/88 фрагментов,
3 связи с UI карты/подземелья; build-reward-scope-code.py и NPC-LOOT.md.
Браузер доступен: NPC 100201012/34 предмета области/фильтр 43 областей проверены,
сервер 17946 восстановлен, 58 тестов прошли. Серверное правило наград за убийство,
знаменатель вероятности и свежий Android по-прежнему не подтверждены.

17.10, V13: Item. Rarity/8 исходных текстур фона/русские подписи в карте и каталоге;
сортировка Mythic→Common, Unique/Seasonal/неизвестные в конце. 5827 записей и
8 SHA проверены, 59 тестов прошли. См.NPC-LOOT.md; runtime-связь с конкретным
игровым виджетом и свежий Android пока не подтверждены.

17.10, V13: полная страница предмета, выбор заточки, благословение и все поля Item.
848 групп заточки+84 благословения, 62583 строки/SHA проверены; браузер подтвердил
Item 11014006 +0/+15,59 тестов. Неразобранные эффекты/пассивы/ограничения доступны
как ID; итоговый серверный эффект экземпляра не вычисляется. См.NPC-LOOT.md.

17.10, V13: компактное оформление страницы предмета и плавающие описания
параметров (наведение/фокус/нажатие, Escape). Браузером проверен шлем 12014006
+15 и клавиатура, значения сохранены; синтаксис JS/console без ошибок.
Данные не изменялись. См.NPC-LOOT.md, item-details-redesign.png.

17.10, V13: базовые параметры+прибавка заточки в скобках, итог в подсказке;
новый item-stat-model.js/4 теста сравнения, всего 63 теста пройдены. Проверены
карточки шлема 12014006/перчаток 12034006; данные клиента не изменялись.

17.10, V13: боевые параметры и навыки NPC подписаны; новые Skill/SkillName_en/
SkillOperation связи сохранены в NPC-LOOT.md и JSON provenance. 1785 SHA/
3039 операций проверены, 63 теста прошли, браузер 100181082/50160/50161 подтверждён.
Формула урона, единицы времени и runtime-условия остаются неизвестными.

17.10, V13: дроп — доказана native-ветка клиентского окна по NpcSpawn. AreaInfoId:
ненулевой→AreaReward, 0→NpcReward по NpcInfoId. Не зависит от отсутствия личных строк.
build-drop-selection-code.py/NPC-LOOT.md; 26 anchors/36 фрагментов; 1785 карточек/
17488 размещений проверены, 64 теста. UI Glade Vagrant/29 предметов области проверен.
Серверная выдача/проценты/модификаторы пока неизвестны.

17.10, V13: проверен NPC 300041: пустой AreaInfoId, нет NpcReward; подтверждены
квестовые ссылки 130420090/130430070 через Param.npcInfoIdList. UI проверен,
связи записаны в NPC-LOOT.md, серверный дроп остаётся неизвестным.

17.10, V13: быстрый поиск личного дропа — фильтр npcLoot=1,554 размещения/
470 NPC, ссылка Void Chronicler200052/29 предметов. 18 Node-тестов карты прошли,
данные наград не изменялись. См.NPC-LOOT.md.

17.10, V13: проверка портрета 100181052 — явной 2D-связи нет, семейный Boss-портрет
не назначен. 8 прямых Img→PNG связей Nocturne; отчёт и источники в NPC-LOOT.md.

17.10, V13: Skill. FireCondition→native parser→40 пар имён/кодов подтверждены
указателями и bytes; build-skill-semantics.py/skill-semantics.json, связи в NPC-LOOT.md.
Always=0, fallback 43; у всех 2632 вхождений навыков Nocturne43, поведение неизвестно.
Добавлены подпись статуса/исходные параметры условия; 1785 SHA/66 тестов проверены.
Единицы времени, runtime-предикаты, формула Damage и оставшиеся эффекты предметов
остаются. Визуальная проверка недоступна: local browser use отключён в Work settings.

17.10, V13: подтверждены 15 названий целей и 15 условий выбора SkillOperation;
Skill. TargetType использует тот же парсер целей. Новый build-skill-target-semantics.py,
SHA/21 anchors/2 JMP и связи в NPC-LOOT.md. В карточках отдельные цель навыка,
цель действия и выбор цели, неизвестные 15/17 не интерпретируются.
1785 SHA/3039 действий/67 тестов прошли; выбранный 100171021→50288/50289→Enemy4.
Runtime-фильтры, единицы времени, формула урона и эффекты предметов остаются.
Визуальный просмотр недоступен из-за настройки Work.

17.10, V13: пассивы 39 предметов→19 SkillSet→19 Skill→35 действий,
native-диагностики связей/SHA проверены. В карточке название/описание клиента,
ID/исходные строки. build-item-details.py/build-npc-loot.py, источники в NPC-LOOT.md.
69 тестов/39 ссылок прошли. Runtime-активация не проверена; числовые проценты
не выведены из текста. Остались EffectType/EffectParams, вложенные эффекты,
ограничения, время и урон. Визуальный просмотр отклонён политикой браузера URL.

17.10, V13: сервер 17946 восстановлен; браузером проверены Item 11013010 +0/+15,
иконка/редкость/благословение, Item 11015000→Frenzy/описание. Ошибок console нет.
Снимки maps/loot/server-check-item.png и passive-checked.png просмотрены;
прежнее ограничение визуальной проверки для этих карточек снято.

17.10, V13: ItemLimit/ItemUseLimit→native парсеры 0/1/2,47 anchors;
14+28 предметных ссылок выведены, 0 потерянных, 71 тест/браузерные примеры прошли.
build-item-limit-semantics.py перед build-npc-loot.py; все связи в NPC-LOOT.md.
Навыки не завершены: вложенные эффекты, runtime-условия/код 43, урон/время остаются.

17.10, V13: Effect92→EffectOperation93 по EffectInfoId подтверждён native diagnostic.
SkillOperation. Param1→Effect пока только кандидат: 75 вхождений/37 ID у NPC,
19 у пассивов; отдельная свёрнутая подпись «не подтверждена», relation_verified=false.
skill-effect-links.py/JS/CSS, источники и отвергнутые native-зацепки в NPC-LOOT.md.
74 теста/1785 SHA/визуальная проверка Impact прошли. Доказательство Param1,
истечение/рекурсия, формула урона, время и runtime-условия остаются.

17.10, V13: Effect. ActionType→56 native-имён, None0/Stun6/fallback 56;
408 известных из 2027 определений. build-effect-action-semantics.py,
источники/12 anchors/JMP в NPC-LOOT.md. UI ActionType/сырые параметры/истечение,
75 тестов/1785 SHA/визуальная проверка прошли. Param1→Effect не доказан,
формула урона/единицы времени/точные runtime-условия остаются.

17.10, V13: OverlayType 5 имён/BuffType 3 имён подтверждены native-парсерами,
выведены раздельно; 9 ключей истечения Skill/Die сохранены без интерпретации.
build-effect-rule-semantics.py/14 anchors/JMP, источники в NPC-LOOT.md;
76 тестов/1785 SHA/2027 определений/браузерная проверка прошли. Накопление,
refresh, истечение, Param1→Effect, время/урон/runtime-условия остаются открытыми.

17.10, V13: найден и закреплён native-путь вычисления/вывода перезарядки
WBP_SkillSummaryInfoT.TextSkillCoolTime; build-skill-time-code.py,
32 anchors/2 float-константы/leaf/vtable/SHA/ресурс export 27. Масштаб ×0,001,
runtime-поправки, деление на заряды и %.1f подтверждены. Глобальная единица
CSV не доказана; csv_time_unit=null, UI не переводился в секунды. Следующий
шаг — фабрика Skill/уровневые overrides и независимая граница секунд.
Источники, точные адреса и границы в NPC-LOOT.md.
Повторная сборка дала одинаковый SHA; 41 опорная запись/2999 инструкций 26
фрагментов побайтно сверены с EXE, SHA каталога совпал, Python syntax прошёл.
Просмотрщики не менялись; новых UI/Android проверок не заявлено.

17.10, V13: SkillLevel1511→Skill getters перезарядки подтверждён через
native loader/индекс/vtable, 33 anchors. Диапазон уровня включительный;
первая подходящая строка, ноль/пусто сохраняет базовое значение. 7 профилей,
4 новых теста прошли; все 1785 NPC/SHA сверены, среди 395 навыков замен нет.
build-skill-level-code.py/skill-level-code.json, источники в NPC-LOOT.md.
Найден счётчик cooldown0x145596ec0, но источник входного интервала ещё неизвестен;
секунды не объявлены доказанными. UI/Android не менялись и не проверялись заново.

17.10, V13: источник интервала замкнут: UGameEngine::Tick/DeltaSeconds→
диспетчер→vtable счётчика cooldown, 33 anchors/27 fragments/1371 инструкция.
build-skill-tick-code.py + контракт UE5.5 подтверждают ms у Min/MaxCoolTime;
build-monster-details проверяет доказательства и маркирует только эти поля.
Карточки показывают базовые min/max в секундах, сырые значения сохранены;
TotalTime/эффекты/предметный CoolTime не пересчитываются. 1785 SHA/2632 skill
вхождения и 81 тест прошли. Сервер 17946 перезапущен, браузером 100171031→
50250/50251→2 с/2 с проверен, console чистая, screenshot сохранён.
Источники в NPC-LOOT.md. Итоговые runtime-поправки/урон/остальное время остаются.

17.10, V13: по просьбе пользователя добавлены доступные имена навыков:
English525 приоритет, полная KO1020 fallback по точному Skill. Id.
22en+267ko=289 подписей/395skills; 106 без имени. Русский перевод только
базовой атаки с оригиналом/флагом перевода/CSV record. 1785 SHA/2632 skill
вхождения, 59Python тестов и браузер 100171031→Базовая атака 01/02 проверены.
build-monster-details.py строит skill-names-verification.json; документация обновлена.
TotalTime остаётся неизвестным:0x14568e9e0 отвергнут как ложная связь
(slot 0xb0 вызывается на объекте 0x1456048e0, не на Skill).

17.10, V13: TotalTime audit закреплён build-skill-total-time-code.py,
5 anchors/4 fragments/2159 instructions + getter bytes/vtable, повторный SHA
совпал. Скан 264 FF90..97/B0-кандидатов — только discovery, не все формы dispatch.
Тип получателя прямого вызова 0x140d550ae также не доказан Skill; это исправляет
возможное неверное прочтение прежней зацепки. Единица/runtime duration неизвестны.
UI: TotalTime · исходное значение + title-пояснение вместо «Длительность»;
JS syntax/браузер 100171031/console прошли, screenshot total-time-checked.png.
Полный регресс повторно не запускался: изменение текста/подсказки, без пересчёта
или изменения исходных данных. Источники/ограничения в NPC-LOOT.md.

17.10, V13: Effect timing: build-effect-time-code.py, 23 anchors/7 fragments/
2941 instructions/imports strtoul/_atoi64. Min/MaxDuration/Period хранятся 64bit,
но первичная загрузка zero-extends uint32; ModifyValue использует int64.
Все 2027 строк укладываются в uint32, Min/Max до 2500000000;413 Duration вне границ.
Поля сохранены раздельно, DurationGrowthRate/пояснение добавлены в общий UI.
load_effects проверяет источник; 83 теста/1785 SHA/75 кандидатов/браузер Frenzy прошли.
Единицы времени, приоритет Duration/MinMax и runtime-таймер не доказаны;
SkillOperation. Param1→Effect остаётся кандидатом. Документация в NPC-LOOT.md.

17.10, V13: native-проверка SkillOperation. Param1 не дала нового подтверждения,
статус кандидата сохранён. Вместо повышения статуса добавлен обратный индекс
подтверждённых Skill↔NPC: 395skills/2632 links, SHA в monster-manifest.
Карточка→«Показать NPC с этим навыком», боковой поиск, ?skill=ID, reset;
учтены Battle-варианты/пересечение фильтров. 85 тестов/1785 SHA/сверка индекса
с каждой карточкой прошли; браузер 50250→3NPC/147spawn, unknown→0 проверен.
Источники/происхождение/границы в NPC-LOOT.md. Фактическое применение навыка
монстром и связь Param1→Effect ещё неизвестны.

17.10, V13: результаты skill-поиска сгруппированы по точному npc_id после
применения мира/предмета/поиска/слоёв. Число размещений/список миров сохранены;
клик открывает карточку и вписывает размещения NPC. Переключатель возвращает
все исходные точки.50250→Field Corpse30/Field Wandering Corpse30/Wandering Corpse87.
21 Node-проверка прошла; браузер 3NPC↔147 записей/карточка проверен, screenshot
npc-skill-groups-checked.png сохранён. Native/серверные связи не менялись.


### 17 октября — каталог книг навыков

Частично: 403 книги Type31,112 с цепочками NPC-наград; отдельный фильтр,
редкость, карточка и переход к источникам карты. 402 совпадения EffectParams/Skill. Id
помечены кандидатами. Осталось доказать обработчик изучения, магазины/крафт.
62Python+25 Node=87 тестов и браузер проверены. См.NPC-LOOT.md, раздел книг.


### 17 октября — книги, результаты крафта

Готово в указанном объёме: 57 книг/107 отдельных путей ItemCraft→Reward→Item,
проверка 3 native diagnostic offsets, SHA/CSV provenance; карточка рецепта/исхода/
количества, фильтр каталога. 89 тестов и браузер 6010001/57 книг прошли.
Осталось: доказать Material. GroupId, Shop reward handler и EffectType4→Skill;
проценты и серверную доступность не заявлять. Подробности в NPC-LOOT.md.


### 17 октября — эффекты предметов и проверка геометрии

Частично: 19 названий Item. EffectType из native parser/43 anchors, 1774 предмета
с подписанным типом; 20 fallback не None. Форматы EffectParams, runtime пассивов
и сочетание World/Room ограничений остаются. AreaBox loader 15 anchors/vtable/ret0,
без доказательства pivot. Отчёт геометрии/5160 навигационных inputs и статус карты,
проходимость неизвестна. 92 теста/браузер прошли. Источники и команды в
NPC-LOOT.md и MAP-ATLAS.md; новых игровых действий/Android проверки не было.


### 17 октября — V67, источники навигации

Частично: 15 native anchors путей/Nav loader/IsPathConnected, 14 RefNavMesh headers
и 1 импорт; Nocturne header 886/соседний кандидат 887,20 ExternalActors с неизвестной
связью. Воспроизводимая сборка navigation-study→geometry→scene, 13Python+21 Node
и SHA проверены. Браузер отключён; маршруты/AreaBox pivot ещё не доказаны.
Далее: схема exports/внешних chunks, навигационные полигоны/связи и IsPathConnected.
Источники в MAP-ATLAS.md. Предметные эффекты остаются в предыдущем состоянии.


<a id="17-октября--v67-подтверждённый-пакет-и20-частей-nocturne"></a>

### 17 октября — V67, подтверждённый пакет и 20 частей Nocturne

Частично: exports связывают 886/887 (прежний candidate повышен после проверки
диапазонов/класса/полного покрытия); 20 ChunkRef/path/Bounds, 6 native descriptors,
строгий decoder.16Python+21 Node/SHA прошли. Сервер 17946 запущен; браузер карта/
status 20/alert/console проверены. Маршруты/AreaBox pivot остаются неизвестны.
Далее извлечение payload частей, полигоны/связность и проверка движения.


### 17 октября — V67, payload и навигационные объекты уровня

Частично: 7PAK/21494 plain records/0 ошибок, 22 RecastNavMesh кандидата.
Подтверждён Nocturne-level header 1141/body 1140 (обратное расположение), 34206 exports,
49bounds/63link components/NavSystem/Recast/RefLoader со всеми SHA.19Python
прошли. Это 115 объектов, не готовый граф; polygons/runtime link conditions
не разобраны. Далее custom serializers/payload. MAP-ATLAS.md/level/index.json.


### 17 октября — V67, относительные точки компонентов лифтов

Частично: 63link components→BP_Lift* по export.outer, 4 native property descriptors/
array и 4constructor anchors. 49 стартов/40 концов/27 пар в relative координатах,
IDuint64 без потери точности.6unknown fields14/22 и все suffixbytes сохранены.
23Python проверки прошли. Сборка build-navigation-level.py→build-navigation-links.py.
Остаются parent transforms/архетипы/direction/enabled/движение и полигоны chunks;
никаких пеших рёбер графа не создано. Источники MAP-ATLAS.md/link-properties.json.


### 18 октября — V67, SceneComponent размещения лифтов

Частично: 63Link.outer→Parent→единственный SceneComponent, 13nativeprefixdescriptors,
явные location63/rotation57/scale14/absolute-locationtrue7, потерянных байтов нет
(неизвестный 8-byte suffix сохранён).27Python проверок прошли. RootComponent,
attachments/архетипы/полные worldtransforms/условия движения остаются. Полигоны
прохода и маршруты не заявлены. Источники MAP-ATLAS.md/lift-placements.json.


### 18 октября — V67, корень и наследование лифтов

Частично: constructorNnLift создаёт Scene и назначает в SceneRoot/Actor. RootComponent,
7 anchors/2 native descriptors. Пакеты BP_Lift/Test/Type01 извлечены, SuperIndex/import
подтвердили NnLift→BP_Lift_C→Test/Type01.30Python тестов прошли. Native defaultroot
доказан, но instance overrides/архетипы/условия движения/worldpoints остаются.
Отчёт lift-blueprints/index.json, команда build-lift-blueprints.py;MAP-ATLAS.md.


### 18 октября — V67, параметры экземпляров лифтов

Частично: 63 явные ссылки SceneRoot/SmartLinkComp проверены по точным exports;
22 native поля SplineActionParams и 6 полей NnLift, Blueprint own count 2/1/0,
62 явных параметра движения, 8 bAutoActivation=false. Unknown PointLinks/tail
сохранены; отсутствующее не заменяется default.34 Python-теста прошли.
Сборка build-lift-instance-settings.py; отчёт instance-settings.json.
Остаются ActorRoot/attachments/PointLinks/runtime activation/единицы Duration.
Доказательства в MAP-ATLAS.md. Проходимость не заявлена.

### 18 октября — V67, PointLinks и ActorRoot экземпляров

Частично: 62 явных PointLinks массива/62 записи, Direction0=BothWays по native
enum; отсутствующий массив не считается пустым. Проверен Actor serialized
prefix и явное равенство Actor. RootComponent=SceneRoot всех 63 экземпляров.
Unknown actor fields/хвосты и raw SupportedAgents сохранены без назначения
разрешений движения. Отчёт point-links.json, build-lift-point-links.py после
build-lift-instance-settings.py.38 целевых Python-проверок прошли.

build-scene-native-defaults.py отдельно проверил 16 anchors, getter/wrapper/ctor
и 2 descriptors: native AttachParent=null, RelativeScale3D=1×1×1 до переопределений.
Реальная сборка прошла; scene-native-defaults.json содержит SHA/смещения/байты.
Эти defaults экземплярам не назначены. Далее архетипы/attachment/потребитель
transform/runtime активация; мировые маршруты по-прежнему не подтверждены.
Полные источники и ограничения — MAP-ATLAS.md. Эффекты предметов остаются частичными.

### 18 октября — V67, прямые ссылки шаблонов SceneComponent

Частично: build-lift-archetypes.py проверил 63 цепочки template/outer ссылок
через 6 Scene-шаблонов в 3 пакетах до native Default__NnLift. Scene.
9 экземпляров с базовым шаблоном, 8 Test, 46 Type01;3 имени размещений устарели,
фактические class/template ссылки согласуются. Все 6 Blueprint Scene templates
без явных свойств; native CDO/post-construction ещё не разрешены.
Новый decode-package-references.py проверяет диапазоны, FName, таблицы и циклы.
42 целевых Python-проверки прошли. Отчёт archetypes.json, SHA и таблицы/экспорты
в MAP-ATLAS.md. Далее native effective defaults/transform/runtime conditions;
готовые координаты переходов и проходимость не заявлены.
Также build-lift-bounds-code.py проверил 18 anchors/4 descriptors/vtable slot 199:
PointLinks stride 0x70, Left+40/Right+58 входят в min/max bounds, затем читается
RootComponent+1d0. Сборка прошла; bounds-code.json. Формула world endpoints/
обновление кэша/навигационная выгрузка не доказаны; следующий поиск локализован.

### 18 октября — V67, мировой кэш корневого компонента

Частично: 4 именованные native binding, 32 anchors/4 descriptors и 3 полных leafgetter
проверены build-component-transform-code.py на закреплённом EXE.
Блок+1d0 подтверждён как мировой transform96 bytes, location+1f0/scale+210;
цепочка 1425a78a0→143af8c00 читает RelativeLocation/Scale/AttachParent и пишет
тот же блок, прослежена ветка без родителя. Реальная сборка прошла.
Отчёт component-transform-code.json. Rotator conversion, итоговые CDO defaults,
world endpoints/runtime state остаются; мировые переходы на карту не нанесены.
Подробные адреса/байты/SHA/границы — MAP-ATLAS.md.

### 18 октября — V67, формула вращения и преобразование bounds

Частично: lift-transform-math.py и build-lift-rotation-evidence.py.
Изолированная эмуляция 1414fd980 с vector trig helper проверила 195 вращений,
включая 57 явных rotation из проверенных компонентных bytes; ошибка≤5.56e-16.
195 синтетических преобразований bounds14550d6c0 совпали с преобразованием
углов локального AABB, включая negative/nonuniform/zero scale; ошибка≤1.17e-10.
Начальный AABB[(0,0,-10),(0,0, 10)] установлен по EXE и учтён в сравнении.
49 целевых Python-тестов прошли. Отчёт rotation-evidence.json с полными
результатами/страницами/SHA; Unicorn 2.1.4 закреплён в requirements-native.txt.
Реальные effective CDO/attachments/world endpoints и проходимость остаются.
Это проверка математики, не 195 игровых переходов. Источники MAP-ATLAS.md.

### 18 октября — V67, предварительный слой лифтов на большой карте

Частично: build-lift-map-preview.py→build-world-map.py публикует 63 записи,
14 связей из полностью явных transforms/endpoints; 49 неполных без подстановки
defaults. Прямые root/archetype ссылки и исходные export/SHA/PointLinks bytes
повторно сверены. Слой отдельно от points/World. Id/навигационного графа,
условие отсутствия parent transform/смещения уровня/runtime явно показано.
world_transform_verified=false и walkable=null; это не 14 проверенных маршрутов.
UI: переключатель, выбор, клик по отметке, A/B/Z/разница высоты, native direction,
сырьё/источники и URL?lift=1836. Камера учитывает ширину карточки.
52Python+21 Node/JS syntax прошли. В браузере проверены полный 1836/неполный 1818,
reload по URL, zoom+/−, 0console errors; снимок lift-preview-checked.png.
Следом inherited defaults/attachments/frame/runtime activation. MAP-ATLAS.md.

<a id="18-октября--v67-исходные-настройки-и57-расчётных-связей"></a>

### 18 октября — V67, исходные настройки и 57 расчётных связей

build-lift-initial-values.py: 26 anchors/3 native descriptors/3CDO checks,
проверенные template chains, native scale1×1×1 и один начальный PointLinks
[(0,-50,0),(0,50,0)] с Direction0. В Blueprint CDO нет PointLinks override,
Scene templates не задают scale. Это initial values, не окончательное runtime.
Слой 57 связей: 14 полностью явных+43 с provenance initial_fields; 49 scale
заполнены из initial (включая 6 ещё неполных), 1 PointLinks у 1821.
Явный 0scale и пустой массив сохраняются; 6 rotations не угаданы.
55Python+21 Node/JS syntax прошли. В браузере 1818(scale), 1821(scale+links),
1819(unknown rotation), URL reload/console проверены. Снимок lift-inherited-checked.png.
Далее 6 rotations, frame/attachments/runtime activation; walkable=null,
world_transform_verified=false. MAP-ATLAS.md/initial-values.json.
После проверки браузер отключён в настройках Work; повторный снимок последней
правки прозрачности/отступов A/B недоступен. Предыдущий снимок новых 57 links сохранён.

### 18 октября — V67, нативная ветка обнуления объекта

build-object-zero-init-code.py: 24 anchors и точная import/IAT цепочка
1487a2e25→VCRUNTIME140.dll!memset. Default-subobject141746350→1417cd8a0→
construct1417e0fc0→allocate1417e0420; zero branch перед class constructor,
но reuse может пропустить обнуление, затем вызывается initializer finalization.
Итоговый default rotation этим не доказан, 6 missing не заполнены.
59Python проверок прошли, 4 новых защищают import target/terminator/ordinal/
string/directory bounds. Report object-zero-init-code.json, SHA/bytes в MAP-ATLAS.md.
Далее constructor/base callbacks и finalization1417c61a0; UI остаётся 57 links,
готовая проходимость не заявлена.

### 18 октября — V67, template copy после конструктора

build-object-template-copy-code.py проверил 43 anchors, import memcpy,
2Scene vtable slots и bytes пустого callback. Finalizer1417c61a0→1417d7840
выбирает explicit template или class+110;1417d4d10 копирует свойства по
runtime offset+44, длинам+30/+34, raw-copy flagbit30 либо virtual slot 100.
Для subobjects отдельный цикл; post-init Scene+50 ведёт к 143a537b0→дальше,
Scene+58 пустой. Реальная сборка прошла. Финальное вращение не доказано:
не разрешены runtime FProperty/source CDO и последующие callbacks.
Отчёт object-template-copy-code.json, источники/SHA в MAP-ATLAS.md.
UI остаётся 57 links/6missing rotations. Следом реальные template values,
а не подстановка нуля из первоначального memset.

### 18 октября — предметы, коробки и обратные источники

ItemBox CSV196/native diagnostics связаны с Item/Reward; 644 коробки,
10568 раздельных путей, 0issues. Карточки: содержимое/изображения/редкость/
количество/rawRate/вложенная цепочка, требуемый ключ, 40 наград за порцию.
Обратные ссылки 1396 предметов, включая 133 книги; path_count не количество
выпадения. Явные unknown режим/шансы/runtime сохраняются.27Python+4 Node,
JS syntax/SHA644boxes и manifest прошли. build-npc-loot.py и build-world-map.py
пересобраны. Browser disabled в Work; визуальный результат пока не проверен.
Подробности NPC-LOOT.md; прочие эффекты/пассивы/условия остаются.


### 18 октября — порядок карточки и локальный сервер

Блок «В каких коробках указан предмет» перенесён после характеристик,
пассивных навыков, ограничений и общих свойств, перед исходными данными.
Состав связей не менялся. build-npc-loot.py и build-world-map.py пересобраны;
node --check, порядок секций и совпадение source/deployed JS проверены.
Сервер запущен на 127.0.0.1:17946, listening подтверждён. Browser tool
отклонил доступ к вкладке по URL policy; визуальный вид не проверен.


### 18 октября — названия режимов строк наград

Reward. RewardGroup→ERewardGroup подтверждён ModifyValue/parser: 7 имён,
72 anchors, fallback 7 не объявлен режимом. Названия показаны по всей цепочке
в раскрытой награде коробки. ItemBox. RewardGroupType остаётся raw/unknown;
его нельзя автоматически подписывать тем же enum.27Python+4 Node прошли,
SHA644boxes/report/deployedJS проверены, loot и большая карта пересобраны.
Подробности и следующий шаг (binding поля коробки/условия выбора/проценты)
в NPC-LOOT.md. Визуальная проверка не выполнена из-за browser URL policy.


### 18 октября — привязка режима коробки к enum

ItemBox. RewardGroupType подтверждён через native loader+28 и параметр
OnItemBoxUpdated/ERewardGroup. 644 коробки получили названия режимов,
unknown/Max не объявляются режимом. Runtime выдачи/шансы остаются неизвестны.
25 native+22data anchors, 28Python+4 Node прошли; 644 SHA/atlas loot manifest/JS
проверены. Порядок сборки и подробные доказательства — NPC-LOOT.md.
Визуальная проверка не выполнена (ранее browser URL policy отклонила вкладку).


### 18 октября — картинки в обратном списке коробок

По запросу пользователя каждая строка «В каких коробках указан предмет»
получила 44px иконку перед названием, фон редкости из каталога и общую ссылку
картинка/название. Точные пути box.icon.images и rarity.background.images
повторно используются из уже связанного каталога; новых числовых joins нет.
623 коробки имеют 1 картинку, 1 имеет 2 кандидата (показаны оба с title пути),
20 не имеют картинки (placeholder ? с пояснением).625 локальных PNG
проверены на наличие. Lazy loading/alt пустой при доступном имени ссылки;
ошибка загрузки показывает placeholder. Сортировка, 40 строк за порцию и
расположение после характеристик сохранены. JS syntax/source-deployed JS/CSS
проверены; build-npc-loot.py и build-world-map.py пересобраны.
Визуальная проверка не выполнялась после отказа browser URL policy.


### 18 октября — порядок коробок: редкость и алфавит

Обратный список коробок использует существующий ItemRarity.compare
(высшие редкости первыми, специальные категории отдельно); при равной
редкости — видимое имя через Intl. Collator ru/numeric: true/sensitivity: base,
затем ID для однозначного порядка. Общая сортировка выполняется перед
порциями 40. Рейтинг не выдумывается. Тот же boxName используется в строке.
Проверен фактический JS sort block на всех 1396 списках, без потери строк;
JS syntax и source/deployed совпадение прошли. Loot/atlas пересобраны.
Новых связей и изменений данных нет; browser visual check не выполнялся.


### 18 октября — книги и целевой навык

Native проверка SkillAcquire и уже изученного навыка подтвердила
EffectParams→_wtoi→Skill. Id. 403 книги/402 найденных Skill, 1missing201006
для книги 22001005. Карточки получили подтверждённое имя/ссылку на навык.
Изучение/серверные условия не проверены; 17 SkillAcquirePotion исключены
из распространения этой связи.30Python+4 Node/SHA/report/JS/atlas manifest
прошли. Источники, новый builder и порядок — NPC-LOOT.md.


### 18 октября — обычные эффекты предметов: кандидаты, связь ещё не доказана

В текущем каталоге 56 Item. EffectType=1 (Effect): 50 CombatPotion Type26,
3 Type5,2 Type55,1 Type48. У всех 56 полный EffectParams совпадает с Effect. Id.
Это числовое совпадение; native target binding пока не найден.
`skill-effect-links.py:item_candidate` сохраняет origin=item, source_field,
item_id/item_provenance, точный raw EffectParams, совпавший Effect definition
и уже проверенные EffectOperation rows. relation_verified=false и
runtime_application_verified=false. Прочие EffectType, пустой параметр и 0
не включаются. Prefix/leading zeros не преобразуются в совпадение.

В item-details/index.json.item_effect_candidates сохранены 56 записей;
эффект/операции/режимы берутся из существующего verified load_effects,
с CSV92/93 schema/SHA/provenance и native diagnostics; нового доказанного
join Item→Effect не заявлено. skill-effects.js различает item и skill
контекст: текст прямо называет совпадение ID и отсутствие установленного
эффекта предмета. Блок свёрнут по умолчанию, раскрывается внутри секции
типа эффекта. Единицы времени, период/длительность, проценты и runtime
не угадываются; исходные параметры и операции сохранены отдельно.

Исследование native EXE (тот же SHA c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8):
сравнения memory+68==1 часто относятся к другим структурам, они отвергнуты
как доказательство Item. EffectType. Исследованы 583 корня с direct call
145a80590 (Item handle getter), 2070 полностью декодированных фрагментов;
6 фрагментов содержат не полностью декодируемый хвост и в доказательства
не включены. Discovery только в игнорируемых .tools/item-get-functions.json
и item-effect-get-paths.txt; это указатель поиска, не воспроизводимый proof report.

Особенно важно не повторять ошибочную ветку 1463759f0: она действительно
читает Item. EffectParams+70 через _wtoi и вызывает 145938880, однако этот
lookup использует EffectOperation manager145940ee0, secondary vtable
149946a38/loader 14595b760 с literal EffectOperation.csv. Его UI caller
14637fe50 проверяет Type по 145db8d60, который допускает 49/53/54/75/76
(BloodSeal/CommonSeal/EventSeal/CommonSeal2/EventSeal2), а не EffectType1.
В текущих 57 предметах этих типов EffectParams пуст, EffectType20. Поэтому
эта ветка НЕ повышает 56 Effect1→Effect. Id до доказанной связи.
Effect manager отдельно: singleton 145940e50/global 14b14e4f0,
secondary vtable1499444b0/slot 38→loader 145959c60; direct handle lookup
145938440. Среди исследованных Item-get корней прямой подходящий вызов
с Item. EffectParams не найден. Следующий поиск: косвенные вызовы/общие
UI effect helpers и server-fed item effect state, сохраняя тип входной записи.

38Python+4 Node прошли; 2 новых теста проверяют item provenance/false flags,
отсутствие recursive application, другие EffectType/sentinels и exact ID.
Проверены 56 кандидатных records, source/deployed shared JS, syntax,
актуальный loot SHA в atlas. Loot/atlas пересобраны. Визуальная проверка
не выполнялась после ранее полученного отказа browser URL policy.


### 18 октября — отдельные карточки навыков и книги изучения

3446 Skill+1missing target получили hash-linked JSON и карточку ?skill=ID.
403 подтверждённых книг доступны с обратной стороны навыка; картинки,
редкость, предмет/источники, отсутствие записи 201006 сохраняются.
Старая ссылка только фильтровала NPC; теперь параметры видны и у player
skills без NPC на Nocturne.25Python+21 Node прошли, SHA3447files/403books/
изображения/source-deployed проверены. Порядок/источники — NPC-LOOT.md.
Реальное изучение и визуальная проверка не подтверждены.


### 18 октября — исходные ограничения применения навыков

Общий renderSkillDetail показывает ClassType/UnusableRoomType/UsableWorldId,
3 флага и группу стоимости повышения в свёрнутом блоке.3446 Skill records
сверены с CSV1505/SHA, 3447detail SHA и deployed JS проверены; syntax прошёл.
Первичное изучение/серверные gates и комбинация ограничений не установлены.
Подробности и статистика — NPC-LOOT.md; browser check не выполнялся.


### 18 октября — SkillLevel в карточке навыка

7 навыков/7 строк SkillLevel, уровни 6–7: расчёт Min/MaxCoolTime по native
первой включённой строке, нуль/empty→base. Other Change fields raw-only.
20Python+23 Node прошли; 84 actual JSON/deployed JS/Python comparisons совпали,
3447 detail SHA и источники проверены. Доступность уровня и runtime cooldown
не подтверждены. Порядок/источники — NPC-LOOT.md; browser check не выполнялся.


### 18 октября — SkillLevel Resource и StackCount

Новый build-skill-level-extra-code.py → code-clues/skill-level-extra-code.json,
SHA256 `a02f33083c80f3afb3e37142f1092cc65ff134802745aeb122bf9af69140ce37`.
Проверены EXE SHA c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8,
Capstone 5.0.6,30 instruction anchors, 4 literals, 2 Skill vtable slots.
Sources Skill 1505/SkillLevel1511 и их index/SHA остаются прежними.

Skill loader 145bc6470: Resource literal 145bc67c4→FString record+f8
(145bc7831/145bc7849), StackCount literal 145bc6746→byte+d4 (145bc7612).
SkillLevel loader 145bc89c0: ChangeResource145bc8b71→FString+20/+28 length
(145bc900e/145bc9023), ChangeStackCount145bc8bfd→byte+78 (145bc94f8).
Getters Skill vtable1499b9440: slot 138→145bba6b0 для Resource,
slotd8→145bba990 для StackCount. Оба используют прежний подтверждённый
lookup 145bb2570 по Skill. Id и первую включённую строку диапазона.
Resource: при FString length+28>1 возвращается row+20, иначе Skill+f8.
StackCount: nonzero byte row+78 возвращается, 0→base Skill+d4.
На следующую пересекающуюся строку после нулевой/пустой замены не переходят.
Пустой UTF16 string имеет length 1 с терминатором; пробел не обрезается.

extra_at_level(Python)/WorldMapModel.skillValuesAtLevel(JS) сохраняют
origins table/field/provenance. JS расширяет прежний cooldown result только
при отдельных resource_replacement_verified/stack_count_replacement_verified.
Остальные Change-поля остаются raw-only. StackCount проверяется как byte
0…255; malformed/negative/overflow отклоняются, не обрезаются по модулю 256.
Это не доказательство смысла счётчика как зарядов или фактической анимации.

В данных 6 ChangeResource: 110018,120023, 130023,140012, 150022,1500221.
Предыдущее commentary о 5 ресурсах исправлено по фактической CSV-проверке.
У 110033 ChangeStackCount2 на уровнях 6–7. UI сравнения показывает выбранные
значения и источник; базовые snapshots не складываются, runtime=false.
Другие изменения/рост/MP/окончательная перезарядка ещё не вычисляются.
Следующий найденный кандидат: getter 145bba160 читает row+6c и base+e4,
но его точная привязка к MP и вариант Max пока не закреплены proof report.
Leaf145bba1f0 читает только base+e4, поэтому нельзя автоматически считать
его ChangeMpMax getter по соседству vtable slots. ChangeMpMin/Max/Growth
в текущих 7 строках пусты; их поддержку этим шагом не заявлять.

Порядок: build-skill-level-code.py и build-skill-level-extra-code.py →
build-world-map.py (внутри build-monster-details.py). Builder сверяет extra
EXE SHA/verified flags/каждый anchor перед публикацией, сохраняет источники
в monster-manifest и skill-npcs.json. Skill index SHA после сборки:
`2506fbca42e4127ba17899f7077774f388f081b51513eef40b6302427f3722b2`.
23Python+25 Node прошли; 3Python+2JS новых теста покрывают диапазоны/ID,
нулевой fallback первой строки, отдельные поля, пробел в Resource,
provenance, отсутствие verified flags и недопустимые bytes/levels.
84 real Skill/level cases (7×0…10,32767) deployed JS совпали с Python
по Resource/StackCount и origins; все 3447detail SHA и source/deployed JS
текст проверены. Дополнительно повторно побайтно сверены 36 anchors отчёта.
Визуальная проверка не выполнена после ранее полученного browser URL policy отказа.


### 18 октября — MP по уровню и повторный запуск сервера

build-skill-level-mp-code.py проверяет Skill MpMin/MpMax literals
145bc677e/145bc678c→stores+e4/+e8 (145bc76a2/145bc76c5),
SkillLevel ChangeMpMin/Max145bc8bd3/145bc8be1→+6c/+70
(145bc94a2/145bc94be), Skill vtable1499b9440 slots100/110→
getters145bba160/145bba0d0. Полные getter control-flow сохранены:
lookup 145bb2570, первая inclusive строка, ненулевой override или base.
Report code-clues/skill-level-mp-code.json SHA256
782b21ffc8d4db1766f2a92fa085a9dd4f5359a8d746da63e2f1f9a111c78d99;
90 instruction/4 literal/2slot anchors, тот же EXE SHA/Capstone 5.0.6.
Builder перед использованием проверяет EXE/verified flags/каждый anchor,
сохраняет MP evidence source в monster-manifest и skill index.
Запускать proof builder перед build-world-map.py.

Skill level comparison теперь показывает исходные MpMin/MpMax с отдельными
verified flags/origins. Все 7 MP overrides пусты, так что реальные записи
возвращают базу. MpGrowth и фактическое потребление MP не вычисляются.
Консервативная модель принимает только nonnegative decimal signed-int32
replacement, malformed/negative/overflow отклоняет, не имитируя UB/partial parse.
25Python+27 Node прошли (2 новых Python+2 Node: независимые поля, first-range,
нулевой fallback, происхождение, proof gate и malformed/overflow).
Все 3447 detail SHA/source-deployed JS сверены; 84 MP real cases подготовлены
для сравнения deployed модели с Python. Browser visual check не выполнялся.
По запросу пользователя listener17946 проверен (отсутствовал), сервер запущен
на 127.0.0.1 из F:/PhoneExit Resources/Vampir. Зафиксированы HTTP200 для atlas,
manifest, skill index и карточки навыка; favicon404 не относится к данным.


### 18 октября — иконки навыков

1101 unique Skill. Img ресурс показан в общей карточке навыка/NPC.188 missing,
2157not_declared не подменяются похожими именами.4 image-поля и source SHA
сохранены.298 PNG SHA/3447detail SHA/source-deployed HTML-JS проверены,
28Python+27 Node прошли. Сборка build-world-map.py обновлена без отдельного
шага. Native widget/актуальный Android не проверены; подробности NPC-LOOT.md.


### 18 октября — пассивный навык → предметы

build-monster-details.py: skill_passive_item_index разворачивает существующую
подтверждённую цепочку Item. PassiveSkillGroupId=SkillSet. GroupId,
SkillSet. SkillInfoId=Skill. Id из item-details/passive groups.
Каждый group JSON загружается через SHA из проверенного item-details index;
каталог Items и index также читаются через loot manifest SHA. Native diagnostics
не переисследуются: ссылки из item-details.passive_diagnostics сохраняются в
skill-npcs.sources вместе с group specs. Новый native join не заявлен.

Для каждого item и sid сохраняются group_id, все set_records/provenance,
item provenance/name/icon/rarity. Несколько строк одного sid не создают
несколько карточек предмета, но все исходные строки остаются; чужой GroupId
исключается. Missing Skill definition не стирает подтверждённый target.
Payload passive_items содержит relation_verified=true,
runtime_activation_verified=false.39 items→19 Skill IDs/19groups/39 links.
Книги изучения остаются отдельным books блоком со своим acquisition flag.

Общий Skill renderer показывает «Предметы с этим пассивным навыком»:
иконки с исходным rarity background, названия/редкость/ID, group ID и число
исходных строк, ссылки на свойства предмета и ?item=ID источники карты.
Сортировка существующая rarity→алфавит→ID. Наличие ссылки не доказывает
активацию, серверные модификаторы или реальную доступность источника.
Блок появляется только при найденных связях, в отдельной карточке и у NPC.
Пример ?skill=321001. Поиск навыков включает reverse passive target IDs,
в текущих данных все они уже присутствуют в Skill table.

Сборка build-world-map.py обновляет monster/skill JSON и manifests.
Skill index SHA256:
`4af0b6d0e30d490caae591fc3253f6b3404a30e9235c036506d5aa38f626b450`.
19 целевых Python tests прошли (monster-details/item-details), новый тест
покрывает exact group, все строки, несколько items, provenance/false activation,
чужую группу и пустой index. JS syntax прошёл. Сверены 3447card SHA,
все 39items с PassiveSkillGroupId присутствуют в reverse sources без потерь,
каждая SkillSet строка имеет правильные GroupId/SkillInfoId, source/deployed JS.
Визуальная проверка не выполнялась после ранее полученного browser URL policy отказа.

### 18 октября — навигация навыков в атласе

После текущей визуальной проверки ?skill=ID перестал неявно скрывать отметки:
фильтр NPC включается отдельным действием и сохраняется как skillNpc=1.
Возврат к карте/раскрытие параметров проверены в браузере; Frenzy321001:
5 предметов, обычные 24071 запись; 50250: явный фильтр 3NPC/147 размещений.
Пустой раздел книг скрыт, SkillEffect отображается безопасно через textContent
и strong; параметры и исходные данные доступны в details.17Python+27 Node
прошли. Осталось пересечение подписей на общем масштабе и адаптивная проверка.

### 18 октября — читаемость подписей карты

Полные прямоугольники подписей больше не пересекаются друг с другом,
видимыми значками и панелью выбора; учитываются все края viewport.
Приоритет выбранной области, 4 направления и смещения до 120px с линиями
к точке, длинные названия сокращены с многоточием. Записи/координаты/поиск
не меняются. 30 Node tests и syntax прошли, реальные общий и увеличенный
виды проверены в браузере; снимки .tools/ux-audit-321001/05-06*.
Проходимость и неизвестные повороты остаются частичными.

### 18 октября — структура справочника

Исследование типов Item/Equipment/Skill/Quest и именованных систем из
native diagnostics выполнено, 17 CSV сверены по SHA, 5827Item по типам.
Результат CATALOG-STRUCTURE.md и maps/catalog-category-study.json;
генератор study-catalog-categories.py. Отдельные каталоги и общее меню
остаются к реализации. Новые native joins не заявлены.

### 18 октября — отдельные каталоги и меню

Реализованы навыки/предметы/книги с отдельными URL, поиском/фильтрами и
подробными карточками, общая навигация. Общий SkillCard и существующий
ItemDetails сохраняют параметры/источники. 68 тестов данных/моделей и
переходы в живом браузере пройдены. См.CATALOG-STRUCTURE.md.
Монстры пока прежний NPC/rewards viewer; полноценная отдельная карточка
монстра, Развитие/Задания и расширенные фильтры остаются следующей работой.

### 18 октября — фильтр класса и прокрутка каталогов

Книги/навыки: класс в фильтре/карточке/URL, Item. ClassInfoId не теряется
при Skill. ClassType=All, unknown/conflict отделены. Догрузка по прокрутке
(порции 60) в новых каталогах и старом NPC viewer. NPC: уровень в списке,
сортировка вверх/вниз/имя, диапазон. 56 тестов и реальные 60→102/120,
уровни 50–60 проверены в браузере. См.CATALOG-STRUCTURE.md. Native runtime
допуск класса не заявлен; полная отдельная страница монстра остаётся далее.

### 18 октября — отдельная страница монстра/NPC

Каталог atlas/monsters.html и ?npc=ID реализованы для 5285NPC;
Battle/навыки/личные цепочки/отдельные области/61307 размещений сохранены.
Меню/ссылки с карты/источников предметов ведут на новую страницу.
32Python+35 Node, 5285detail SHA и несколько браузерных случаев пройдены.
Новые runtime joins/проценты не заявлены; портреты NPC продолжены ниже, свежий Android,
подтверждение проходимости/поворотов и остальные системы остаются далее.

### 18 октября — изображения NPC из явных полей клиента

Npc. Img и NpcProfile. NpcInfoId→Npc. Id/Img связаны с точными texture basename.
Каталог/карточка/карта используют общий MonsterCard.renderPortraits, фильтр
«Изображения» отделяет найденные файлы.86NPC с изображениями, 40missing,
5159not_declared; 55PNG. Семейство Blueprint не подменяет отсутствующий портрет.
53 целевых теста, 5285detail SHA/55PNG SHA/7deployed UI файлов проверены.
Браузер: профиль 91001 и Larva100001 карта→полная карточка, PNG708×492.
Подробности/источники/SHA — NPC-LOOT.md и CATALOG-STRUCTURE.md.
Остаются поиск 40 указанных ресурсов, runtime-сверка внешности, свежий Android,
повороты/проходимость; обычному 100181052 картинка не приписана.

### 18 октября — навыки → NPC всех миров

Индекс расширен на все 5285NPC: 1344 навыка/9610 точных связей,
отдельное all_npc_ids; прежнее npc_ids сохранено для 395 навыков Nocturne.
Каталог/фильтр считают все миры, полная карточка показывает NPC с уровнем/
мирами/ссылкой; догрузка 60.20Python+34 Node и сверка всех 5285NPC/
3447skill SHA/полноты обратных связей пройдены. Браузер: Sweep1002061
4NPC вне Nocturne, переход 99002000;50401 —201 всего, 170 на карте,
догрузка 60→180, фильтр карты 170NPC/177 размещений. Новых native joins нет,
runtime-применение навыков не доказано. См.CATALOG-STRUCTURE.md/NPC-LOOT.md.

### 18 октября — поиск предметов по эффектам/пассивам/ограничениям

items.html: EffectType, наличие PassiveSkillGroupId и LimitGroupId/ItemUseLimitId;
фильтры пересекаются с поиском/редкостью/типом/классом книги, сохраняются в URL
и возврате.56Effect1/39passive/42restriction declarations; код 20 неизвестен,
не None. Словарь эффекта экспортируется в loot/index из проверенного builder,
без загрузки 3.1 MB item-details для общего списка.20Python+6 Node/26 tests,
SHA источников/4deployedassets и браузерные 56/39/42/возврат/Viper102 проверены.
Новых доказанных EffectParams→Effect или runtime-предикатов нет. Подробности
и отклонённая native ветка 14611f5f0 — NPC-LOOT.md.

### 18 октября — подтверждённые материалы крафта

Новая native-связь ItemCraft. Id=ItemCraftMaterial. GroupId, несмотря на пустой
CraftInfoId; CostType2/CostParam→Item. Id доказан виджетом материалов.
563 рецепта/1733 строки (1369Item+364Asset); 38 несвязанных строк сохранены отдельно.
В 861 пути результатов 441 предмета и 403 книгах сохранены материалы/provenance,
картинки/ссылки/количества/CostEnchantLevel; правила подгрупп и сервер не заявлены.
build-craft-material-binding.py→build-npc-loot.py→build-world-map.py выполнены;
64 native+17data anchors, 27Python+10 Node/37 tests, SHA/861 пути/403books и браузер
21011003 (10Page/100Trinity/250000Gold), 11015007 (материал с 13 заточкой) проверены.
Подробности/источники/границы — NPC-LOOT.md, CATALOG-STRUCTURE.md.

### 18 октября — материал → рецепты → предметные результаты

156 материалов/1369 связей, SHA-файлы craft-uses. Одна запись на рецепт сохраняет
все строки затрат и каждый путь/исход результата отдельно; валюты и недоказанные
target исключены. Карточки результатов с иконками/редкостью и ссылкой recipe=ID,
которая раскрывает рецепт/переводит фокус и прокрутку. Порции 40/автодогрузка.
29Python+10 Node/39 tests, 156 SHA/все 1369 связей/5deployedfiles сверены. Браузер:
Skill Book Page11 рецептов, Essence6010001 раскрывается при переходе; Trinity265,
40→80. Новых native joins нет; runtime/проценты остаются прежними неизвестными.
Документация: NPC-LOOT.md/CATALOG-STRUCTURE.md.

### 18 октября — повёрнутые AreaBox: точка вращения и направление

Найден потребитель 145dd3fa0→14568ed80: MinPos/MaxPos/Yaw→проверка XY-точки.
Центр(Min+Max)/2 и положительный XY-поворот подтверждены 11728 точками 1466 случаев
в ограниченной Unicorn 2.1.4 эмуляции без игры/OScalls. Все 772 поворота таблицы
и 322Nocturne получают геометрию; карта 603AreaBox/175Area labels/24074points.
Две обратных записи не исправлены предположением, navigation_ready=false.
16Python+30 Node/46 tests, SHA603polygons/772 audit и браузер SquallHill945% прошли.
build-area-box-code.py→build-area-transform-evidence.py→build-world-map.py;
MAP-ATLAS.md содержит источники/anchors/отчёт/кеш/--fresh. Остались реальные
полигональные nav-данные/маршруты и Android, а не поворот этих AreaBox.

### 18 октября — извлечение generated-пакетов навигации Nocturne

Дополнительный поиск 147428UAsset headers/106PAK/789182486 байт дал 214 кандидатов.
34 пакета с summary pathNocturne/_Generated_ подтверждены exports/body coverage/
ownership RecastNavMeshDataChunk→NavigationDataChunkActor→Level→WorldNocturne.
Извлечены 34Recast payloads/17348530 байт, все версии сохранены.37Python tests,
34 полных пары/214hit SHA/цепочка geometry→scene и браузерный счётчик проверены.
Инструменты search-navigation-chunk-headers.py→build-navigation-generated-chunks.py
→build-world-map.py. MAP-ATLAS.md: источник, лимиты, SHA. Далее custom serializer/
полигоны/связи/выбор версии и маршруты; navigation_ready=false.

### 18 октября — собственная сериализация Recast chunks

build-recast-serialization-code.py закрепляет 50 опорных инструкций EXE,
класс/constructor/vtable/Serialize и два tile/cache codecs. Native version 20..26,
uint64 length включает себя; int32 перед codec не является длиной байтов для skip.
Во всех 34 экспортах по одному кандидату envelope (offset 14/version 26),
tile_count суммарно 19098. Не объявлять границу properties/полигоны разобранными.
Найдена отдельная custom-version lookup по 16 байтному ключу с порогом 97;
значение архива ещё устанавливать. Отчёт/SHA/проверки в MAP-ATLAS.md.
Четыре новых теста: начало отсчёта длины, версии/count, truncation и bounded search.
Всего 25 целевых Python tests; независимо сверены 15 fragments/50 anchors/34export SHA.
Остались property boundary/custom version→восстановление buffers→полигональные
связи/активная версия/маршруты/Android. navigation_ready=false.

### 18 октября — восстановление буферов тайлов Recast

extract-recast-tile-buffers.py: 34 полных экспорта/19098 тайлов/27249848 байт,
изолированная Unicorn 2.1.4, явные гипотезы property offset 14/custom version 97.
Все записанные/вычисленные размеры равны, каждый поток завершён точно на EOF.
Нативный lookup версии выполнен 63 раза; значение 97 подставлено, не извлечено.
validate-recast-tile-buffers.py независимо сверил source/proof/EXE/code-pages,
все 34buffer SHA/19098tile SHA, непрерывность исходных/выходных диапазонов.
21navigation+7 recast tests=28. Отчёт/SHA/команды — MAP-ATLAS.md.
Следом: native-структура вершин/полигонов/соседей, property boundary/custom
version и выбор активных пакетов, привязка координат и проходимость маршрутов.
routes_verified=0/navigation_ready=false; готового навигационного графа нет.

### 18 октября — геометрия и внутренние соседи тайлов

build-recast-geometry-code.py закрепил 47 anchors serializer/присоединения
тайла/именованного dtNavMeshQuery::raycast; непрочитанный tail явно opaque.
decode-recast-geometry.py: 214851 вершина/104726 полигонов/228354 направленных
internal links; все индексы в границах, все общие рёбра взаимны.
34 пакета/19098 тайлов сохраняют гипотезы предыдущего этапа и все версии.
21navigation+13 recast tests=34, весь output JSON независимо сверен с buffers.
MAP-ATLAS.md: layout/источники/SHA/порядок/ограничения. Далее 108758high-bit
рёбер и специальные переходы, coordinate conversion, active versions и путь;
routes_verified=0/navigation_ready=false.

### 18 октября — native координаты и отображение сетки на карте

build-recast-coordinate-evidence.py: 29 anchors/69 cases, native world→nav
[-X, Z,-Y] и inverse[-X,-Z, Y] совпали побайтно, signed zero сохранён.
build-recast-map-overlay.py (включён в build-world-map.py) создаёт SHA-bound
слой 18430 ячеек/101090 обычных полигонов; 62 special polygons пропущены.
JS лениво загружает/валидирует geometry, clip по viewport, LOD ячейки→полигоны.
Слой отключён по умолчанию и явно исследовательский, показывает все высоты.
56Python+33 Node=89 tests, все 207420vertices/101090faces/scene binding/deployed
assets проверены; браузер 233%/14413%/1375% и снимок 19-navigation-overlay.png.
Остаются active coverage/parameters, special transitions, runtime link limits/
quantization и проходимость/Android. MAP-ATLAS.md содержит источники/порядок/SHA.

### 18 октября — правила внешних рёбер и дубли сетки

build-recast-portal-code.py: 57 anchors/26 fragments, source side→opposite side,
plane/overlap epsilon, height test с detail triangles, interval bytes и uint32
length общей сетки. decode-recast-nav-params.py: один кандидат Nocturne offset 443,
height parameter35; property boundary/inheritance dispatch ещё не доказаны.
build-recast-grid-inventory.py: 19098→18430grid/layer, 668 идентичных повторов,
конфликтов 0, внутри package дублей 0. Все 19098grid/hash/source identities
независимо сверены с native buffers.21navigation+20 recast tests=41.
MAP-ATLAS.md: sources/SHA/команды/ограничения. Следующий этап — полное native
сопоставление внешних рёбер с detail height и подтверждёнными параметрами;
active coverage/версии/координаты/special links/проходимость остаются.

### 18 октября — native matcher на всей объединённой сетке кандидатов

recast-portal-emulator.py: строго ограниченные клиентские portal/detail/triangle/
array-fast-path инструкции в Unicorn 2.1.4; только cookie call пропущен, никаких
OS/import/game process.10synthetic cases и real reciprocal seam прошли.
build-recast-external-graph.py --height 35:18430 тайлов/104961 boundary edges,
106595 native calls/125718 направленных переходов/2953 отклонённых пары.
188detail/332triangle samples. audit-recast-external-graph.py проверил все
125718 границ/индексов/интервалов, reverse отсутствует у 0 пар; 32 native replay совпали.
21navigation+24 recast tests=45. MAP-ATLAS.md: SHA/порядок/ограничения.
Порог 35 и архивные/property assumptions явные; graph — candidate union.
Остаются параметры активной сетки/coverage, special links, coordinate conversion,
runtime link limits/quantization/порядок загрузки и реальные маршруты/Android.
routes_verified=0/navigation_ready=false.
