# Vampir — главный указатель разработки

Атлас переключён на русский язык: названия и описания из именованных таблиц
текущего клиента, исходный текст при отсутствии однозначного перевода.
[Источники, сборка и границы перевода](../resource-tools/vampir/ATLAS-RUSSIAN.md).

Цель: самостоятельный сетевой бот без процесса игры, затем управление через
лёгкую 2D-карту, игровые меню, сценарии фарма и переносимый Android runtime.
Исследовательские инструменты и большие данные остаются отдельно от runtime.
Пользователь перешёл на Global / EU / Prelude 2. Основной тестовый аккаунт
через панель получил Game Login 0 и одного персонажа; назначение по ключу сохранено.
После отдельного отказа на NID следующий запуск получил серверную позицию;
статус «В мире» проверен в панели на одном EU-аккаунте.
[Наблюдения и границы EU-сессии](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-EU-ACCOUNT-CONSOLE.md).
После создания персонажа пользователем новый EU-аккаунт также прошёл
автоматический launcher-вход ботом: Game Login 0, один персонаж Prox на Prelude 2.
Он назначен по серверному ключу. После отдельного отказа NID HTTP 400 следующий
запуск получил позицию Prox. XI и Prox одновременно наблюдались «В мире»
в семи снимках за 30 секунд; затем оба worker штатно остановлены.
Это короткая проверка двух аккаунтов, не длительная устойчивость или reconnect.
Прежний SDK 1203 в успешной попытке не повторился; причина отказа не изолирована.
[Панель аккаунтов, списки и границы живой проверки](../vampir-headless/ACCOUNT-CONSOLE.md).
В панели добавлена общая таблица с раздельными паролями под «глазиком».
Подготовлены 24 новых аккаунта с осмысленными почтовыми именами и назначениями
по два на каждый из 12 EU-серверов. Все почтовые ящики созданы и проверены,
все 24 аккаунта Netmarble подтверждены. Назначения ещё не означают наличие
игровых персонажей.
Прямой вход SDK / лобби без Phone Exit проверен. Установлен отдельный выбор
лобби EU / NA / SG в текущем EXE; selector прошёл 540 native-сценариев.
Свежий EU-каталог получен: Prelude 2 — server ID 384 / group ID 358.
Прежний HK-профиль получил Game Version 0 и Game Login 59 / BlockedInfo до списка.
Он больше не используется для EU; этот отказ не переносится на основной аккаунт.
Создание нового персонажа ботом ещё не выполнялось; причина прежнего отказа не установлена.
Проверена отдельная ветка пустого списка: 16 native случаев успешного ID 102
отличаются от 18 отказов Login 57 / 58 / 59. Найдены Create 103 / Result 104,
вложенный CreateData и producer; полный формат внешности ещё не проверен.
[Пустой список и подготовка создания](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-EMPTY-LIST-CREATION-ENTRY.md).
Целый reader запроса создания ID 103 проверен на 36 телах и 1398 коротких
префиксах, включая строки и непустой массив внешности.
[Формат чтения и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-REQUEST-READER.md).
Целый writer ID 103 проверен на 42 телах и 24 отказах выходного fixture;
переносимый encoder совпал с native байтами. Допустимые игровые значения,
producer и результат создания ещё не подтверждены; отправка не подключена.
[Запись тела и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-REQUEST-WRITER.md).
Источник класса уточнён: PlayerState создания хранит ID найденной строки,
полученной по типу из `Class_` tag. Lookup прошёл 45 native случаев с sparse
storage. Затем singleton связан с ClassInfo / Type loader и Gunner converter;
свежий PAK подтвердил Id 3 / Type 3 / DefaultGender 1. Проверка текущих строк
и native lookup охватила 54 случая; отправки создания ещё нет.
[Цепочка выбора и оставшиеся границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CLASS-LOOKUP.md).
[Текущие классы и источники](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CURRENT-CLASSES.md).
Reader ответа создания ID 104 проверен на 16 телах и 729 коротких префиксах.
Переносимый decoder возвращает code и запись, но не сохраняет ник автоматически.
[Ответ создания и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-RESULT-READER.md).
Целый helper внешности проверен в 12 сценариях до границы JSON serializer:
обход занятых настроек и обязательный VoiceType. Начальный VoiceType равен 0;
реальные ключи внешности и JSON engine output ещё не подтверждены.
[Входы генератора внешности](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-INPUTS.md).
Entry helper внешности прошёл 24 native случая до lookup / JSON captures:
неизвестная definition пропускается, найденная задаёт отдельный JSON key.
BoneGroup F / M извлечены из текущего PAK: по семь групп с ID 1–7 и разными
наборами костей. Схема строки сверена с EXE. Затем точные пары `.uasset` / `.uexp`
подтверждены полным каталогом текущего PAK с проверкой SHA1 обоих индексов.
Источник диапазонов и начальных float-значений ещё открыт.
[Definition и преобразование ключей](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-ENTRY.md).
[Текущие группы внешности](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-BONEGROUP-RESOURCES.md).
[Имена файлов и проверка каталога](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-BONEGROUP-DIRECTORY.md).
Сброс перед preview проверен в 24 native случаях: поля внешности, голос и map
очищаются, пол сохраняется. Последующие записи preset / UI ещё не прослежены;
это промежуточное состояние, не готовая внешность для отправки создания.
[Инициализация и следующий вызов](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-RESET.md).
Далее прослежены preset и сохранённая внешность через UI ползунки. Обработчик
и запись float прошли 44 native случая: нормализация value / scale выполняется
перед записью, JSON и preview. Поиск / вставка записи map пока fixture;
реальные preset, масштаб и диапазоны ползунков ещё не подтверждены.
[Запись параметров и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-SLIDER.md).
Следом настоящие map lookup / insert / update прошли 26 native сценариев
с коллизиями и повторным использованием свободных слотов. Строковые операции
и память остаются fixtures; рост map не проверен. Predicate preset прошёл
64 случая сравнения типа класса. Теперь нужны реальные строки и значения пресета.
[Контейнер внешности и фильтр пресетов](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-MAP.md).
Текущие таблицы пресетов прочитаны: 16 / 13 строк. Type 3 связан с
DA_PresetDarkMage3_F/M (ID 3 / 2), несмотря на имя файла. Значения извлечены;
семь float defaults 0.5 и voice 0 подтверждены native constructor. Пропущенные
int32 остаются неизвестными до проверки CDO. Четыре теста прошли.
[Пресеты Carnage, значения и недостающие defaults](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CURRENT-PRESETS.md).
Пол связан с ресурсом: 0 / Male → M, 1 / Female → F. При DefaultGender 1
у Carnage выбирается F и preset ID 3. Целые path helpers прошли 1024 случая
с явными engine-строковыми fixtures. Max 2 не считать допустимым полом.
[Enum пола, суффиксы и уточнение прежнего разбора](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-GENDER-PATHS.md).
Для CharacterCustomizeUI подтверждён native constructor default scale 1000:
шесть сценариев через условный constructor wrapper, с сохранением guards.
Поздние overrides и min/max ещё не проверены. Найдена функция создания CDO;
её allocation / default copy нужны для отсутствующих int32 пресета.
[Identity экрана, масштаб и следующий путь CDO](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CUSTOMIZE-SCALE.md).
Следом проверена граница default property copy: 36 native сценариев подтвердили,
что размер родительского DataAsset 0x30 не позволяет копировать собственные поля
пресета от +0x30. Обнуление новой allocation найдено статически; полный цикл
CDO / загрузки asset ещё не проверен, отсутствующие int32 остаются unknown.
[Копирование defaults и границы проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-DEFAULT-COPY.md).
Initializer / context push и вся цепочка constructors пресета прошли 24 native
сценария без подмены базовых constructors: int32 сохраняются, семь float равны
0.5, voice равен 0. Ещё шесть postconstruct сценариев с текущими virtual methods
без config / subobjects изменили только flags. Wrapper завершения и загрузка
asset ещё не проверены; omitted int32 пока не подставляются автоматически.
[Инициализация, virtual bindings и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-INITIALIZER.md).
Wrapper завершения прошёл 24 native сценария: 18 немедленных и шесть отложенных.
Проверены восстановление context и пометка копии initializer из queue fixture.
Оба текущих asset указывают native CDO `Default__NnDataAssetForCustomizePreset`;
extractor теперь проверяет class / template / super references и отклоняет подмены.
Перенос defaults при загрузке asset ещё не исполнен, omitted int32 остаются unknown.
[Завершение и привязка шаблона](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-COMPLETION.md).
Найден ordinary constructor `1417e6cb0` со встроенным initializer. В 18 native
сценариях проверены copy flag, source CDO и перенос по выбранному списку полей.
Extractor сохраняет отдельную модельную проекцию недостающих int32 со значением 0;
исходные unknown сохранены, loaded asset не объявлен проверенным. Проекция —
явный кандидат для следующей offline проверки целого producer / JSON внешности.
[Обычный объект и происхождение проекции](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-OBJECT.md).
Целый producer создания прошёл 37 native сценариев: 24 остановки и 13 перехватов
до границы отправки. Native writer совпал с encoder, включая модельный Carnage/F.
Порядок Hair / Head / Eye / Decal связан с текущими helper-записями в owner;
дополнительные байты равны 0/0, items пуст, ожидается ID 104. JSON helper остаётся
fixture; следом его ключи / значения и целый handler результата. Сети не было.
[Запрос, порядок полей и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRODUCER.md).
Ключи JSON внешности проверены в 36 native сценариях через AsNumber и formatter:
при явных Latin rules текущие группы дают ключи 1–7; другая таблица цифр меняет
ключи. Float32 → double, signed zero и обязательный VoiceType подтверждены.
Добавлен переносимый builder с явным Latin profile и SHA; числовая семантика
сверена с native setter captures. Native JSON bytes и серверный допуск не заявлены.
[Ключи, культура и builder](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md).
Целый handler ID 104 прошёл 128 успешных и 30 ошибочных native сценариев.
Code 0 принимает запись независимо от совпадения имени; nonzero не назначает
персонажа. Добавлено решение runtime `created` / `rejected` / `needs_refresh`
без автоматического retry. Следом — подключение одной отправки к принятому
пустому списку и живой контроль; создания ботом пока не было.
[Ответ, ожидание и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-RESULT-HANDLER.md).
Создание подключено к GameConnection / exchange как явная opt-in операция:
accepted Login и пустой список, один keyed ID 103, полный send перед ID 104.
Timeout / EOF дают unknown без retry; existing character исключает Create.
Локальная socket-сессия и regression проверки прошли. Worker / UI отправку
пока не включают; далее постоянный журнал неопределённого исхода и живой контроль.
[Сессионный lifecycle и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-SESSION-FLOW.md).
Worker и панель получили отдельное создание Carnage. Постоянный журнал фиксирует
pending до очереди; crash / unknown блокируют повтор до отдельного свежего списка.
Подтверждённые key/name сохраняются, слот назначается по уникальному совпадению
ключа в новом списке. Проверены временная БД, конкурирующие попытки и worker mocks;
живое создание ещё не запускалось. Далее одна проверка пустого EU-аккаунта.
[Worker, журнал и проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-WORKER-JOURNAL.md).
Живой контроль запущен: новый EU-аккаунт дважды прошёл NID, но получил SDK
HTTP 400 / 1203 до игрового соединения. Основной аккаунт SDK прошёл, затем
остановился на выбранном лобби. Create не отправлялся, журнал попыток пуст.
Найдена и исправлена передача creation_factory через вложенные wrapper-функции;
два новых теста прошли. Причина различий SDK / лобби остаётся неизвестной.
[Живые этапы и исправление](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-LIVE-PREFLIGHT.md).
Текущий launcher-контракт теперь сверён отдельно от прежнего EXE: два запроса,
три ключа и два обработчика ответа. Формат совпадает с разделением в runtime;
source-bound audit и три теста прошли без авторизации. Причина SDK 1203 остаётся
открытой; следующий участок — фактический consumer ошибки, а не повтор регистрации.
[Текущие адреса, проверки и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-LAUNCHER-CONTRACT.md).
Далее найден прямой игровой caller SDK и его callback. Целый callback прошёл
67 native сценариев; обычный отказ ведёт к сообщению, успех и специальные ошибки
разделены. UI, журнал и manager actions остаются captures. Причина живого 1203
не установлена; следующий вопрос — выбор режима до отправки первого входа.
[Цепочка результата и границы исполнения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GAME-SIGN-IN-RESULT.md).
Первый игровой вход содержит отдельный Fetch и базовые условия; в runner бота
этого этапа пока нет. Целый Fetch callback прошёл 27 native сценариев: только
ShowBasicTerm 30050027 вместе с контекстом 1203 ведёт в TermsOfService.
Это не основание для SignUp после любого отказа launcher. Далее backend Fetch
и продолжение условий, затем явный режим первого подключения.
[Первый вход, условия и точные границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-FIRST-GAME-FETCH.md).
Добавлен отдельный read-only `--fetch-player`: один `v1/fetch-player`, затем
остановка без входа / условий / создания. Четыре новых и 20 auth regression
tests прошли. Новый аккаунт получил HTTP 400 / SDK 1203 именно на Fetch;
контроль основного остановился на NID до запроса. Далее продолжение terms до SDK SignUp.
[Контракт Fetch, живая проверка и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-FETCH-CONTRACT.md).
Продолжение индивидуальных условий замкнуто до текущего SDK SignUp. Целая native
цепочка с виртуальными обёртками и выбором Guest / Netmarble прошла 99 сценариев;
UI, HTTP и серверное создание остаются вне проверки. Найдены входы termsUrl:
страна, язык и платформа. Далее реальный ответ / завершение окна условий.
[Переход к SDK SignUp и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-TERMS-CONTINUATION.md).
Подтверждён BasicTerms GET и отдельный ответ NO DATA: resultCode -1 передаётся
как raw UI state 2 с error result. Публичный запрос UA / en-US / PC получил
такой ответ. Добавлен offline plan / summary условий; четыре теста прошли,
summary не подтверждает согласие и не разрешает SDK SignUp. Далее individual terms без player ID.
[Ответ условий и граница согласия](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-BASIC-TERMS-RESPONSE.md).
Индивидуальные условия без player ID используют termsUrl GET и termsType I;
это отдельная ветвь от agreementUrl с player ID. Диспетчер и отложенный callback
прошли 96 native-сценариев: исходные ошибка и состояние сохраняются. Публичный
индивидуальный GET получил NO DATA с объектом terms вместо массива BasicTerms.
Добавлен отдельный план GET без сетевого вызова; пять тестов условий и два
теста передачи результата прошли. Далее проверка обработчика NO DATA до
диспетчера, затем ветви с доступными условиями и их показом;
первый SDK вход ещё не замкнут, новых персонажей бот не создавал.
[Индивидуальный запрос и передача результата](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-INDIVIDUAL-TERMS-DISPATCH.md).
[Прямой маршрут, результат и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-DIRECT.md).
[Региональные адреса и native-проверка](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-LOBBY-REGIONS.md).
[Живой EU-вход и отказ 59](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-GLOBAL-EU.md).

Карта должна принимать действия по выбранной точке / сущности, а оболочка —
показывать события сессии, игровые окна, их тексты и доступные кнопки.
Состояние команды и её результат подтверждаются сессией; отключение вывода
не останавливает обработку событий.
[Требования к действиям и окнам](../vampir-headless/TASKS.md#действия-с-карты-события-и-кнопки).
Обновления должны обрабатываться автоматически: обнаружение изменений,
переизвлечение и сверка связей; неоднозначные случаи — в очередь ручной доработки.
[Порядок и критерии](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md#автоматизация-следующих-обновлений).

Последняя живая проверка 22 октября через новый Redmi M2006C3LG / JP:
Login / список / выбор / вход в мир code 0, затем сервер принял одну команду
обучения 1001 / 2: ID 9904 code 0. Сокет и маршрут закрыты. Выбор квеста,
автоматическое движение ещё не проверены. Повторный вход без команды подтвердил
изменение записи обучения 1001 с 0 / 0 / 1 на raw0c 2 / raw10 1 / state 2.
[Сохранённое состояние](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-PERSISTENCE.md).
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-ACK-ACCEPTED.md).

Периодический Ping подключён явно. Новая JP-проверка после ID 206 прошла
20 секунд: четыре периодических Ping, пять ID 17, ошибок нет. Сокет и маршрут
закрыты. Длительная сессия, движение, карта и reconnect ещё не проверены.
[Проверки heartbeat и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SESSION-KEEPALIVE.md).

Проекция Map 10/11 повторно проверена на текущем EXE и новых World/Map CSV.
Лёгкая модель серверной позиции → пиксели для 36 миров используется слоем
сессии в атласе; проходимость не подтверждена.
[Источники, изменения таблиц и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-MAP-POSITION.md).

В атлас подключён read-only слой сессии: live цель входа показана в мире 10010 /
Blood Pool. Вывод включается / выключается, «К персонажу» выбирает мир и центрирует
карту. Проверены 120 секунд сессии: 24 периодических Ping / 25 ID 17 без ошибок.
Маркер очищен после close, endpoint и маршрут закрыты. Это снимок цели входа;
непрерывное положение, живые сущности и движение ещё не подключены.
[Запуск, проверка UI и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-MAP-SESSION.md).

## Что работает и где остановились

Для сравнения квестового поведения пользователь сохранил новую эталонную
запись запуска, движения по квесту, телепорта и остановки автопрохождения.
Файлы проверены, игровой поток разобран: 394 пакета, без незавершённых кадров.
ID 1801 / 1802 / 1836 не встречаются; найдены QuestUpdate / Complete / Start /
Teleport. Точное соответствие кликам ещё не установлено. Следом — поля ID 1810.
[Эталон квестового сценария](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-QUEST-REFERENCE-CAPTURE.md).
[Пакеты официального сценария](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-REFERENCE-TIMELINE.md).
Формат QuestUpdate / 1810 проверен целым native replay: 29 байт, вектор,
два qword и байт. Добавлен отдельный codec без отправки; источник значений
и обработка результата ещё не установлены.
[Структура запроса и проверка](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-WIRE.md).

Новый вход через Xiaomi / JP прошёл до мира с кодом 0, но один повторный
запрос списка квестов снова вернул code 100. Исправленный decoder разобрал
ответ без ошибки. В словаре текущего клиента 100 соответствует
CharacterNotSelected; причина отсутствия нужного контекста ещё не установлена.
Samsung / JP получил
Game Login 58 / BlockedIp до этого запроса. Выбор квеста пока не выполнен.
[Повторная проверка и источники](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-REFUSAL-RECHECK.md).
[Имя кода и границы расшифровки](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-RESULT-NAMES.md).

**Текущий результат: вход, выбор и ID 206 приняты; серверная целевая позиция получена.**
В одном соединении Login 0, CharacterList 0 / один персонаж, ID 110 code 0 /
4724 байта полностью разобраны; затем ID 202 → ID 203 → ID 204 → ID 205 → ID 206.
Ошибок нет. Вектор ID 206 проверен на конечные значения и связан с миром ID 204;
это позиция до коррекций движка, пока без подтверждённой проекции на 2D-карту.
[Живой результат и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-WORLD-FINISH.md#живой-id-206-после-замены-телефонов).

Следом — последующие события положения и сущностей, затем квестовое состояние;
длительное поддержание и восстановление проверять отдельно. Готовые native readers и вход не повторять без нового шага.

Входящие пакеты движения ID 306 / 307 разобраны и сверены с native readers:
28 тел и 20 коротких префиксов. ID 307 содержит ключ сущности и XY; применение
к собственному персонажу и карте ещё проверяется.
[Форматы и следующий шаг](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-CHARACTER-MOVE-EVENTS.md).

ID 307 подключён к feed карты с проверкой ключа собственного персонажа;
XY показывается как серверная цель с сохранённой высотой из ID 206.
Локальные проверки прошли. Три новые попытки через доступные JP / HK получили
58 / BlockedIp до списка. После замены телефонов HONOR JP прошёл вход, выбор,
ID 206 и 120 секунд без ошибок; цель входа показана, ID 307 не поступил.
Живое обновление XY пока не подтверждено. Соединение / feed / маршрут закрыты.
[Проверки, ограничения и следующий шаг](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SELF-TARGET-STREAM.md).
[Успешная проверка через HONOR JP](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-HONOR-SESSION.md).

Уточнение пользователя: персонаж ждёт нажатия квестовой панели / шага обучения.
Приоритет — определить активный шаг и связать его текст с обработчиком панели,
затем подтверждение действия и движение. В готовых извлечениях найдена цепочка
Tutorial 1001 / step 1001002 → `QuestPanel_PanelTouch`. Шесть выбранных строк
текущих CSV совпали с прежними; активное состояние ещё проверить.
ID 9905 / TutorialUpdateNotify уже приходил
в сессии. Вложенный формат разобран: decoder прошёл 72 native тела и 29 коротких
префиксов; смысл трёх полей и lifecycle применения ещё проверяются.
[Reader состояния обучения](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-UPDATE-READER.md).
Новый явный observer прочитал живой ID 9905 через HONOR JP: 16 записей,
ключ 1001 / state 1, остальные state 0. Конкретный шаг и смысл остальных
полей ещё проверяются; кнопка продолжения не нажималась.
[Живое состояние и следующий шаг](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-STATE.md).
Локальный переход к следующей строке проверен в 64 native-сценариях с явными
fixtures допуска / запуска. raw0c=0 не доказывает ожидание step 2;
проверка условий и callbacks задач продолжается.
[Выбор строки и переход](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STEP-ADVANCE.md).
Прослежен отдельный путь завершения обучения: producer создаёт
PktTutorialUpdate / ID 9903 с ключом и селектором строки. Показ подсказки связан
с UI-контроллером; активный шаг и callback нажатия пока не подтверждены,
команда не отправлялась.
[Подсказка, запрос и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-ACTION-ROUTE.md).
Формат ID 9903 теперь проверен исполнением: два uint32 и исходный байт,
64 native вектора и три отказа записи. Добавлен отдельный encoder без отправки.
ID 9904 / TutorialUpdateResult разобран: decoder прошёл 216 native векторов /
19 коротких префиксов; handler и сброс ожидания — 45 сценариев с явными fixtures.
Удаление ожидающего ключа, копирование раннего ответа и применение записи
теперь проверены native: 12 / 32 / 384 сценария. Серверная запись и локальный
селектор различаются; в этих проверках ответа gate задачи и запуск — fixtures.
Потребитель очереди ID 9904 прошёл ещё 64 native-сценария с явными fixtures
освобождения: готовность, порядок, возобновление и отсутствие повторной обработки.
Начальная цепочка ID 9905 → построение локальной задачи → первый переход
прошла 192 native-сценария с явными table / storage / launch fixtures;
ранний gate исполнен настоящим кодом. Именованные setters подтвердили поля
TutorialStep, но row+0x50 нельзя подменять Tutorial.Type из CSV.
Условия автоматического действия и callbacks ещё проверяются; отдельную явную
команду ID 9903 предстоит связать с наблюдением и ответом той же сессии.
Классификация квестов, автовыполнение и источники прежнего UI
уточнены в TASKS.
[Writer и следующий ответ](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-REQUEST-WRITER.md).
[Ответ и различие ожиданий](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-RESULT.md).
[Применение и отложенный ответ](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-APPLY.md).
[Consumer очереди и начальное уведомление](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-QUEUE-DRAIN.md).
[Начальный переход и именованные поля](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STARTUP.md).
[Данные и сетевые привязки](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-PANEL-ENTRY.md).
[Ближайший порядок](../vampir-headless/TASKS.md#ближайшее-действие).

### Предыдущие этапы до живого ID 206

Полный эталон 4c713eb5 уже дал продолжение: после ID 110 сервер присылает
ID 202 без исходящего ID 201, затем клиент отправляет ID 203 (8 байт), получает
ID 204 и отправляет пустой ID 205. Current apply / receive / start request
прослежены статически; границы native проверок приведены ниже. Теперь нужен
актуальный consumer ID 204 и условия завершения мира. Позиция остаётся неизвестной.
[Цепочка из эталона и текущего кода](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#продолжение-по-полному-эталону-4c713eb5).
ID 203 сверён с native writer; префикс ID 202 проверен в 80 случаях,
целый reader ID 204 — на 72 телах и 30 коротких префиксах текущего SHA.
Добавлен явный `--read-world-start` для перехода в том же соединении до ID 204.
Хвост ID 202 остаётся непрозрачным; ID 205, готовность мира и позиция не подтверждены.
Живая JP-проверка прошла до ID 204 code 0; соединение и маршрут закрыты.
[Результат новой сессии](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#живое-продолжение-id-204-принят-22-октября).
[Проверки и границы продолжения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#продолжение-до-id-204-локальные-и-native-проверки-22-октября).
Запрос ID 205 и проверка его состояния в текущей сборке исполнены в 48 сценариях: состояния
2 / 3 / 4 и флаг +0xc1 определяют разрешение отправки. Тело запроса пустое.
Найден путь через состояние 4 и streaming actor, а в ID 206 — создание / обновление
NnCharacterPC по серверному вектору. Native callback / позиционный wrapper проверены
в 8 / 36 сценариях. Целый reader ID 206 проверен на 18 телах с пустыми массивами,
81 коротком префиксе и 256 headings. Непустые массивы дополнительно прошли
24 тела и 286 коротких префиксов, включая размеры из эталона;
без нового флага runtime останавливается после ID 204. Явный `--read-world-finish`
добавляет ID 205 → ID 206 и серверную целевую позицию; локальные проверки прошли.
[Условия ID 205 и границы проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#id-205-текущая-проверка-состояния-и-запрос-22-октября).
[Завершение загрузки и путь позиции](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-RELEASE-WORLD-FINISH-POSITION.md).



Ниже сохранён путь предыдущих проверок, включая прежние отказы Login 16;
они не отменяют текущий успешный результат выше.

21 октября после докачки примерно 1,1 ГБ подтверждены новый EXE SHA
98802d550890…, AppVersion 1.13.14 и ClientVersion 261105. Отдельные профили
`recovered-release` для CDN и SDK / NID подключены с проверкой источника;
смешивание старого SDK snapshot с новым профилем отклоняется до авторизации.
Новые settings / GMC2 defaults, PC label, игровой override, base selector,
URL и заголовки проверены native-сценариями. Инструменты остаются вне runtime.

В Game Login была найдена прежняя compiled-строка Version / Login. Новая строка
подтверждена pointer / literal нового EXE, native slice и успешным HK-захватом;
профиль теперь передаёт её в оба пакета и отклоняет смешивание версий.
Новый native mapper подтвердил: код 1 — InvalidPacketVersion.
После исправления через JP и HK SDK / лобби / Game Version приняты, Game Login
дал **16 / InvalidState** в обоих случаях. Список при отказе не отправлялся.
Реальный вход бота, выбор и позиция ещё не получены; временные маршруты закрыты.
[Доказательства, исправление и live результаты](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-WIRE-TAG.md).

Пользователь заменил телефоны; на последней проверке доступны samsung SM-A205F
и Redmi 2201116SI с выходом JP, Redmi M2103K19Y — HK, APK 0.9.6.
Следом сверить оставшиеся поля / источники metadata и ранний обмен с успешным
клиентом; не повторять авторизацию без конкретного подтверждённого изменения.
Обновления данных и остальная цепочка до позиции остаются в общем плане.
Новая официальная запись 2d150317… сделана через HK (уточнение пользователя).
Разобраны 190 игровых пакетов: Login code 0, CharacterList code 0 / один персонаж,
выбор ID 109 → ответ ID 110 и дальнейшая инициализация. Metadata клиента 792 байта
против 219 у бота; ClientVersion 261105, server 256 и raw language byte 1 совпали.
Переход бота на HK при том же subset тоже дал 16; причина не выделена. Позиция
не извлечена. Ключи в Login / metadata трёх успешных захватов затем сравнены
с текущим Windows-хранилищем и привязкой бота: проверенные значения совпали.
Предыдущая запись 8e13f35e… была пустой: ошибка лаунчера вне игрового фильтра.
Для следующей проверки Phone Exit получил явный режим «Весь TCP через телефон»
без списка адресов: до 3 минут, 32 МиБ и 1024 соединения, с автоостановкой.
Охват приложений задаётся режимом VPN; HTTPS остаётся зашифрованным, UDP не
записывается. [Инструкция расширенной записи](../../pc/DIAGNOSTICS.md#как-записывать).
[Разбор и границы сравнения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#успешный-hk-захват-2d150317-после-обновления).
Новая запись 3f8ab7fe… снова содержит успешные Login / список / выбор:
181 игровой пакет, Login code 0, список code 0 / одна запись, ответ ID 110.
В записи запуска 21fc5087… нет игровых соединений: захват достиг прежних
128 потоков за 33 секунды и выключился. Это ограничение диагностики, не
установленная причина ошибки игры; предел увеличен до 1024 потоков.
[Результаты обеих записей](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#расширенные-записи-3f8ab7fe-и-21fc5087-21-октября).

Пользователь закрепил 4c713eb5… как основной эталон полного успешного входа.
Полная запись проверена: 125 секунд / 97 потоков, лимиты не достигнуты.
Есть список серверов, вход в лобби и одно успешное игровое соединение:
189 пакетов, Login / список code 0, выбор ID 109 → 110. Повторный Game Login
после разрыва мира не наблюдался. Во всех трёх успешных записях до Login идут
IDs 30413 → Version → Ping; бот начинает с Version. Следом доказать источник
и роль предварительного кадра / Ping на новом EXE, затем решить, что менять.
[Полная последовательность и сверка ключей](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#полный-запуск-4c713eb5-и-сверка-идентификаторов).
По новому EXE выгружены constructor / Version callback и source-bound targets
уведомления подключения. Прямой поиск scalar 30413 и wire-константы результата
не дал; роль предварительного кадра ещё не установлена. Эти же literal searches
без изменившихся входов повторять не требуется.
[Проверенные адреса, выгрузки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-BOOTSTRAP.md).
Продолжение: actual send новой версии выгружен; найден producer Ping.
36 native сценариев подтвердили поля «часы / разница», порог >5000, readiness
и recovery branch. Эталонные пять Ping согласуются с producer; часы первого
примерно на 9 часов впереди времени capture. Затем источник часов проверен:
GetSystemTime UTC → календарные ticks → Unix epoch + signed offset в минутах.
24 native clock-сценария и три теста прошли; в обоих lobby ID 2 эталона offset
равен 540. Затем текущая registration связана с ID 2 / PktLobbyVersionResult:
actual reader → handler → clock setter прошли 18 сценариев и 24 длины входа,
три регрессионных теста. Свежий lobby clock context подключён в runner новой
сборки: Version → один ранний Ping → Login. Формула, signed offset, порядок
кадров и отказы проверены локально. Периодический Ping ещё не подключён;
кадр 30413 не найден. Живая JP-проверка: SDK / лобби / Game Version приняты,
получен ID 17, Login снова 16. По запросу пользователя отдельная диагностика
отправила ID 101 после отказа на том же соединении; за 10 секунд ID 102 не пришёл.
Обе проверки завершены, временные маршруты закрыты. Причина 16 остаётся открытой.
[Clock source, native проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-CLOCK.md).
Дополнительная сверка эталона подтвердила session-field handoff лобби → игра:
две строки ответа, SDK token / NID / device / server согласованы с builder.
Полная metadata одинакова в обоих официальных Login — 792 байта. Есть отличие
соединений: официальный ServerList и lobby Login идут в разных TCP-потоках,
у бота — на одном. Причина 16 этим не установлена; следующие источники для
проверки — metadata и lobby lifecycle.
[Сверка полей и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#дополнительная-сверка-перехода-лобби--игра).
Найдена текущая ветвь заполнения common data: FLogImpl::Start → 0x144555470,
которая записывает строки в сам объект. Выделены source helpers и передача
MakeSessionID в отдельный setter. Восемь native случаев и два теста подтвердили:
setter меняет I_NMSessionID, который collector Login не выбирает. I_TID имеет
отдельный источник settings+0x608 → common data. Формат проверен четырьмя
native случаями; current Save сохраняет это поле. Runtime новой сборки теперь
добавляет собственный постоянный TID бота через CoCreateGuid и отдельное SQLite
состояние, без изменения SaveGame игры. 14 проверок прошли. Живая JP-попытка
подтвердила metadata 262 байта, SDK / лобби / Game Version приняты, но Login
снова 16. Маршрут закрыт. Остальные metadata и lobby lifecycle ещё проверяются.
Следом выгружены шесть current update callees. Целые UpdateGmc2 / UpdateSDKSetting
прошли 31 native сценарий и три теста: источники IP / страны / города / SDK полей,
отсутствие сервиса, lazy initialization, пустые / равные / изменившиеся строки.
Service и FString backend — fixtures. Условные player / NID ветви ещё
открыты; runtime metadata пока не расширена. Источник страны установлен в продолжении ниже.
[Источники, адреса и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-COMMON-DATA.md).
Затем статически прослежен GMC2 callback → response consumer → geo helper:
key clientIp передаётся string helper, результат переносится в settings+0x38,
откуда UpdateGmc2 получает I_ConnectIP / I_NMMobileIP. GeoLocation helper
0x144552430 оказался SetCountryCode: пишет settings+0x3f0 → I_CountryCD,
а A1 сохраняет прежнюю страну только при непустом старом поле. Целый setter
с notify=0 прошёл 14 native случаев и три теста; FString backend — fixtures.
Generic JSON helpers и полный callback native не исполнены, runtime пока не расширен.
[Цепочка, адреса и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md).

По коду новой сборки прослежены поиск JSON-поля, получение вложенного объекта
и преобразование значения в FString. Есть ветви для чисел и логических значений;
приём только объектов и строк в боте будет отдельной локальной политикой.
Следом подключить свежие clientIp / geoLocation с проверками источника, маршрута,
возраста и правила A1. Полный JSON parser и callback этим не проверены.
[Контракты и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md#json-helpers-границы-извлечения-полей).
Теперь runtime новой сборки получает GMC2 перед входом через выбранный маршрут
и использует один ответ для SDK и metadata. Добавлены I_ConnectIP из clientIp
и I_CountryCD из geoLocation, с правилом A1 и пределом возраста 300 секунд.
34 локальные проверки прошли. Следом — живая проверка; Login 16 ещё не устранён.
[Свежий контекст и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md#свежий-gmc2-context-в-runtime).


Ниже — состояние предыдущего этапа до дополнительной докачки.
21 октября пользователь подтвердил завершение обновления; сервер ещё на технических
работах. Офлайн-аудит выявил новый EXE и основной ProjectRED-Windows.pak.
От снимка 19 октября 35 архивов совпали по полному SHA, 127 — только по выборочной
проверке. Свежий индекс основного PAK построен; 3210 из 3325 сохранённых файлов
нашлись с прежним содержимым. Patch manifest пока старый; совместимость входа
и прежних адресов функций не установлена. [Результаты и следующий шаг](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md).
Ghidra-сравнение двух EXE дало кандидатов для 239 из 424 исследованных функций;
девять приоритетных пар выгружены с инструкциями и псевдокодом. Структура Login
похожа, но внешние зависимости и совместимость новой сборки ещё проверяются.
На новом EXE reader целого body списка проверен в базовом профиле: 12 полных
ответов совпали с переносимым decoder, 238 коротких префиксов отклонены.
Native archive / UTF-8 / record readers и callbacks выполняются вместе;
контейнерная память остаётся fixture. Непустые extensions / optional map проверены
ещё 31 полным body и 489 префиксами, включая коллизии и замену повторного ключа.
Для списка подтверждены constructor / vtable / ID 102 / reader и ключ регистрации.
Новый handler и его gate / predicate исполнены вместе с reader в 50 сценариях:
проверены применение списка, сохранение прежних записей при отказе и начальный
индекс персонажа. Ещё 25 сценариев выполняют непрерывный путь от списка через
state setter и indexed caller до constructor / writer запроса выбора ID 109.
20 байт тела совпали с переносимым codec; handoff, выходной archive и Engine / UI
остаются fixtures. Новая транспортная цепочка и реальная сессия ещё не подтверждены.

На 20 октября 2026 бот проходит NID / SDK-вход, получает список серверов и
успешный ответ выбранного лобби. Игровой Version принят; Game Login на ID 256
ранее возвращал 16 / InvalidState. Новый launcher-вход принят SDK / лобби,
но Game Login через два JP-телефона и HK вернул 58 / BlockedIp.
После следующей замены телефонов новый JP дал 16 / InvalidState при том же
launcher flow; со вторым новым JP прямой транспорт не установился.
Список персонажей из реальной сессии не получен.
21 октября официальный клиент через выбранный JP вошёл в мир: пользователь
создал Okly на Franz 2. После закрытия игры бот на том же телефоне снова получил
16; три сохранённых ключа устройства совпали с текущими Windows-значениями.
Совпадение остальных полей авторизации не доказано.

Для сравнительной записи добавлен [диагностический режим Phone Exit](../../pc/DIAGNOSTICS.md).
21 октября получена первая реальная запись официального клиента: игровой Login
принят с кодом 0, список содержит одного персонажа, видны запрос выбора и ответ
ID 110. Проверены целостность, framing и исходящие CRC; позиция ещё не извлечена.
[Подробности и воспроизведение](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md).
Сравнение выявило два отличия: metadata +0xd8 содержит 791 байт вместо пустой
строки; byte +0x124 равен 1 вместо 7. Источники актуального контекста ещё нужно
подключить; причина отказа 16 и достаточность этих отличий не доказаны.
Байт +0x124 связан с языком: 1 / en-US, 7 / ko-KR. Добавлены явный выбор
языка и encoder metadata с DeviceKey; [проверки и реальные попытки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).
Две новые попытки с языком 1 остановились раньше Game Login: выбранное лобби
ответило 10036. Последующий native-разбор mapper лобби установил ключ IsInspect:
таблица клиента расшифровывает его как технические работы. Влияние языка на
Game Login пока не проверено.
Добавлены свежая страна SDK / NID и явная частичная metadata из шести полей.
Обе ветви проверены через тот же JP и также получили 10036 до Game Login;
полная metadata официального клиента ещё не собрана. Runtime различает
IsInspect и прежний игровой InvalidState, выводит понятные причины отказа.

У launcher-ветви подтверждены отдельный credential и два HTTP-вызова;
условие выбора проверено локально. Установлены заголовок launcherToken и
различие ответов. Выбор backend по каналу и GetLauncherToken с существующим
NID credential проверены локально. Явный runtime launcher flow проверен на
сервере до отказа Game Login. [Реальные результаты и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

[Сводка по темам](../resource-tools/vampir/knowledge/TOPICS.md) отделяет рабочее,
проверенное локально, статические связи и незавершённое. Актуальные вопросы:
[questions.json](../resource-tools/vampir/knowledge/questions.json).

## Существующая карта и игровые справочники

Сохранённые страницы находятся в `F:/PhoneExit Resources/Vampir/maps/`.
При работающем локальном сервере библиотеки доступны все семь разделов:

| Раздел | Локальная страница | Для чего использовать в боте |
| --- | --- | --- |
| Карта | [Карта](http://127.0.0.1:17946/maps/atlas/index.html) | География, NPC, цели квестов и исследовательская навигационная сетка |
| Монстры | [Монстры](http://127.0.0.1:17946/maps/atlas/monsters.html) | Выбор целей и связанные сведения о NPC |
| Предметы | [Предметы](http://127.0.0.1:17946/maps/loot/items.html) | Предметы, добыча и связанные источники |
| Книги | [Книги](http://127.0.0.1:17946/maps/loot/books.html) | Книги навыков и способы получения |
| Навыки | [Навыки](http://127.0.0.1:17946/maps/atlas/skills.html) | Параметры навыков и связанные данные |
| Коллекции | [Коллекции](http://127.0.0.1:17946/maps/collections/index.html) | Состав коллекций и связи с предметами |
| Характеристики | [Характеристики](http://127.0.0.1:17946/maps/attributes/index.html) | Определения характеристик и связанные эффекты |

Это уже извлечённые данные и существующий интерфейс: использовать их при развитии
2D-оболочки. Ссылки зависят от локального сервера; происхождение, ограничения и
команда его запуска — в [описании атласа](../resource-tools/vampir/knowledge/evidence/maps/MAP-ATLAS.md).
Структура справочников — в [описании каталогов](../resource-tools/vampir/knowledge/evidence/game-data/CATALOG-STRUCTURE.md).

Сетка пока исследовательская: перед построением пути проверить актуальность
ресурсов, активный мир, высоту, проходимость и переходы. Статические точки NPC и
целей квестов не показывают текущее состояние персонажа или существ в мире.
Для живого слоя нужны серверные позиция, сущности и прогресс заданий.
Связи заданий, действий, обучения и интерфейса уже собраны в
[графе квестов](../resource-tools/vampir/knowledge/evidence/scenarios/QUEST-DEPENDENCIES.md).
Порядок подключения — в [плане карты и сценариев](../vampir-headless/TASKS.md#карта-справочники-и-квестовый-сценарий).

## Найти накопленные результаты

| Тема | Текущее знание и границы |
| --- | --- |
| Вход, SDK, устройство, metadata | [Авторизация](../resource-tools/vampir/knowledge/topics/auth.md) |
| Кадры, сокеты, лобби, игровой Login | [Сеть](../resource-tools/vampir/knowledge/topics/network.md) |
| Список, выбор, создание, вход в мир | [Персонажи](../resource-tools/vampir/knowledge/topics/characters.md) |
| Атлас, геометрия, сетка и маршруты | [Карта](../resource-tools/vampir/knowledge/topics/maps.md) |
| Окна, контролы, масштаб, будущая оболочка | [Интерфейс](../resource-tools/vampir/knowledge/topics/interface.md) |
| Квесты, обучение, покупки и фарм | [Сценарии](../resource-tools/vampir/knowledge/topics/scenarios.md) |
| NPC, предметы, навыки и каталоги | [Игровые данные](../resource-tools/vampir/knowledge/topics/game-data.md) |
| Версии, SHA, переизвлечение и регрессии | [Обновления](../resource-tools/vampir/knowledge/topics/updates.md) |
| Ghidra, CUE4Parse, Dumper-7 | [Инструменты](../resource-tools/vampir/knowledge/topics/tools.md) |

До нового исследования: [правила базы знаний](../resource-tools/vampir/knowledge/README.md),
затем поиск адреса/имени через `function-registry.py --query`.
[FUNCTION-INDEX.md](FUNCTION-INDEX.md) ведёт к реестру функций и доказательств.
Не повторять разобранную ветвь без нового входа или явно записанного unknown.
[План единого поиска](../resource-tools/vampir/knowledge/INDEX-PLAN.md): объединить
имеющиеся выгрузки по SHA клиента, затем добавить поиск / очередь недостающего
анализа. Учтён обычный выпуск обновлений по средам рано утром; новый baseline
принимается после загрузки и сверки SHA.
[Первый этап индекса](../resource-tools/vampir/knowledge/INDEX-USAGE.md) реализован:
Более 230 отчётов и 600 функций двух версий, поиск текста и прямых вызовов без запуска
Ghidra. Вопросы, доказанные роли и ресурсы пока остаются в отдельных справочниках.
Перед новым экспортом обязательно проверить этот индекс по текущему SHA:
`function` / `search --release installed`, при необходимости `callers`.
Если база отсутствует или появились новые выгрузки, сначала выполнить `build`.
[Автоматизация исследования](../resource-tools/vampir/knowledge/RESEARCH-WORKFLOW.md):
`prepare` объединяет вопрос / SHA / материалы / выбранные проверки; `collect`
выгружает недостающие явные адреса; `finish` сохраняет вывод по версии.
`check` проверяет согласованность перед коммитом; `update` объединяет полный
аудит файлов, resource adapters и очередь перепроверки связей.
Автоматического продвижения runtime profile и фонового расписания нет.

## Код и данные

- `vampir/`: существующий экранный бот Android, его настройки и templates.
  [bot.py](bot.py), [entry.py](entry.py), [quests.py](quests.py), [shop.py](shop.py).
- [vampir-headless](../vampir-headless/README.md): диагностические runners и
  самостоятельный клиент; [TASKS.md](../vampir-headless/TASKS.md) — порядок работ.
- `vampir-shared/vampir_core/`: общие bounded codecs, состояния и соединение.
- [resource-tools/vampir](../resource-tools/vampir/README.md): исследование,
  сборка каталогов и карты; инструменты не включать в приложение бота.
- `F:/PhoneExit Resources/Vampir/`: большие отчёты, extracted assets, карта,
  snapshots и exports. [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md).

Клиент исследования: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
SHA установленного EXE: `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Прежние native-результаты относятся к сохранённому EXE
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`;
перенос связей на новую сборку ещё не проверен.
Это собранный код и cooked-данные клиента; исходного C++ проекта нет.
Совпадение версии Windows и Android автоматически не предполагается.

## История

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) сохраняет прежний README целиком:
старые результаты, команды и границы. Он не является текущим состоянием.
Подробные исследования физически разнесены по `knowledge/evidence/<тема>/`;
карта старых и новых путей —
[document-locations.json](../resource-tools/vampir/knowledge/document-locations.json).
Не добавлять новые хронологические отчёты в этот README: обновлять тему,
вопрос и соответствующее доказательство.
