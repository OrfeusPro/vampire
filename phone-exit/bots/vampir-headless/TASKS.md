# Самостоятельный Vampir — актуальный порядок работ

Новый приоритет пользователя: живой вход и создание персонажа через HK.
Netmarble/SDK launcher sign-in прошёл; игровой профиль остановился на проверке
источника, до Game Login и списка. [Проверка и следующий шаг](LIVE-HK-CHECK.md).
Завершить профиль текущей сборки; затем список и Carnage только при пустом списке.

Внешний reader ответа ID 102 прошёл 24 полных случая пустого списка,
38 коротких вводов и 7 отказов. Ненулевой счётчик требует отдельного чтения
записей персонажей. Далее — CharacterRecord, вложенные структуры, целый список
и обработчик ответа; профиль не активирован.
[Доказательства и следующий участок](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-LIST-ENVELOPE-11316.md).

Current WaitingEndNotify ID 27 → request ID 101 проверен в 24 native сценариях:
handler, policy gates, request/quick-select и packet constructors. Следом —
reader/handler ответа списка; сеть и dispatch ещё не проверены.
[Путь и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-WAITING-END-11316.md).

Current VersionResult reader проверен на native input archive: 32 полных случая,
17 коротких тел и 5 отказов операций. Следом — current handler/переход к Login;
игровой профиль ещё не активирован. [Проверка и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-RESULT-11316.md).

Регистрация ID 2 и current handler/gate проверены в 14 сценариях: только result 0
доходит до captured Login prepare. Далее — объединение с reader и зависимости
профиля. [Связи и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-RESULT-HANDLER-11316.md).

Current final virtual +28 после LoginResult подтверждён как reset: constructor/
getter/final table и 8 native сценариев перенесены. Инициатор списка теперь
подтверждён отдельно в WaitingEndNotify, см. выше. [Связи и границы reset](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-CONTINUATION-11316.md).

Post-state wrapper/tail callee прошли 44 native сценария; отказ Ghidra устранён
явной моделью E9 без расширения unwind. В общей цепочке это пока capture.
[Доказательства и следующие связи](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-POST-STATE-11316.md).

Reader → handler LoginResult теперь работают на одном packet без host перезаписи:
44 общих сценария, включая Unicode и string boundaries; 131 отказ чтения не
вызывает handler. Далее — реальные сервисы и post-state. [Проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-BODY-HANDLER-11316.md).

Текущие LoginResult handler/gate прошли 38 native сценариев на synthetic packet:
state stores, ошибки, signed gates, controller и SDK conditions. Далее — body
интеграция и post-state с отклонённым unwind export. [Границы и доказательства](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-HANDLER-11316.md).

Текущая регистрация ID 4 связана с handler `14679aec0`; проверены таблицы,
аргументы и exports. Далее — native gate/handler branches; статическая связь
не доказывает сессию. [Доказательства и следующий участок](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-REGISTRATION-11316.md).

Сохранённые направления пользователя: **1, 5, 8, 9**; HK-проверка разрешена выше.
[Актуальный offline checklist](OFFLINE-PLAN.md). Ниже сохранены результаты прежних
этапов; старые «дальше» не заменяют текущий план.

Входной буфер LoginResult теперь создают native concrete/base constructors:
72 проверки полей / ABI и общая цепочка чтения прошли без ручной записи cursor.
Далее — handler/dispatch; storage primitives остаются fixtures.
[Результат и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-BUFFER-11316.md).

Native FString/std::string/UTF-8 теперь включены в целый LoginResult с числовым
archive. 160 различных полных случаев, 4 границы размеров, 332 коротких тела,
25 отказов и 6 специальных строк проверены. Далее — input construction / handler.
[Storage boundaries и готовые exports](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-STRING-11316.md).

Input archive/scalar/raw методы теперь native внутри LoginResult; 320 полных
случаев, 332 коротких ввода и 25 отказов прошли. Далее — actual FString/UTF-8,
concrete buffer constructor и current handler/dispatch. Runtime guard сохранён.
[Проверка и готовые exports](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-INPUT-11316.md).

Текущие LoginResult/nested readers прошли 320 полных случаев, 332 коротких
префикса и 25 отказов; Python decoder совпал с полями native caller.
Далее — actual input archive/UTF-8 и handler/dispatch; код 0 не означает сессию.
[Готовые exports и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-11316.md).

Metadata теперь исполняется внутри целого Login с общими manager / allocator:
448 сценариев проверили поле `+d8`, SDK gates и cleanup. Далее — реальные SDK /
string/map/variant boundaries, интеграция writer/archive и текущий result reader.
[Проверка на общей памяти и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-METADATA-11316.md).

Metadata collector/selector/loader/UserInfo copy/move/writer исполнены на общей
памяти: 288 случаев, 33 field mappings, optional branches и refcount cleanup.
Далее — реальные источники UserInfo / primitives и интеграция в whole Login.
[Готовые exports и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-METADATA-11316.md).

В Login включены native SDK mode/main/value и шесть leaf getters: 2 016 случаев
с cache warm/resolve/absent. Metadata collector экспортирован, 27 связей ключей
проверены статически. Далее — его consumer и реальные источники значений.
[Прогон, ограничения и готовые материалы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-SDK-11316.md).

Целые Login prepare / constructor проверены в 672 сценариях с явными fixtures.
Далее — реальные SDK/string/platform/language/number зависимости, интеграция
writer/archive и текущий result reader. Готовый export повторно не получать.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-11316.md).

Native NM provider / getter прошли 36 сценариев, интеграция с Version prepare —
64. Семь нужных callees уже экспортированы; дальше platform/context, Windows /
CPU helpers, затем Login prepare и result readers.
[Границы и готовые материалы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-NM-11316.md).

Version prepare / constructor исполнены целиком в 64 сценариях проекции и
cleanup. Дальше — actual OS/context/string getters, отдельный Login prepare
и текущие result readers. Эти prepare exports уже есть, повторять collect не нужно.
[Границы caller fixtures](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-11316.md).

Version / Login writers проверены на порядок полей и отказы: 160 случаев.
Native UTF-8 helpers прошли ещё 222 сценария, полный string writer — 228.
Native archive прошёл 45 случаев и 64 полных тела Version / Login.
Дальше — preparation и result readers. Готовые packet / string / UTF-8 /
archive exports повторно не выгружать.
[Адреса, границы и следующая проверка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-ARCHIVE-WIRE-11316.md).

Возобновляемая сверка пары сборок проверена; готов только offline launcher.
Дальше — полный Version / Login writer / result, затем список / выбор персонажа
и вход в мир. Constructors / tag slices уже проверены, их exports не повторять.
[Очередь и границы текущих доказательств](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RESUMABLE-UPDATE-11316.md).

Контроллер обновления поддерживает `--plan-only`, `--resume` и `update-status`.
Профиль готовится отдельно, активации и продвижения baseline нет.
[Возобновление, зависимости и очередь](../resource-tools/vampir/knowledge/RESUMABLE-UPDATE.md).

При переносе адресов доступен BinExport / BinDiff: сначала сравнение имеющегося
разбора, затем `binary-diff.py prepare` для единственного кандидата и отдельная
проверка его связей. Не подменять этим contract checks или живую проверку.
[Порядок и ограничения](../resource-tools/vampir/knowledge/evidence/tools/HEADLESS-BINARY-DIFF.md).

Добавление exports теперь не требует повторного импорта всей базы: на этой
библиотеке 16,991 секунды против 66 секунд полного build, неизменный повтор
6,864 секунды. Это замер индексатора, не всего переноса игры.
[План автоматизации следующего обновления](../resource-tools/vampir/knowledge/UPDATE-AUTOMATION.md).

Для продолжения Version / Login уже сохранён batch export пяти roots:
`F:/PhoneExit Resources/Vampir/ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-7c5a462e9d0c/details.json`,
SHA `c94200451d70a9eb459767aa9076b5f98a90325605c135686db082f31a290619`.
Готовые owners / constructors повторно не выгружать; их полная семантика ещё не подтверждена.

Compiled tag 1.13.16 проверен через новый pointer и четыре native сценария:
строка совпала с 1.13.14, адреса изменились. Полный Version / Login consumer
ещё требует сверки; игровой runtime profile пока не переключён.
[Источник, fixtures и следующая проверка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-COMPILED-TAG-11316.md).

Update теперь вызывает явно отмеченные offline checks с кэшем зависимостей;
ошибки и проверки без поддержки текущего SHA остаются в очереди. При сверке
SDK пересоздан зависимый NID report и заново закреплён manifest профиля.
[Как фиксируются обновления и что ещё осталось](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-CHECK-DISPATCH.md).

SDK profile 1.13.16 подключён для явного launcher flow: шесть новых offline
проверок проходят, installed SHA / account / route / freshness guards сохранены.
Direct SDK операции и игровой протокол новой сборки ещё требуют переноса;
живой вход пока не подтверждён, серверы недоступны по сообщению пользователя.
[Профиль, проверки и следующий этап](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-RUNTIME-11316.md).

Актуальная установленная версия после обновления 23 октября — **1.13.16**,
patch revision **262487**, EXE SHA `d00a197796b7…`. Полная сверка 165 архивов
выявила два изменённых; доступные ресурсы обработаны. Совместимость runtime
с новой сборкой ещё не подтверждена. Прежние успешные сессии и исследования
ниже относятся к предыдущей сборке.
[Результат обновления и очередь перепроверки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-UPDATE-11316.md).
23 октября пользователь сообщил о временной недоступности серверов в штатной
игре. Это наблюдение пользователя, отдельный вход ботом не повторялся; точная
причина и связь с прежним IsInspect остаются непроверенными.
Автоматический поиск по точным ориентирам нашёл два launcher candidates новой
сборки; сверка SDK/GMC2 и перенос остальных auth checks ещё нужны.
[Что искать при следующем обновлении](../resource-tools/vampir/knowledge/UPDATE-TARGETS.md).
Получены полные экспорты двух новых launcher-функций; повтор collect использует
готовые материалы без JVM. Живой вход новой сборки ещё не подтверждён.
[Явный экспорт нового SHA и проверки](../resource-tools/vampir/knowledge/evidence/tools/HEADLESS-REQUESTED-GHIDRA.md).
Статический launcher request/response audit перенесён на новый SHA: 16 функций,
10 ключей, суффиксы, thunks и локальные ветвления. Живой вход этим не подтверждён.
[Launcher-контракт 1.13.16](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-CONTRACT-11316.md).
Новый GMC2 Start проверен на 512 native случаях до границы копирования базы.
URL и начальные значения отдельно проверены ниже; полный SDK profile ещё требует переноса.
[Выбор базы и fixtures](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-GMC2-START-11316.md).
Четыре базы GMC2, service/group и SDK 5.2.11 подтверждены новым native replay.
Начальные zone 1 / пустой market ещё требуют сверки game override.
[Конструкторы и начальные значения 1.13.16](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-DEFAULTS-11316.md).
Статически найдена текущая ветка game overrides: семь функций, строки market /
client ID и путь NMENV. Источники и границы статической проверки:
[Связи настроек SDK 1.13.16](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-OVERRIDE-LINKS-11316.md).
Ветка исполнена в 106 native сценариях: real даёт zone 2, NMENV и SDK handles
управляют market. GMC2 URL / headers и полный профиль ещё требуют переноса.
[Результаты выполнения и fixtures](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-OVERRIDE-NATIVE-11316.md).
Найдены текущие Refresh / Request GMC2 и статически сверены 889 инструкций.
Их точные signatures подключены к автоматическому поиску после изменения EXE.
[Участки URL / headers и границы сверки](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-GMC2-REQUEST-LAYOUT-11316.md).
GMC2 URL slice с настоящими getters / initializers / append прошёл 27 native
сценариев. Заголовки и полный профиль пока не перенесены.
[Выполнение URL и автоматические проверки](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-GMC2-URL-NATIVE-11316.md).
GMC2 headers slice прошёл 73 native случая с synthetic HTTP captures.
Platform и полный SDK profile ещё требуют проверки.
[Поля headers, gates и fixtures](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-GMC2-HEADERS-NATIVE-11316.md).
Текущий PC initializer / getter прошёл 12 native случаев. Исправлен export
switch: case blocks входят в проверяемые инструкции, прежний неполный материал
сохранён. Полный SDK profile пока не собран.
[Платформа и контроль полноты](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-PLATFORM-11316.md).
Собран отдельный SDK profile-кандидат из шести native reports / 739 случаев.
Он пока не включён в runtime: NID caller inputs и auth guards ещё требуют сверки.
[Состав профиля, проверки и следующий этап](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-PROFILE-11316.md).
FDeviceInfo::GetPlatform проверен в 52 native случаях: default PC и выбор
console slot при initialized TLS. NID parent / context builder ещё не подтверждён.
[Caller платформы и fixture limits](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-WEB-PLATFORM-11316.md).
Текущий NID CheckPossibleToOpen найден через explicit caller export. Десять
базовых context pairs прошли 32 native случая; extensions / gates ещё открыты.
[Связи NID inputs и сохранение unknown](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-CONTEXT-11316.md).
Дополнительные параметры NID проверены в 256 native сценариях: authType,
выбор аргумента webViewType и условный credential. Converter и ранние gates
ещё требуют разбора; сеть и авторизация не запускались.
[Результат, fixtures и проверяемые cleanup tails](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-EXTENSIONS-11316.md).
Реальный converter webViewType проверен на всех byte: 1024 случая отдельно
и 448 вместе с NID caller. 30 → steam, 31 → epic, 34 → xbox, иначе sdk.
Результаты ранних gates и account additions приведены ниже.
[Преобразование, источники и автоматизация](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-CONVERTER-11316.md).
Ранние условия NID прошли 112 native случаев; приоритет NID token и fallback
полей аккаунта — 512. Реальные getters и error callbacks не исполнены.
Далее query encoding / browser delivery и auth source guards новой сборки.
[Условия, поля аккаунта и границы проверки](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-GATES-11316.md).
Текущий ASCII query encoder прошёл 396 native случаев с реальными whitelist /
hex leaves; сборка URL и передача в owner fields — 48 случаев с fixtures.
Открытие браузера и целая авторизация этим не подтверждены.
[Кодирование, URL assembly и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-QUERY-11316.md).
Найдены текущие OnDeepLink / OnResult: статически сверены 1384 инструкции,
route, mode mask и семь key bindings. Поиск включён в планы updater;
валидация результата ещё требует native replay текущей сборки.
[Обработчики результата и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-RESULT-SOURCE-11316.md).
Текущий OnResult и FString copy прошли 1100 native случаев: missing / empty,
mode gates и раздельная передача токенов. Parser / channel / settings ещё fixtures;
следом реальные helpers и auth source guards, затем живая проверка.
[Проверки результата и передача токенов](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-RESULT-NATIVE-11316.md).
Реальные numeric / channel helpers прошли 112 / 176 случаев и 1124 совместных
OnResult сценария. Return fixtures убраны в новой проверке; DLL / locale CRT
учтены в кэше. Далее runtime guards / browser boundary и подключение профиля.
[Helpers, текущие источники и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-PRIMITIVES-11316.md).
GMC2 geo path и SetCountryCode прошли 672 native случая. Policy 1.13.16
учитывает A1 / a1 и отвергает смешивание geo разных SHA. Browser smoke прошёл;
загрузчик SDK profile ещё требует переноса, установленный SHA guard сохранён.
[Geo policy, проверки и оставшееся ограничение](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-GMC2-GEO-11316.md).

Статус на 23 октября 2026. Цель продукта сохраняется полностью: клиент без
игры, 2D-карта с игровыми меню, фарм, обновления данных и Android.

Уточнение: Global / EU / Prelude 2. На основном тестовом аккаунте уже есть
персонаж: панель получила Login 0 и одну запись, назначение по ключу сохранено.
Первая проверка входа в мир остановилась на NID. Следующий запуск получил
серверную позицию; статус «В мире» проверен на одном EU-аккаунте.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-EU-ACCOUNT-CONSOLE.md).
Прежний HK-профиль исключён из EU-проверок. Для новой EU-почты подтверждён
автоматический launcher-вход после создания персонажа пользователем:
Game Login 0 и одна запись Prox на Prelude 2. Назначение по серверному ключу
сохранено. После отдельного NID Login Failed / HTTP 400 следующий запуск
получил позицию Prox. Затем XI подключён параллельно: оба active в семи снимках
за 30 секунд, оба worker штатно остановлены. Прежний SDK 1203 не повторился
в успешном чтении, но причинная связь с созданием персонажа не установлена.
Ранее игровой SDK возвращал HTTP 400 / код 1203. Пользователь
подтвердил существующий игровой аккаунт и ручной вход в лаунчер. Создание
SDK-профиля из панели удалено; продолжать только авторизацию, затем список
персонажей. Создание персонажа допустимо лишь при принятом пустом списке.
Контроль 23 октября: основной аккаунт успешно загрузил EU-серверы через launcher,
но следующий отдельный вход для списка персонажей получил NID Login Failed /
HTTP 400 до SDK. Отказ не специфичен новой почте; гипотеза об отсутствии
игрового профиля по нему отвергнута. Нужно изолировать причину повторного входа.
Следующий контроль прошёл одной операцией «Войти и прочитать персонажей»:
NID / SDK → каталог EU → Prelude 2 → Game Login 0 → свежий список с XI.
Каталог и список сохранены, входа в мир не было. Предварительная отдельная
загрузка серверов для выбранного сервера не нужна. Причина прежних
NID-отказов остаётся открытой и после успешного списка нового аккаунта.
Ручной вход нового EU-аккаунта в нашем WebView 23 октября подтвердил NID,
после чего обычный SDK SignIn дал HTTP 400 / 1203. До игрового Login не дошло.
Последующая успешная авторизация нового аккаунта через launcher описана выше.
SignUp не запускать и не выводить отсутствие регистрации из кода 1203.
[Панель и проверенные границы](ACCOUNT-CONSOLE.md).
Параметры создания задаются в аккаунте: класс выбирается явно, по умолчанию
Carnage; случайный ник сохраняется и меняется только после подтверждённого
отказа «ник занят», максимум пять вариантов. Если на выбранном сервере уже
есть персонаж, новый не создаётся даже без назначения слота в панели.
Локальный план и форма проверены; wire создания, внешний вид и серверная
привязка отказа занятого ника ещё не подключены.
Прямой NID / SDK / лобби вход проверен. Добавлен выбор регионального лобби;
пользователь подтвердил EU. Свежий каталог дал Prelude 2 / ID 384 / group 358.
На прежнем HK-профиле были Game Version 0 и Login 59 / BlockedInfo до списка.
Следом — подключить подтверждённые состояния двух сессий к карте и продолжить
обработку игровых событий; создавать ещё одного персонажа на этом аккаунте не нужно;
причину старого ограничения не считать доказанной причиной поведения других аккаунтов.
Параллельно разобрана подготовка создания первого персонажа: игровые ID 103 /
104, CreateData writer / reader и producer найдены. Пустой ID 102 и отказ Login
разделены current native replay; отправка создания пока не подключена.
Constructor / getter источника класса прошли 144 native случая; допустимая строка
класса и appearance JSON ещё не проверены.
[Источник класса и fixtures](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CLASS-SOURCE.md).
Целый reader ID 103 с constructor, CreateData и appearance прошёл 36 тел и
1398 коротких префиксов. Проверены Unicode, непустой массив и границы памяти.
Writer затем прошёл 42 тела и 24 отказа raw output fixture; переносимый encoder
совпал с native байтами. Далее — допустимые игровые значения и ответ ID 104.
[Формат чтения и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-REQUEST-READER.md).
[Запись и переносимый encoder](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-REQUEST-WRITER.md).
Установлена цепочка `Class_` tag → byte type → lookup → row ID `+8` →
`RdPlayerStateCharacterCreate +0x360`. Lookup прошёл 45 native случаев.
Затем подтверждены ClassInfo singleton / Type loader / Gunner converter и
строка свежего PAK: Carnage Id 3 / Type 3 / DefaultGender 1. Проверка данных
и lookup прошла 54 случая. Далее — producer внешности / JSON и ID 104.
[Выбор класса](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CLASS-LOOKUP.md).
[Текущая строка Carnage](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CURRENT-CLASSES.md).
Constructor / reader ID 104 прошли 16 тел и 729 усечений; все поля записи
совпали с переносимым decoder. Handler и коды отказа остаются отдельно;
параметры внешности / JSON и реальное создание пока не подключены.
[Чтение результата создания](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-RESULT-READER.md).
Внешний appearance helper прошёл 12 native сценариев до captures JSON:
занятые строки, float / режим и обязательный VoiceType. Constructor подтверждает
начальный VoiceType 0. Далее — реальный источник параметров, конвертация ключей,
JSON engine output, whole producer и handler ID 104.
[Внешность и границы JSON](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-INPUTS.md).
Entry helper затем прошёл 24 случая: missing definition пропускается, JSON key
получается из definition ID, float → double сохраняет signed zero. Lookup /
converter / JSON — captures. Следом текущие BoneGroup F / M assets и definitions.
[Ключи внешности и ресурсы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-ENTRY.md).
Текущие BoneGroup F / M затем разобраны целиком по EXE-схеме: семь групп,
ID 1–7, списки костей. Следом пары `.uasset` / `.uexp` подтверждены по точным
именам в полном каталоге текущего PAK; SHA1 обоих индексов совпали.
Диапазонов / начальных float в этой таблице нет; искать их источник и заполнение owner map.
[Извлечение и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-BONEGROUP-RESOURCES.md).
[Именованные пары и проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-BONEGROUP-DIRECTORY.md).
Сброс owner перед preview прошёл 24 native случая: десять байт внешности,
VoiceType, FString и map очищаются; пол сохраняется. Проверены buckets 0 / 1,
освобождение storage — fixture. Далее проверить `14642f090` после preview
и последующие записи map, затем выбранный preset и диапазоны float.
[Сброс и статическая последовательность](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-RESET.md).
`14642f090` обновляет preview, затем найдено применение preset / сохранённой map
через ползунки. Их обработчик и helper записи прошли 44 native случая:
value / scale как float32 пишется в запись перед JSON / preview. Map lookup /
insert остаётся fixture. Далее проверить `1464368f0`, predicate `1464479f0`,
текущий preset и реальные scale / min / max ползунков.
[Preset → ползунок → запись float](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-SLIDER.md).
Map lookup / insert / update затем прошли 26 native сценариев при заранее
выделенной памяти: коллизии, обновление без дубликатов и reuse свободных слотов
с occupation bits через границу 31 / 32. Predicate preset прошёл 64 случая;
он сравнивает row type с типом выбранного класса. Далее текущие строки
DT_CustomizePreset F/M, ссылки и значения выбранного пресета, scale / min / max.
[Map и predicate: fixtures и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-MAP.md).
Обе текущие таблицы затем разобраны целиком: 16 / 13 строк. Уникальный type 3
ссылается на DA_PresetDarkMage3_F/M, IDs 3 / 2. Assets извлечены по ссылкам,
схемы сверены с EXE. Native constructor задаёт float defaults 0.5 и voice 0;
пропущенные int32 не инициализирует. Далее проверить CDO defaults для них,
byte пола → F/M и реальные scale / min / max. Четыре теста прошли.
[Текущие пресеты и неизвестные поля](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CURRENT-PRESETS.md).
Преобразование пола затем проверено в 1024 native случаях: Male 0 → M,
Female 1 → F. DefaultGender 1 у Carnage соответствует F / preset ID 3.
Строковая операция сохраняет первую букву, а не удаляет её, как было ошибочно
описано раньше. Sentinel Max 2 также даёт M, поэтому результат helper не
является валидацией пола. CDO int32 defaults и настройки ползунков ещё открыты.
[Проверка пути и границы fixtures](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-GENDER-PATHS.md).
Настоящий экран CharacterCustomizeUI связан через getter `146404090` и
условный wrapper `14640a3f0` с constructor `1464166f0`. Шесть native случаев
подтвердили default scale 1000 и пустой owner; поздние overrides и min/max
ещё не проверены. CDO creation найден в `1416a4780`; далее его allocation
`1417e6110`, initializer `1417ca780` и завершение `1417cbe90` для omitted int32.
[Масштаб, исключённые кандидаты и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-CUSTOMIZE-SCALE.md).
Разобраны allocator / initializer / completion и postconstruct. Новая allocation
обнуляется в найденной статической ветке; DataAsset регистрируется с размером 0x30.
Целый InitProperties прошёл 36 native сценариев: property end ограничен source
class size, поля пресета от +0x30 не копируются из родителя размером 0x30.
Полный preset CDO и загрузка asset не исполнены; omitted int32 пока unresolved.
Следующий шаг — проверить завершение именно этого CDO и применение defaults
при загрузке asset, затем разрешать отсутствующие поля extractor.
[Воспроизведение и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-DEFAULT-COPY.md).
Следом исполнены initializer, context push, constructor пресета и оба base
constructors: 24 сценария, int32 сохранены, float 0.5 и voice 0. Шесть целых
postconstruct сценариев без config / subobjects изменили только object flags.
Текущие UClass callback slots и preset slots +0x58 / +0x60 пустые.
Далее — wrapper завершения с выбором immediate / deferred и перенос defaults
при загрузке asset. Config helper не считать целиком служебным: его config-ветка
может менять свойства, здесь покрыт ранний возврат при отсутствии class flag 0x4.
[Native цепочка и fixtures](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-INITIALIZER.md).
Completion wrapper и selector прошли 24 native сценария: 18 immediate / 6 deferred.
При deferred объект сохраняется, native wrapper помечает копию initializer,
полученную от queue fixture; последующее выполнение очереди не проверено.
Оба текущих asset ссылаются на native CDO через template -2; class -1 и super 0
теперь проверяются extractor. Подмены class / template / super отклоняются.
Далее — перенос defaults и десериализация при загрузке именно этого asset;
повторять проверенные constructors и механическое ветвление completion не нужно.
[Сценарии, шаблон и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-COMPLETION.md).
Обычный constructor найден в `1417e6cb0`, initializer в нём встроен; `1417d6b00`
уточнён как archetype selector. Вся цепочка ordinary construction прошла 18 native
сценариев с пустым / полным / частичным списком копируемых полей.
В extractor добавлена отдельная проекция defaults с `model_only=true` и
`verified_loaded_asset=false`; исходные omitted int32 остаются unresolved.
Следом — целый producer `146449dc0`, JSON и handler ID 104 с явным модельным
кандидатом внешности. Фактическая десериализация / late overrides остаются unknown;
не нужно повторять обычный constructor ради совпадения с загруженным экраном.
[Проверки и границы модели](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRESET-OBJECT.md).
Целый producer `146449dc0`, constructors пакета и writer прошли 37 сценариев:
24 остановки и 13 перехватов перед отправкой. Sentinel останавливает до PlayerState,
отсутствующий PlayerState — до JSON. Пустой ник producer не проверяет.
Порядок scalar bytes установлен по helper exports и подтверждён native чтением;
модельный Carnage/F дал `[1, 8, 16, 9, 2, 2, 2, 9, 0, 0]`. Тело совпало с encoder.
JSON пока fixture. Следом — actual key conversion / значения JSON и целый
handler ID 104 `146796690`, затем подключение создания при принятом пустом списке.
Новая живая отправка и создание персонажа этим изменением не выполнялись.
[Producer и воспроизводимые сценарии](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-PRODUCER.md).
Цепочка numeric keys / values прошла 36 native сценариев: outer / entry,
AsNumber, formatter, integer digits, parts join и ToString. IDs 1–7 дают Latin
ключи при явных Latin rules; Arabic rules дают другие цифры. Live culture не читалась.
Portable `encode_character_appearance` требует SHA и `key_profile='latin'`,
округляет float32, сохраняет signed zero и отклоняет неизвестные / nonfinite inputs.
JSON сравнивается семантически с setter captures; native serializer bytes не проверены.
Далее — целый handler ID 104, затем кандидат Carnage и живое создание при пустом списке.
[Числовые ключи и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md).
Целый handler `146796690` прошёл 128 success / 30 error сценариев. Code 0
передаёт record manager независимо от name-match callback; key пишется при
наличии selection state. Error снимает wait при valid UI. В synthetic invalid-UI
ветках найден null write; это не утверждение о live crash, runtime её не повторяет.
Portable outcome возвращает created / rejected / needs_refresh, без retry;
code 0 без identity требует списка, nonzero не сохраняет identity error-record.
Далее — интеграция одной отправки Create после принятого пустого списка,
decode ID 104, сохранение серверного ключа и refresh после неоднозначного разрыва.
[Handler, fixtures и решение runtime](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-RESULT-HANDLER.md).
Opt-in creation_payload подключён к exchange / GameConnection: accepted Login
и accepted empty list, один frame ID 103 с общими key/sequence; ID 104 только
после full send. Unknown при timeout/EOF, без повторов; existing character не создаётся.
Шесть локальных lifecycle/socket тестов и 40 exchange / 9 connection / 12 selection
regression прошли. Это synthetic local exchange, не живая игровая проверка.
Следом — explicit worker operation, persistent pending/unknown до отправки,
сохранение server key/name и чтение списка перед новым решением после разрыва.
UI / worker пока не отправляют Create, остальные классы factory ещё не поддерживает.
[Сессия и следующий этап](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-SESSION-FLOW.md).
Explicit worker operation create и кнопка панели подключены только для Carnage.
Factory готовит payload после свежего accepted empty list; SQLite pending
фиксируется до очереди. Две конкурентные попытки сериализуются, crash даёт unknown,
следующий Create требует отдельной сверки списка. Confirmed key/name сохраняются;
slot назначается по unique key match при прежнем target и без пользовательского назначения.
Четыре journal/worker теста, семь socket flow, 40 exchange, 20 console и один table
тест прошли; JS syntax проверен. Браузерный UI и живая отправка ещё не проверены.
Далее проверить активные worker панели перед перезапуском; один пустой EU-аккаунт,
один Create, затем новый список и вход по server key. Массовое создание пока не запускать.
[Журнал и ограничения интеграции](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-WORKER-JOURNAL.md).
Живой preflight: nightraven / EU Aria 1 дважды прошёл NID, но SDK launcher
sign-in вернул HTTP 400 / 1203 до game TCP. Bot-test контроль прошёл SDK,
однако выбранное лобби не дало игрового контекста. В конце 0 активных jobs
и 0 записей creation_attempts; ID 103 не ставился в очередь. Регистрация не повторялась.
Исправлен callback creation_factory через run / _run / _after_lobby; два wrapper
теста проверили обе границы, внешний worker mock раньше их не покрывал.
Далее проверить account-specific auth различия по существующим источникам,
без массовых повторов и SignUp fallback; создание остаётся непроверенным live.
[Наблюдения и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-CREATE-LIVE-PREFLIGHT.md).
На текущем SHA статически сверены launcher/token `1444ef840`, launcher/sign-in
`144504980`, три initializers и ответы `1444cd020` / `1444d45a0`. Аудит проверяет
SHA и инструкции; три теста прошли без входа. Прямого SignUp в этих handler нет,
причина 1203 неизвестна. Далее `1444e7630` и фактический consumer SDK error;
семь готовых экспортов использовать повторно. Не запускать массовые входы.
[Контракт текущей сборки](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-LAUNCHER-CONTRACT.md).
Следом найдены текущие dispatcher `1444e7630`, игровой caller `14561b6a0`
и callback `145605100`. Целый callback и три getter leaves прошли 67 сценариев;
logging/UI/manager actions — captures. Причина SDK 1203 не декодирована,
synthetic raw fields не считать живым ответом. Далее caller roots `145603ab0`
и `145605440`: выбрать реальную operation/channel/step до первого входа.
Два теста и workflow checks прошли; авторизация не запускалась.
[Результат SDK → игровой callback](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GAME-SIGN-IN-RESULT.md).
Найден Fetch первого подключения: `14560b250` → channel 33 → `1444e9270`.
Целый `145603ab0` прошёл 27 сценариев: успех вызывает SignIn 33 / step 15;
только error 30050027 / context 1203 ведёт в TermsOfService и BasicTerms Show.
В runtime этого этапа нет. Два теста и три workflow checks прошли offline.
Далее backend `1444e8890` / `1444e9b00` и terms continuation `14561ace0`;
не добавлять SignUp fallback на обычный launcher 1203, NID-регистрацию не повторять.
[Первый игровой Fetch](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-FIRST-GAME-FETCH.md).
Fetch contract подтверждён статически: `v1/fetch-player`, credential + scope=channel.
Добавлен явный `--fetch-player` без SignIn/SignUp/terms; четыре новых и 20
auth regression tests прошли. Live nightraven получил Fetch HTTP 400 / SDK 1203;
bot-test контроль остановился на NID до Fetch, без вывода о его SDK-профиле.
Следом vtable targets `14560b130` / `14560aff0` и terms implementation `1445ac980`.
[Read-only Fetch и продолжение условий](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-FETCH-CONTRACT.md).
Terms callback → два native virtual bridge → closures → classifier проверены
в 99 сценариях; статический handoff доведён до `144506cf0` SDK SignUp.
Raw UI state не доказывает фактическое завершение согласия; SDK профиль не создавался.
Далее `144584210`, `143d1d470`, `144522040`, callback pointer `1445744b0`:
query / HTTP / ответ BasicTerms, затем реальный первый игровой вход.
[Проверка terms continuation](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-TERMS-CONTINUATION.md).
BasicTerms HTTP wrapper — CreateGet. Callback `14456a870` передаёт resultCode -1
как raw UI state 2 с error result; это не zero result и не доказательство согласия.
Public UA / en-US / PC GET дал NO DATA / terms[]. Offline plan и bounded summary
готовы; четыре теста и шесть workflow checks прошли. Далее `144580990` и callback
pointer `1445744c0` из готового `1445a0100`: individual terms без player ID.
[BasicTerms ответ и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-BASIC-TERMS-RESPONSE.md).
Индивидуальные условия без player ID используют termsUrl GET и termsType I;
с player ID действует отдельная ветвь agreementUrl. Публичный индивидуальный
GET получил NO DATA с объектом terms вместо массива BasicTerms. Проверены
план запроса и передача результата через очередь. Затем 40 native-сценариев
замкнули обработчик ответа, настоящий конструктор ошибки и игровой callback:
итоговый код 30057209, signed context сохраняется. При NO DATA / state 2
и заданном callback игра выбирает переход SDK SignUp для Netmarble 33 / step 13;
остальные ненулевые ответы дают сообщение об ошибке. Это ещё не сетевой SignUp.
Добавлен отдельный режим первого SDK-входа: Fetch → ответы условий → SDK SignUp
при двух NO DATA → SignIn с проверкой player ID. Доступные условия останавливают
операцию; NID-регистрация не повторяется. 43 выбранных теста прошли. Следующая
живая попытка nightraven прошла NID, Fetch, условия, создание SDK-профиля и
SignIn; статус sdk_created сохранён. Проверка создания на Aria 1 затем прошла
launcher SDK, но получила выбранное лобби 10036 до списка персонажей. Запрос
создания не отправлялся. Причина нестабильных NID HTTP 400 остаётся открытой;
новая диагностика возвращает только фиксированные подсказки без текста ответа.
[Живой SDK-вход и границы отказа лобби](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-FIRST-SDK-LIVE-AND-NID-HINTS.md).
Текущий mapper подтвердил 10036 → IsInspect в native replay. После отдельного
отказа NID с признаком капчи пользователь вошёл вручную: NID и launcher SDK
приняты, но выбранное лобби снова вернуло 10036 до списка персонажей.
Это отдельный от авторизации отказ; создание не отправлялось.
[Текущий mapper и границы вывода](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-RELEASE-LOBBY-ERRORS.md).
Контроль основного аккаунта на Aria 1 и его прежнем Prelude 2 также прошёл NID /
launcher SDK и получил selected lobby 10036 до Game Login. Назначения сохранены
без изменений. Это исключает отсутствие нового персонажа как единственное
объяснение; серверную причину и общий контекст клиента ещё нужно разделить.
[Сравнение двух EU-серверов](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-EU-LOBBY-CONTROL.md).
Первый SDK-вход подключён к панели отдельной кнопкой с явными параметрами
условий. Подтверждённый профиль повторно не подготавливается; обычный вход
не переключается на регистрацию. Прошли 45 offline тестов и HTTP-контроль
отказа для подтверждённого профиля без запуска worker. Живой вход через кнопку
ещё не проверен.
[Подготовка SDK из панели](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-CONSOLE-FIRST-SDK-LOGIN.md).
[Первый SDK-вход: запуск и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-FIRST-SDK-LOGIN.md).
[Индивидуальный запрос и очередь](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-INDIVIDUAL-TERMS-DISPATCH.md).
[Обработчик ответа и игровой переход](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-INDIVIDUAL-TERMS-RESPONSE.md).
[Функции, проверки и следующий unknown](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-EMPTY-LIST-CREATION-ENTRY.md).
[Проверка прямого маршрута](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-DIRECT.md).
[Адреса и native selector](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-LOBBY-REGIONS.md).
[Живая проверка EU](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-GLOBAL-EU.md).

| Порядок | Результат, который нужен | Что есть / что остаётся |
| --- | --- | --- |
| 1. Вход | Game Login принят, затем реальный список персонажей | На JP SDK / лобби / Game Version / Game Login code 0, CharacterList code 0 / одна запись после свежего GMC2 и metadata 312 байт |
| 2. Персонаж | Получить список, выбрать, получить позицию | На JP ID 109 → ID 110 code 0, body 4724 байта полностью разобран; ID 202 → ID 203 → ID 204 code 0; ID 205 → ID 206 code 0; серверная цель входа получена и показана на карте |
| 3. Сессия | Поддержание, ответы, разрыв и восстановление с понятными состояниями | Проверены 120 секунд live после ID 206, 24 периодических Ping / 25 ID 17 без ошибок; длительная сессия и reconnect не проверены |
| 4. Карта и UI | Движущийся персонаж, цель перемещения, игровые меню | Live цель входа показана, вывод отключается, привязка / сглаживание добавлены; свои XY-цели ID 307 подключены локально, в новой живой сессии ID 307 не пришёл; живые сущности и игровые меню ещё не подключены |
| 5. Фарм | Место → путь → автобой → контроль состояния | Данные квестов / NPC / навыков есть; сетевой сценарий не выполнен |
| 6. Обновления | Автоматически определить изменения, переизвлечь данные, сверить связи; вручную разбирать только нерешённое | Есть единый update / полный аудит / resource adapters и очередь; автоматическая совместимость всех связей не подтверждена |
| 7. Нагрузка и Android | Измеренный лёгкий runtime, инструменты отдельно | Нагрузка нескольких аккаунтов и перенос самостоятельного бота ещё не проверены |

Последняя живая проверка 22 октября после замены телефонов: JP / TECNO TECNO KJ5n
прошёл Login 0, список / выбор и ID 204 → ID 205 → ID 206 code 0.
Бот получил конечную серверную целевую позицию без запуска игры. Соединение и
временный маршрут закрыты; движение, проекция на карту и длительная сессия
пока не проверены. Предыдущие отказы BlockedIp относятся к прежним выходам.

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

## Карта, справочники и квестовый сценарий

Эталон официального сценария `b70d6be4e33f6fd0086342f0f9d13d86` сохранён:
выбор персонажа, запуск квеста, пропуск заставок, движение, телепорт и остановка
сюжетного автопрохождения со слов пользователя. Структура записи проверена;
точное время кликов ещё не сопоставлено с пакетами.
[Источник, SHA и порядок разбора](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-QUEST-REFERENCE-CAPTURE.md).
Игровой flow 124 разобран: 394 пакета, без остатка кадров; ID 1801 / 1802 /
1836 отсутствуют. Официальная цепочка включает 1810 / QuestUpdate,
1815 / QuestComplete, 1803 / QuestStart и 1820 / QuestTeleport.
[Проверенная timeline и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-REFERENCE-TIMELINE.md).
Следующий путь — состояние квеста и поля ID 1810; диагностический 1801
не воспроизводит этот официальный сценарий.
Wire ID 1810 проверен: vector 3 × float32, два uint64 и byte, всего 29 байт.
Целые native writer / reader прошли 48 тел, шесть отказов записи и 29 коротких
префиксов. Codec не подключён к отправке; значения полей должен дать producer.
В десяти сохранённых запросах raw30 совпадает с ключами Quest, но семантическая
привязка ещё не доказана. [Формат, fixtures и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-WIRE.md).

Отдельная запись PktQuest / Progress проверена. Живой диагностический запрос
ID 1801 с 0 / 0 через HONOR JP вернул code 100, успешного списка нет.
Выявлена ошибка прежней модели suffix: настоящий ID 1802 содержит
PktItemChangeList, а не PktQuestData. Исправленный decoder и actual constructor
проверены на 27 телах / 131 префиксе при пустых item changes; непустые пока
явно отклоняются. Старый claim полного списка с группами отозван.
[Коррекция и сохранённый ответ](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LIST-CORRECTION.md).
Повтор по запросу пользователя через новый Xiaomi / JP снова дал code 100
после Login / списка / выбора / входа в мир с кодом 0. Исправленный decoder
разобрал ответ без ошибки; тело совпало с прежним. Новый Samsung / JP получил
отдельный Game Login 58 / BlockedIp до запроса квестов.
[Сравнение стадий и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-REFUSAL-RECHECK.md).
В словаре текущего клиента подтверждены пары 0 / Success, 58 / BlockedIp,
100 / CharacterNotSelected. Почему запрос получает «персонаж не выбран»
после принятого входа в мир, ещё не установлено; qword запроса не объявлен
Character ID. Следом — источник штатных параметров и контекст запроса.
[Инструкции пар и ограничения](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-RESULT-NAMES.md).
0 / 0 без нового основания не повторять.

Для первого серверного шага обучения добавлен явный `--ack-initial-tutorial`:
одна команда 1001 / 2 после успешного входа в мир и свежего состояния того же
соединения, с различением очереди, полной отправки, ответа и неизвестного
результата. Локальная цепочка и одна живая отправка проверены: новый Redmi
M2006C3LG / JP прошёл вход в мир, сервер ответил ID 9904 code 0 / `accepted`.
Повторный вход без ID 9903 подтвердил устойчивую запись 1001: raw0c 2,
raw10 1, state 2; 20 секунд без ошибок. Выбор квеста и движение ещё не проверены.
[Состояние после повторного входа](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-PERSISTENCE.md).
[Принятая команда и следующий этап](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-ACK-ACCEPTED.md).
Прежние HONOR и Redmi JP вернули Game Login 58 / BlockedIp до отправки команды.
Для отдельного Node-каталога подтверждено системное хранилище CA, пустой
список при ошибке TLS не означает отсутствие доступных телефонов.
[Живые сводки и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-INITIAL-TUTORIAL-ACK.md).
Новый Pixel 5 / JP восстановлен по разрешению пользователя; сигнализация
прошла, прямой канал завершился `direct_connection_failed`. Игровой вход
через него ещё не проверен. Сначала нужен готовый транспорт.
[Проверка Pixel и сохранность профиля](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-PIXEL-CHANNEL.md).
Это подтверждение шага, а не команда выбора / автопрохождения квеста.
[Условия запуска и ограничения](README.md#текущее-состояние).

Повторно использовать существующие семь разделов: карту, монстров, предметы,
книги, навыки, коллекции и характеристики. Их адреса и источники сохранены в
[главном README](../vampir/README.md#существующая-карта-и-игровые-справочники).
Атлас, навигационную сетку, геометрию интерфейса и граф квестов не извлекать
заново без изменения источника или конкретного пробела в данных.

После подтверждения входа в мир подключить серверные мир / позицию персонажа,
цель и путь к атласу. Для маршрутов сначала сверить версию сетки, высоту,
проходимость и особые переходы. Точки размещения из таблиц дополнять живыми
сущностями, их состоянием и целями боя; прогресс квеста получать из сессии.

По сообщению пользователя 22 октября официальный клиент находится в мире:
ранние задания сразу запускают перемещение, затем встречаются ролики и тексты.
Это кандидат на первый проверочный квестовый сценарий после входа бота.
Наблюдение относится к игре; бот уже получил ID 206, но квестовый сценарий ещё не выполнял.

В сценарии различать движение / прибытие, бой, взаимодействие, диалог / выбор,
обучение, ролик и загрузку. Переходы связывать с данными задания и подтверждением
сервера. Для работы без 3D определить необходимые подтверждения диалогов и
роликов; возможность пропуска каждого этапа пока не доказана. Не повторять
действия вслепую при неизвестном результате.

Целевая оболочка — игровые меню и кнопки с 2D-картой в центре. Вывод слоёв,
текстов и анимаций сделать отключаемым; обработку необходимых событий сессии
и сценария сохранять при скрытой карте. Экономию ресурсов затем измерить.

### Действия с карты, события и кнопки

Разделять тип квеста, его задачи, обучение и выбранный режим выполнения.
В прежнем графе / native enums есть Scenario, Sub, Daily, Dungeon, Bloodline,
Guide, Wanted, GuildDefense и Item. Это историческая классификация, которую
нужно сверять с текущей сборкой. Guide-квест и Tutorial не объединять:
обучение может быть отдельной задачей внутри сюжетного квеста.
[Граф и примеры](../resource-tools/vampir/knowledge/evidence/scenarios/QUEST-DEPENDENCIES.md).

По уточнению пользователя квест можно выбрать как чекбокс для автоматического
перемещения / боя. Показывать выбранное автовыполнение отдельно от завершения
квеста. Поле AutoQuest в таблице QuestTask — отдельный признак данных; оно само
по себе не доказывает включённый режим персонажа или конкретную сетевую команду.
Для обучения нужны последовательности открытия меню, выбора предмета,
экипировки, улучшения и других действий с указанными целями и проверкой результата.
Не сводить все шаги к нажатию панели или произвольной атаке.

Повторно использовать игровые окна, кнопки и размещение из сохранённого
UI-каталога после сверки версии, родителей и масштаба. Ориентиры находятся в
`F:/PhoneExit Resources/Vampir/`: `ui-catalog/index.json`, `ui-geometry/`,
`archive-image-catalog.json`, `archive-images/`, снимки прежнего бота — `phone-tests/`.
В каталоге есть WBP_TutorialGuidePopup / WBP_TutorialGuidePageT и окна Guide-квестов;
связи встроенных иллюстраций справки с конкретными страницами ещё проверить.
[Каталог и геометрия](../resource-tools/vampir/knowledge/evidence/interface/UI-CATALOG.md),
[масштаб](../resource-tools/vampir/knowledge/evidence/interface/UI-SCALE.md).

Чекбокс «Следовать за персонажем» удерживает его в центре карты и выбирает
его мир, сохраняя выбранный масштаб. При отключении слежения карта остаётся
в текущем положении. Сейчас он следует последнему снимку цели входа;
непрерывное слежение требует подключения событий движения.
Маркер плавно приближается к полученной координате; привязанная камера следует
той же отображаемой позиции. Это сглаживание вывода без предсказания движения.
При смене мира позиция переключается сразу, при потере сессии маркер убирается.

Карта должна управлять ботом: выбор точки, NPC, объекта или цели квеста
открывает доступные для этой цели действия. Подключать перемещение,
взаимодействие, атаку, запуск сценария и остановку по мере подтверждения
их сетевых обработчиков и условий доступности. Статическая точка из справочника
сама по себе не подтверждает наличие живой сущности или возможность действия.

Показывать происходящие в сессии события: движение и прибытие, кто кого атакует,
изменение квеста, диалог, награду, обучение, ролик, загрузку и ошибку.
Для игрового окна выводить его текст и доступные кнопки, включая причины
недоступности, если они известны. Связать окно с ресурсом игры, контролами,
условием появления, обработчиком действия и результатом сервера; использовать
уже найденные размеры и масштаб интерфейса после сверки с актуальной версией.

Команда проходит явные состояния: в очереди → отправлена → подтверждена либо
отклонена; при потере ответа — результат неизвестен. Подтверждение приёма
команды и завершение действия показывать раздельно. После разрыва сначала
восстановить состояние, затем решать о продолжении; неизвестное действие
не повторять автоматически. Кнопки должны соответствовать текущему состоянию
сессии и выбранной цели, а не только наличию обработчика в коде.

Журнал событий ограничить по размеру. Отдельно отключать его вывод, слои карты,
всплывающие окна и анимации; необходимые события продолжать обрабатывать.
Действие, требующее выбора пользователя, оставлять ожидающим и показывать
индикатор ожидания. Скрытие окна не считается нажатием кнопки или согласием.

Сейчас подключён только просмотр цели входа. Следующий технический шаг —
входящие события положения и сущностей; затем состояние квестов / окон и
первые подтверждённые команды с карты. Эти требования описывают целевой
интерфейс, а не уже работающие игровые действия.

## Ближайшее действие

Локальный переход обучения проверен в 64 native-сценариях: при заданном
разрешающем результате вызова raw0c увеличивается на 1 либо сохраняется по
флагу; state 0 становится 1. Реальный вызов содержит побочные эффекты, его
условия ещё не доказаны. Прослежены инициализация пары ключ / селектор, путь
показа подсказки и producer PktTutorialUpdate / ID 9903. Перед выполнением
проверить loader TutorialStep, ответ / снятие ожидающего ключа и callback панели.
Writer `0x145858ef0` уже проверен: 9 байтов, 64 native вектора и три отказа;
кодек не подключён к отправке. Ответ ID 9904 разобран: 19 байтов, 216 native
векторов / 19 коротких префиксов. Handler / сброс общего ожидания прошли 45
сценариев с fixtures. Удаление ключа / копирование раннего ответа / применение
записи дополнительно прошли 12 / 32 / 384 native-сценария с явными границами.
Различать серверный selector и локальный +1; в проверках ID 9904 gate и запуск
задач — fixtures. Потребитель queued ID 9904 проверен в 64 сценариях: настоящий
вход `0x1464cd550`, внутренний фрагмент `0x1464cd590` отдельно не вызывать.
Начальное применение ID 9905 / bootstrap / первый переход дополнительно
прошли 192 native-сценария: ранний gate настоящий, table / storage / запуск —
fixtures. Именованные setters `0x145c46830` / `0x145c46d20` подтвердили поля,
но происхождение row+0x50 и timer row+0x60 ещё неизвестно.
Следом связать явную ограниченную команду ID 9903 с текущей записью и ответом
ID 9904 в той же сессии. Отдельно продолжить условия автоматического запуска
и callback панели; подтверждение обучения не выдавать за действие ID 1836.
Сброс ожидания не означает завершение действия.
Активный step 2 ещё не подтверждён.
[Ответ и границы применения](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-RESULT.md).
[Очередь, удаление ключа и запись состояния](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-APPLY.md).
[Готовность и разбор очереди](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-QUEUE-DRAIN.md).
[Первый переход и поля таблиц](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STARTUP.md).
[Тело запроса и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-REQUEST-WRITER.md).
[Путь действия и следующий пробел](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-ACTION-ROUTE.md).
[Переход, строки и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STEP-ADVANCE.md).

Живой ID 9905 теперь прочитан через HONOR JP: 16 записей, ключ 1001 / state 1,
два других поля равны нулю; остальные 15 записей имеют state 0. Вход и 20 секунд
heartbeat без ошибок; соединение / feed / маршрут закрыты. Следом определить
семантику state и полей прогресса, чтобы выбрать ожидающий шаг и показать кнопку.
Не выдавать совпадение ключа 1001 за доказательство активного step 1001002.
[Живые данные, observer и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-STATE.md).

По уточнению пользователя персонаж ждёт нажатия панели квеста / обучения.
Первым разобрать активный квестовый шаг, текст и действие панели; затем проверить
его подтверждение и переход к движению. Отсутствие ID 307 само по себе не
подтверждает причину ожидания. В готовом прежнем извлечении есть кандидат:
Quest 110110 / Moving forward → task 110110040 → Tutorial 1001 → step 1001002,
текст о нажатии панели квестов справа, ключ `QuestPanel_PanelTouch`,
`WBP_GameUI / DeferredQuestUI / TableViewQuestList`, элемент 0.
Сверить эту цепочку с текущими таблицами и состоянием персонажа; не считать
кандидат уже подтверждённым активным шагом. Повторно извлекать весь каталог не нужно.
Выбранные шесть строк текущих CSV уже совпали с прежними полями. Найден
PktTutorialUpdateNotify / ID 9905, который действительно приходил в HONOR-сессии.
Callback и reader элемента теперь разобраны: ID 9905 — bool, uint16 count,
записи из трёх uint32 и state byte с clamp 3. Decoder прошёл 72 native тела
и 29 коротких префиксов. Handler найден; раннее применение откладывается.
Следом установить смысл полей / состояний и проверить lifecycle перед
подключением к живой сессии.
[Reader и границы применения](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-UPDATE-READER.md).
PktQuestPanelSelect / ID 1836 найден, но его producer / поле запроса ещё неизвестны.
[Сверка строк, ID и следующий адрес](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-PANEL-ENTRY.md).

Входящие ID 307 подключены к feed карты с проверкой ключа выбранного персонажа.
XY обновляется как серверная цель, Z сохраняется из ID 206 с явной пометкой.
Локальные проверки прошли; живая проверка на TECNO / vivo JP и Redmi HK получила
58 / BlockedIp до списка персонажей. После замены телефонов HONOR JP прошёл
вход, выбор и ID 206, затем 120 секунд без ошибок. Маркер цели входа показан;
ID 307 за это время не поступил. Соединение / feed / маршрут закрыты.
Продолжать writer / producer ID 305 и события квестов / окон; без нового шага
вход не повторять.
[Семантика цели, проверки и живые отказы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SELF-TARGET-STREAM.md).
[Новый успешный вход и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-HONOR-SESSION.md).

Для движения найдены текущие ID 305 / 306 / 307. Входящие ID 306 / 307 имеют
лёгкие декодеры; целые native readers прошли 28 случаев и 20 коротких префиксов.
ID 307 передаёт ключ сущности и XY, а receiver берёт Z из объекта и применяет
преобразование. Его условия и фактическую позицию проверить отдельно;
подключена только серверная XY-цель с сохранённой высотой, команды движения не отправлялись.
[Форматы, обработчики и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-CHARACTER-MOVE-EVENTS.md).

Разобрать последующие серверные события положения и сущностей для модели
сессии. Маркер цели входа на существующей карте и 120 секунд heartbeat уже проверены.
Live ID 206 code 0 получен через новый JP; соединение и маршрут закрыты.
Отдельно проверить проекцию, высоту, обновления положения, разрыв и восстановление.
Полный хвост ID 202, engine correction и сценарии квестов остаются открытыми.
[Живой ID 206 и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-WORLD-FINISH.md#живой-id-206-после-замены-телефонов).

## Предыдущие этапы до живого ID 206

Первую попытку остановил локальный лимит сопутствующих пакетов. Он исправлен:
обработка до 4096 пакетов / 128 ID, sample32; 19 socketpair-тестов прошли.
Повтор по просьбе пользователя завершился без ошибок.

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


[Отчёты и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#повторная-живая-проверка-выбор-принят).

Далее — история пути к этому результату; прежние формулировки отказа 16
не являются текущим блокером.

Профили 1.13.14 / ClientVersion 261105 готовы. Исправлена устаревшая
compiled-строка Version / Login; её новый источник проверен в EXE и native slice,
совпадение с успешным HK-захватом подтверждено. Код 1 — InvalidPacketVersion.
После исправления на JP и HK SDK / лобби / Game Version приняты, Game Login
вернул 16 / InvalidState. Список не отправлялся, соединения закрыты штатно.

Добавлен явный --read-character-list: при успешном Login он использует текущий
GameConnection / selection flow для ID 101 → 102. Socketpair-проверки прошли;
live список бота из-за отказа Login не получен. Автовыбор персонажа не включён.
Далее сверить источники оставшихся полей / metadata и ранний обмен с успешным
HK-клиентом: полная metadata там 792 байта, последний subset бота с I_TID — 262 байта.
Обязательность этих полей и причина 16 не доказаны; новый вход только после
конкретного подтверждённого изменения.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-WIRE-TAG.md).
Основной эталон подключения по выбору пользователя — запись
4c713eb525f1931c0cd285feae3faccc; полный путь / SHA и результаты находятся
в разборе по ссылке ниже. Она подтвердила успешную цепочку официального клиента.
Проверенные NMDeviceKey / DeviceKey в трёх захватах совпали с текущими HKCU
и привязкой бота. Выделено отличие раннего обмена: ID 30413 пустой seq 0,
Version seq 1, Ping seq 2, Login seq 3; бот начинает с Version seq 0.
Producer Ping новой версии исполнен в 36 native сценариях: source fields,
порог >5000, readiness / recovery подтверждены. В эталоне первый Ping показывает
смещение около 9 часов от capture clock. Clock source затем проверен native:
UTC GetSystemTime / Unix epoch + signed minute offset, 24 сценария / 3 теста.
Эталонные lobby ID 2 содержат 540 минут. Текущая регистрация ID 2 затем
подтверждена вместе с whole reader → handler → clock setter: 18 сценариев,
24 длины входа, три теста. Свежий lobby context подключён к раннему Ping для
нового SHA: Version → Ping → Login, локальные проверки прошли. Живая JP-попытка
с Ping снова дала Login 16; получен ID 17. Отдельный прямой запрос ID 101 после
отказа, разрешённый пользователем, за 10 секунд не получил ID 102. Следом
проверять оставшиеся отличия bootstrap / metadata по источникам; источник / роль
ID 30413, периодический Ping и полный lifecycle также остаются.
Для metadata найден actual writer новой сборки: FLogImpl::Start → 0x144555470.
Setter строки MakeSessionID проверен: это I_NMSessionID, а не I_TID; восемь
native случаев / два теста прошли. Формат I_TID проверен native; current Save
сохраняет settings+0x608. Новый runtime добавляет собственный постоянный TID
в частичную metadata, с SQLite reuse / concurrency / source guards; 14 тестов
прошли. Живая JP-попытка с I_TID дала metadata 262 байта и снова Login 16 при
принятых SDK / лобби / Game Version. Следом остальные source helpers / callbacks
metadata и lobby lifecycle; тот же контекст без нового изменения не повторять.
[Текущие записи и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-COMMON-DATA.md).
[Источник часов и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-CLOCK.md).
Наблюдение само по себе не разрешает подставить magic ID или старый Ping.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#полный-запуск-4c713eb5-и-сверка-идентификаторов).
Единая цепочка обновления всех данных и сценариев ещё не завершена.

Предыдущий этап до докачки:
21 октября установка обновлена, сервер ещё на технических работах. Офлайн-аудит
обнаружил новый EXE и основной PAK; свежий индекс PAK и сравнение сохранённых
файлов готовы. Patch manifest пока прежний. Ghidra дал кандидатов для 239 из
424 исследованных функций; девять пар входа / персонажей выгружены отдельно.
Базовый whole-list reader нового EXE проверен: 12 полных bodies совпали с
переносимым decoder, 238 коротких префиксов отклонены; память контейнеров — fixture.
Непустые appearance extensions / optional map прошли ещё 31 body / 489 префиксов,
включая duplicate overwrite и разные соседние записи. Constructor / vtable /
ID 102 / reader и ключ регистрации подтверждены отдельным native replay.
Новый handler / gate / predicate проверены вместе с reader в 50 сценариях:
применение и замена списка, сохранение при отказе, начальный индекс. Engine / UI
и память состояния — fixtures. Непрерывный ID 102 → setter / indexed caller →
ID 109 constructor / writer прошёл 25 сценариев; 20 байт тела совпали с codec.
Handoff и выходной archive — fixtures. Следом — handoff / транспорт новой сборки
и реальный вход. Старые адреса не переносить без проверки.
[Снимки, SHA и границы аудита](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md).

Рабочий вопрос — `login-invalid-state` в
[questions.json](../resource-tools/vampir/knowledge/questions.json).
Сравнить доказанные поля Login и SDK / launcher context. Новую сетевую попытку
делать после конкретного проверенного изменения. `common-data-population`
остаётся отдельным unknown; обязательность metadata на сервере не доказана.
Не расширять log replay без связи с недостающим полем или записью common data.

Проверено различие launcher credential / NID credential и launcher gate.
Ключ launcherToken и отдельные схемы ответов установлены; внутренний канал
берётся из другого поля credential. Проверен GetLauncherToken с NID credential 33.
Планы, parser и runner реализованы; реальные launcher token / sign-in приняты.
Через два JP-телефона и HK Game Login вернул 58 / BlockedIp.
После последней замены телефонов тот же flow на новом JP вернул 16 / InvalidState;
второй новый JP не установил прямой транспорт. Новый аккаунт и ключи не создавались.
Официальное сравнение выполнено 21 октября: пользователь создал Okly на Franz 2
и вошёл в мир. После закрытия игры бот на том же выбранном JP снова получил 16.
Три ключа Windows совпали с сохранённой привязкой. Следом — источники оставшихся
полей игрового контекста; одинаковый вход без нового отличия не повторять.

По запросу пользователя добавлена [локальная запись TCP в Phone Exit](../../pc/DIAGNOSTICS.md).
21 октября получена официальная запись: игровой Login 0, список с одним персонажем,
выбор ID 109 → 110 и последующий обмен. Framing / исходящие CRC проверены;
позиция ещё не извлечена. Сравнение Login выявило непустую metadata +0xd8
(791 байт, включая I_DeviceKey) и policy byte +0x124 = 1 вместо 7 у бота.
Следом — источники актуальных metadata и policy перед исправлением runtime.
Байт policy связан с языком менеджера локализации; runner допускает явный
`--language-code`. Encoder с DeviceKey воспроизвёл официальные 791 байт, но свежие
поля ещё нужно собрать. [Продолжение и live результаты](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).
Две сравнительные попытки с языком 1 получили LobbyLoginResult 10036 до игры.
Mapper лобби расшифровал этот код как IsInspect / технические работы;
смешивать его с ошибкой Winsock или прежним Game Login 16 нельзя.
Свежая страна и частичная metadata из шести подтверждённых полей уже подключены
и проверены по отдельности: выбранное лобби в обеих попытках вернуло 10036.
Helper отказа `0x145f8a550` связан с отдельным mapper `0x1458050e0`, а его
код 10036 — с IsInspect. Полные неизвестные поля metadata пока не заполнять
догадками; проверку игрового входа продолжить после изменения ответа лобби.
[Запись и границы разбора](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md).
[Результаты](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

## Как не повторять исследования

Продолжение metadata на новом SHA: шесть update callees сохранены, целые
UpdateGmc2 / UpdateSDKSetting проверены в 31 native сценарии с fixtures service
и FString. Следом — producer settings+0x3f0 / +0x3e0 из GMC2 и условные
channel / NID ветви UpdatePlayer. Runtime ещё не дополнен этими полями.
Теперь найден путь clientIp → settings+0x38 и geoLocation → SetCountryCode →
settings+0x3f0. Setter с notify=0 проверен в 14 native случаях: A1 сохраняет
непустое прежнее поле, но записывается при пустом. Следом — свежий GMC2 context
для runtime; город без нужного consumer отдельно не разбирать.
[Новый разбор](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md).
[Адреса, проверки и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-COMMON-DATA.md#обновление-сессионных-полей-из-sdk-и-gmc2).

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


Перед новым разбором искать VA/имя в реестре и читать вопрос / decision_rule.
[Правила базы знаний](../resource-tools/vampir/knowledge/README.md).
[Сводка всех тем](../resource-tools/vampir/knowledge/TOPICS.md).

[TASKS-HISTORY.md](TASKS-HISTORY.md) сохраняет прежние номера H/U и всю историю
этапов. Формулировка «готово в указанном объёме» там означает bounded этап,
а не завершённый продукт. История не является очередью на повторное выполнение.

При завершении подключения подготовки SDK к панели установленный EXE изменился:
SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверки этого этапа относятся к прежнему SHA `98802d550890…`; совместимость
новой сборки ещё не подтверждена. Перед следующим живым входом сверить обновление.
