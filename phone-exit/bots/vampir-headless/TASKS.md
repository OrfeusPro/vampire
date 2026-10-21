# Самостоятельный Vampir — актуальный порядок работ

Статус на 22 октября 2026. Цель продукта сохраняется полностью: клиент без
игры, 2D-карта с игровыми меню, фарм, обновления данных и Android.

| Порядок | Результат, который нужен | Что есть / что остаётся |
| --- | --- | --- |
| 1. Вход | Game Login принят, затем реальный список персонажей | На JP SDK / лобби / Game Version / Game Login code 0, CharacterList code 0 / одна запись после свежего GMC2 и metadata 312 байт |
| 2. Персонаж | Получить список, выбрать, получить позицию | На JP ID 109 → ID 110 code 0, body 4724 байта полностью разобран; ID 202 → ID 203 → ID 204 code 0; семантическая позиция ещё не получена |
| 3. Сессия | Поддержание, ответы, разрыв и восстановление с понятными состояниями | Bounded GameConnection и локальные проверки есть; полный live lifecycle не проверен |
| 4. Карта и UI | Движущийся персонаж, цель перемещения, игровые меню | Использовать существующий атлас / nav study / UI geometry; live слоя ещё нет |
| 5. Фарм | Место → путь → автобой → контроль состояния | Данные квестов / NPC / навыков есть; сетевой сценарий не выполнен |
| 6. Обновления | Автоматически определить изменения, переизвлечь данные, сверить связи; вручную разбирать только нерешённое | Есть единый update / полный аудит / resource adapters и очередь; автоматическая совместимость всех связей не подтверждена |
| 7. Нагрузка и Android | Измеренный лёгкий runtime, инструменты отдельно | Нагрузка нескольких аккаунтов и перенос самостоятельного бота ещё не проверены |

## Ближайшее действие

Найти подтверждённый consumer позиции и необходимые шаги мировой инициализации
на текущем SHA. Вход / список / выбор уже выполнены через JP: Login 0,
CharacterList 0 / одна запись, ID 110 code 0 / 4724 байта полностью разобраны.
Сокеты и временный маршрут закрыты. Позиция, completion мира и длительная
сессия ещё не подтверждены; повтор выбора без нового действия не нужен.

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
в 8 / 36 сценариях. Полный decoder ID 206 на новом SHA ещё не сверен;
runtime по-прежнему останавливается после ID 204.
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
