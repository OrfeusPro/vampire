Для launcher 1.13.18 проверены восемь key initializers и ссылки request globals,
оба callback E9 и transport call sites. Статические тесты прошли; JSON/значения,
callback targets/transport и живой вход ещё не проверены, профиль не активирован.
[Связи и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LAUNCHER-REFERENCES-11318.md).

Для launcher token/sign-in 1.13.18 проверены полные формы инструкций и
локальные переходы: 652/679 инструкций совпали с 1.13.16, routes подтверждены.
Внешние calls/data остаются unresolved; совместимость авторизации и новый
профиль этим не подтверждены.
[Проверка и следующий этап](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LAUNCHER-SHAPE-11318.md).

Офлайн-обновление 1.13.18 завершило автоматический проход: needs_review,
два полных экспорта кандидатов launcher и конфигурация AppVersion=1.13.18.
Новый профиль не собран: 150 строк очереди привязок/проверок/зависимостей.
Следом — review launcher token/sign-in и перенос связанных checks по новому SHA.
[Отчёт и ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-AUDIT-11318.md#продолжение-штатного-обновления).

Установлен клиент 1.13.18 (EXE SHA d3070828…), обнаружен изменённый основной PAK.
Штатный plan-only аудит сохранил отдельный план: 165 архивов проверены полными
SHA, 164 совпали. Профиль не активирован; прежняя сессия hk-test сохраняется.
[Аудит, SHA и продолжение](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-AUDIT-11318.md).

Найден current producer pending+44: receiver 145DAD170 переносит native input+14
и передаёт его actual writer. 48 новых случаев вместе с прежними дают 145;
A8=true/derived vtable и внешние подсистемы — fixtures. Current ID204 handler
с receiver и active state ещё не связаны для live offer.
[Источник и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-PENDING-11316.md).

Callback writer теперь исполняется native с явным tail: AL=1 может обходить
копирование/processing, а environment phase остаётся 3. Перехваченный пустой
capture проверен после writer return; 48+9+16+24=97 сценариев прошли. Scheduler,
guards/engine processing остаются fixtures, live action не включён.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-CALLBACK-11316.md).

Phase handler теперь исполняется native: writer реально ставит фазу 3 до
guard; caller ставит 5 для выбранных состояний. 48 случаев, 9 getter ветвей
и 16 phase переходов прошли с проверкой записи до notify. Совпадение +40
не означает готовность Time: фаза должна быть выше 5. Live action не включён.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-PHASE-11316.md).

Getter объекта guard теперь исполняется native: global/typecheck/fallback/resolve
и context+158 заменили прежнюю подстановку. 48 writer/readiness случаев и
9 getter ветвей прошли. Virtual+7B8, источник pending+44 и активное состояние
ещё неизвестны; live action не включён.
[Источник и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-GUARD-OBJECT-11316.md).

Подтверждён writer environment+40: при true внешнем guard пишет аргумент и
сбрасывает pending+44; при отказе сохраняет прежнее и ставит C1. Source retry
caller и readiness проверены вместе в 48 native случаях; callback/guard engine
остаются fixtures. Источник pending и активное состояние ещё нужны для live offer.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-UPDATE-11316.md).

Найден метод environment vtable+10: он задаёт +40 из той же нулевой
константы, что QuestTask data+14. Метод включён в 34 native Time сценария;
прежние synthetic 3/4 заменены начальным 0 и явным mismatch 1. Его вызов
в живом lifecycle и поздние изменения полей ещё не подтверждены.
[Источник и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-INIT-11316.md).

Environment predicate связан с настоящим constructor/global/vtable: getter
читает int окружения +40. Эти native функции заменили две прежние подстановки;
34 Time сценария прошли. Registry callback и фактические значения полей ещё
не установлены, поэтому live offer пока не включён.
[Источник и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-ENVIRONMENT-BINDING-11316.md).

Начальное QuestTask data+14 связано с конструктором: source constant 0,
загруженные шесть шагов «Зова крови» сохраняют 0 в обоих порядках загрузки.
Проверка включает 36 native проекций; поздние записи поля и environment kind
ещё не установлены, реальный action offer не включён.
[Источник и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TASK-BASE-DEFAULT-11316.md).

Readiness predicates теперь используют тот же task/data, что и Time: exact
record+30 leaf и оригинальный RunInInstance getter+89, 34 native сценария.
Закрытая instance ветвь вызывает model virtual+30; её побочные эффекты ещё
не установлены. Онлайн-сессия сохранена, игровые команды не отправлялись.
[Проверка и оставшиеся условия](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TIME-TASK-BINDING-11316.md).

# Vampir — главный указатель разработки

Два native readiness predicates подключены к Time lifecycle: 34 сценария.
Первый сравнивает data+14/environment virtual+B8; второй mode3 выбранный quest
либо flag против byte+5A. Missing model/data и несоответствие блокируют таймер.
Role data/environment ещё unknown, их значения synthetic; далее QuestInfo
source/selected environment и concrete offer builder. Сессию сохранять.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TIME-GATES-11316.md).

Backend owner offers подключены к существующему JS quest adapter: enabled
только для явного шага, stale/busy блокируются, после dispatch остаётся receipt.
Missing prompts отображаются отдельно от готовности действий. 3 HTTP/JS/local
socket bridge tests, 14 регрессий и Node suites прошли; requested preview собран.
Production offer builder ещё не включён; живую сессию сохранять.
[Контракт и preview](../vampir/UI-LIVE-MESSAGES.md#мост-явного-owner-offer-к-панели-заданий).

Однократный quest pump подключён к новому owner loop после world publish.
Только explicit trusted offer + HTTP намерение дают dispatch; default no-op,
stale контекст отказывает, после попытки offer снимается без автопродолжения.
4 новых теста / 22 регрессии / 42 login tests прошли. Source-bound offer builder
ещё не включён в launcher; текущая сессия сохраняется на прежнем коде.
[Контракт и границы](../vampir-headless/ACTIONS.md#однократный-owner-pump-выбранного-шага).

Quest receipt сопоставляет ответы1811/изменения1854 после socket acceptance
по scope/quest и 10секундному окну, с baseline/duplicate checks и deep copies.
Чужой world1854 теперь игнорируется. Это candidate observations, не causal
transaction или confirmation. 4 новых теста и 21 регрессия прошли; live owner
сохранён. Далее source-bound expected transition и одноразовый owner pump.
[Контракт и ограничения](../vampir-headless/ACTIONS.md#наблюдения-после-передачи-кадра).

Добавлена отдельная transport receipt для QuestUpdate: queued до последнего
байта, socket_accepted после полного кадра, partial close → outcome_unknown.
Owner snapshot/journal показывают receipt отдельно от server confirmation.
4 локальных partial/blocked/close/budget/isolation теста и 23 регрессии прошли.
Текущая сессия не перезапускалась; далее корреляция response/request/progress.
[Контракт и ограничения](../vampir-headless/ACTIONS.md#полный-кадр-принят-локальным-сокетом).

Добавлено наблюдение ID1811 в новом LiveSession: полный source-bound decoder,
последний scoped ответ и ограниченный journal. 4 теста: native parity900,
50 synthetic sessions/HTTP/uint64, scope/world/close/errors; результат не
подтверждает sent action и не меняет1854. Текущий owner сохранён на прежнем
коде; далее корреляция результата/шага и один игровой тест.
[Контракт](../vampir-headless/ACTIONS.md#наблюдение-questupdateresult-без-автоматического-подтверждения).

Current handler 1811 связан с регистрацией и моделью: packet+18 quest key,
+20 state, nested+28 progress, flag1. 192 native сценария gate/dispatch прошли;
projection/model virtual lifecycle fixtures явные. True gate включает особый
1197 в одном режиме, поэтому confirmation не равен допуску gate. Далее
наблюдательный decoder/receipt и корреляция; сессию сохранять.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-RESULT-APPLICATION-11316.md).

Current PktQuestUpdateResult 1811 проверен целыми outer/nested readers/writers:
30 байт <IQBBQQ>, outer byte clamp6, nested byte без clamp. 900 полных
вариантов / 30 коротких / 12 primitive failures прошли с archive fixtures.
Смысл raw key/progress и подтверждение действия ещё требуют receiver; далее
registration/handler 1811. Сессию сохранять.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-RESULT-11316.md).

Native update → pending consumer → producer проверены в 24 сценариях:
kind1 создаёт packet 1810; busy сохраняет запись, missing actor/model может
удалить её без send. Captured fields прошли portable codec/local socket.
Provider/actor/property/cleanup fixtures явные, live admission false. Далее
reader/корреляция 1811 и ограниченный одноразовый Time тест; сессию сохранять.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-CONSUMER-11316.md).

Time completion теперь проверен вместе с native pending wrapper: 34 случая.
1455ca010 не отправляет пакет сразу: добавляет kind1 в model+80 и подавляет
same QuestInfoId даже при другом index. Другой kind/key сохраняется; внешний
guard может запретить append. Далее consumer pending → producer/result;
live admission false, сессия сохранена.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-PENDING-TIME-11316.md).

Native Time callback/start/tick/timer/completion прошли 24 сценария на
source 110120005 (0.1) / 110120070 (1). Порог сначала ставит FFFFFFFF;
следующий tick вызывает named request. Без смены owner state цикл повторяется,
с изменением state повтор прекращается. JSON/engine/gates/request sink fixtures
явные, live admission false; далее route 1455ca010 и условия selected task.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TIME-11316.md).

Native lookup/progress теперь выполнены непосредственно на массиве шести
задач 110120 после native main/ru загрузки: 36 проекций, original index 0 →
110120005, reverse index 0 → 110120070. У всех шести source service group
пустая; текущий регион не нужен этому gate. Active lifecycle/handler/position
ещё не допущены; далее kind 6 Time 0.1 и применение task state. Сессию сохранять.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LOADER-PROJECTION-11316.md).

Очередь намерений соединена с typed QuestUpdate через owner dispatch и
явно привязанный GameConnection. Пять локальных HTTP/socket-тестов проверяют
повтор, scope/context, backpressure/unknown и изоляцию двух владельцев.
Selected-state contracts в тестах synthetic; production loop и серверное
подтверждение ещё не подключены. Живая сессия не перезапускалась.
[Контракт и границы](../vampir-headless/ACTIONS.md#получение-намерения-и-постановка-questupdate-владельцем).

Добавлен typed переход GameConnection → QuestUpdate outbound после accepted
world completion и проверки source SHA. Четыре локальных socket-теста покрывают
world gates, key rotation, sequence/backpressure и двух владельцев. API/queue
ещё не соединены с selected-state handler; живых quest-команд не было.
[Граница и следующий шаг](../vampir-headless/ACTIONS.md#переход-из-владельца-сокета-в-typed-outbound).

Совместная native цепочка identity/key/region lookup/numeric reader/setter
прошла 1008 случаев: found empty/JP → 0 без primary fallback, missing →
legacy/cache; одновременно существующие profile keys дают разные числа.
Lower storage/string/platform/write fixtures явные; actual region/изоляция
реальных аккаунтов ещё не доказаны. Сессию сохранять.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-NUMBER-11316.md).

Числовое чтение RegionSelect прошло 56 native сценариев: found flag отделён
от значения, запятые удаляются, найденные empty/JP дают 0 и true; missing
сохраняет output. Storage/string fixtures явные, active region неизвестен.
Далее совместный lookup/reader и lower storage; сессию сохранять.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-REGION-NUMBER-11316.md).


Native identity getter добавлен к key/region lookup/setter: 432 случая,
refresh/empty/failed-init cached fallback/successful-init и ownership проверены.
Platform/subsystem/string/config fixtures остаются; identity semantics и active
region не подтверждены. Реальные профили/настройки/сессия не менялись.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-IDENTITY-11316.md).

Native dynamic RegionSelect key / lookup / setter прошли 288 случаев:
две synthetic identity дают разные keys, absent/empty identity — PreLogin.
Engine/identity/string/config services остаются fixtures, actual identity /
active region и storage не подтверждены. Настройки и сессия сохраняются.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-KEY-11316.md).

Native provider getter / region lookup / service setter прошли совместно
216 случаев: primary/legacy/missing config paths, fallback+A8 и две legacy
write intentions только в памяти fixture. Dynamic key/config IO/string fixtures
остаются; actual region не подтверждён, реальные настройки не менялись.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-REGION-11316.md).

Native service setter прошёл 144 случая: lookup/fallback региона, запись
RegionType/ServerId, dirty/ready flags и сохранность остальных данных.
Handler source binding передаёт selected state+30C. Region provider/lookup
fixtures пока явные, active numeric region не подтверждён; сессия сохраняется.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-SETUP-11316.md).

Current ServerServiceGroup связан с native loader fields: RegionType и
Min/MaxServicePhase (не client version). ServerGroup.Id 256 задаёт phase 10000;
group 10000 candidate policy различает regions 0–4 / 5–7. Active RegionType /
numeric setup ещё не доказаны, вывод не переносится в live. Сессия сохраняется.
[Source bindings и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-DATA-11316.md).

Native nonzero service gate / environment getter / policy прошли 30 случаев:
inline/external buckets, missing/empty group, deny/allow lists и inclusive version
bounds. TLS/manager/config inputs и string/version services — явные fixtures;
actual current policy ещё не доказана. Далее source-bound service table / numeric
environment перед whole catalog admission. Сессию сохранять.
[Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SERVICE-POLICY-11316.md).

Native ru override edge cases прошли на 8 main / 9 ru source rows × 2 orders:
duplicate 50000090011 last-row-wins при explicit flags; unmatched ID не создаёт
record, missing translation остаётся empty. Param/fields/groups сохранены.
Whole catalog/current policy/active flags ещё нужны, live admission false.
[Границы и доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-OVERRIDE-EDGES-11316.md).

Whole base + ru override loaders и localization transform выполнены совместно:
6 original rows × 2 orders, 6 TaskName stores; исходный Param / все поля / group
order сохранены. No-op override fixture заменён native root; file/header/string /
settings/storage fixtures остаются. Missing/duplicates/full catalog ещё нужны,
live admission false, сессия сохраняется.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LOADER-OVERRIDE-11316.md).

Native localization transform прошёл 336 сценариев на русских названиях и
lexical strings: explicit flags / Untranslated / fallback / ### prefix.
String/settings services — bounded fixtures; active flags и whole override
ещё не допущены. Далее ru override loader с missing/duplicate rows.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LOCALIZATION-11316.md).

Для названий этапов выбран русский current QuestTask_Name CSV: 5943 base IDs
найдены, 1 missing и 48 duplicate IDs сохранены без выбора победителя. Все 16
locale schemas не имеют Param; native optional branch связан с record+90.
Native override/active flags ещё не исполнены, live admission false.
[Русские строки и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-OVERRIDE-DATA-11316.md).

Actual numeric getters / native decimal parser / Windows CRT прошли 26 906
случаев из всех 5944 CSV rows без расхождений. Native scalars заменили fixtures
в whole loader на 6 rows × 2 orders; fields и group order совпали. Edge inputs
отличаются от generic int/float; override / file/header / full load остаются
открыты, live admission false. Сессия сохраняется.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SCALARS-11316.md).

Whole QuestTask loader выполнен с native tokenizer / constructor / maps:
6 исходных строк «Зова крови» в прямом и обратном порядке, все 16 data fields
сверены; group array сохраняет insertion-slot order. File/header/scalar/string /
storage и overrides остаются fixtures. Actual getters / override / whole catalog
нужны до live admission; соединение сохраняется.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LOADER-11316.md).

Настоящие QuestTask constructor / field-copy включены в map chain вместо
constructor fixture: 210 создания с проверкой defaults, 420 inserts / 840 lookups.
Empty-wide / allocator / hash fixtures остаются явными. Accepted CSV stores /
whole loader / overrides ещё нужны; live order не допущен, сессия сохраняется.
[Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-RECORD-CHAIN-11316.md).

Native CSV tokenizer прочитал 6 исходных строк «Зова крови» и 8 lexical cases;
созданные пустые service-group cells прошли actual getter / Windows atoi / zero
filter. IO/string/vector storage — явные fixtures. Whole loader / record creation /
overrides ещё нужны перед live order admission; действующая сессия сохраняется.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-CSV-ROW-11316.md).

FindOrAdd→insert→growth→rehash проверены совместно: 6 fresh-map sequences,
420 inserts / 840 existing lookups. Порядок slots/payload сохраняется с явными
allocator/hash/bit-append fixtures. Далее CSV accepted-row creation/loading;
live order admission пока false.
[Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-MAP-CHAIN-11316.md).

120 native rehash cases подтвердили сохранение nodes/payload и slot iteration;
16 growth cases — расчёт ёмкости / замену pointer с явным realloc fixture.
CSV fresh load / whole insertion chain / overrides ещё открыты; order не допущен.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-MAP-GROWTH-11316.md).

CSV cell / SSO getter и настоящий Windows atoi прошли 14 случаев; 8 zero cases
прошли через native service-group gate без skip, 3 column bounds — без CRT.
Row creation / fresh load / growth ещё открыты, active step не допущен.
[Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-EMPTY-GROUP-11316.md).

96 native preallocated insert cases подтвердили append/free-slot и hash linking;
4 missing/parsed-zero service-group ветви возвращают «не пропускать». Parser пустой
ячейки, growth/rehash и полный порядок загрузки ещё открыты; active step не допущен.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SPARSE-INSERT-11316.md).

Current QuestTask CSV связан с native stores Id / QuestInfoId / Type. 5944 записи
и 1353 группы прошли lookup / progress с настоящим Type getter; каталог сохранён
вне Git. CSV order / active step не допущены: нужны sparse insertion / row filter
и override proof перед привязкой к живому индексу.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-CSV-PROJECTION-11316.md).

Factory case 6 / создание / replacement прошли 378 native сценариев с настоящими
constructor / shared move / refcounts и явными внешними fixtures. Исправлен
обнаруженный native replay пропуск Jcc fallthrough в export: 14 index / 14 collector /
14 workflow tests прошли. Далее task table order / current CSV и конкретный owner
action; игровые команды ещё не включены.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TASK-REPLACEMENT-11316.md).

В новом коде владелец может явно подключить очередь к /actions и /policy:
проверены loopback HTTP для 50 synthetic sessions, токены, точные offers,
дедупликация, смена мира и отключение auto skip. Production game pump / decoder
ещё не подключены; действующая сессия не перезапускается.
[Контракт и ограничения](../vampir-headless/ACTIONS.md).

В live-прототип добавлены сообщения / ответы / «Пропустить», default skip=true,
отдельное автовыполнение по клику на квест и ожидание ручного подхода к NPC.
Node и браузерный fixture прошли. На Infinix те же флажки видны с настоящими
HP/MP, сессия сохранена; message decoder / owner API ещё не подключены.
[Паспорт и границы](UI-LIVE-MESSAGES.md).

Current QuestUpdate codec прошёл 81 native тело, 29 коротких входов и 6 отказов
записи с настоящими constructors / archive IO. Добавлен typed outbound frame;
selected task / action API / pump ещё открыты, живые команды не отправлялись.
[Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-WIRE-11316.md).

Основа очереди действий прошла 5 тестов с 50 synthetic accounts: намерения
quest / dialogue / skip / equip изолированы, неизвестный исход блокирует повтор.
Игровые handlers / API / UI ещё не подключены; текущую сессию не перезапускали.
[Состояние реализации](../vampir-headless/ACTIONS.md).

Current task lookup и progress projection проверены вместе в 324 native
сценариях с настоящим обходом коллизий; manager / hash callback — fixtures.
Порядок задач и применение к selected state ещё открыты. Для выполнения по
клику / диалогов / пропуска / экипировки нужен отдельный action adapter;
текущая Infinix-сессия сохраняется, analysis остаётся только наблюдением.
[Проверка и следующий шаг](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TASK-LOOKUP-11316.md).

Новый Infinix X650 / HK вошёл в мир независимым запуском: Okly, уровень 1,
HP 2700/2700, MP 2000/2000, «Зов крови». Игра, транспорт и сервер карты
теперь имеют отдельных владельцев Task Scheduler. На uptime 239 секунд heartbeat
40 / 40, сессия сохранена; проверка перезапуска Codex ещё требуется.
[Текущая сессия и baseline](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-SCHEDULED-11316.md).

После перезапуска Codex прежние Redmi game owner / transport / API отсутствуют:
сессия офлайн, причина завершения не установлена. --detached переведён на
одноразовую задачу текущего пользователя вне дерева Codex. Два Windows-теста
подтвердили сохранение synthetic worker после taskkill /T и очистку при timeout;
настоящий transport / owner запущены новым способом, но Redmi / HK получил
58 / BlockedIp. Оба owner штатно закрылись, повтор не запускался. Для проверки
перезапуска Codex с персонажем нужен новый выход и успешный вход.
[Новый запуск и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-SCHEDULED-OWNER-11316.md).

Current progress helper проверен целиком в 324 native сценариях; установлены
индекс задачи, читаемый со знаком, формирование результата и fallback.
Происхождение task array / применение к модели остаются открытыми;
следование по клику пока не включено. Во время исследования Redmi была онлайн;
после перезапуска Codex её владелец завершился, как указано выше.
[Проверка и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-PROGRESS-11316.md).

В живой панели задания выводятся на русском из текущего PAK: 1 341 название
и описание через общий каталог и адаптер. На сохранённом онлайн-персонаже
проверен «Зов крови» (110120). Неизвестные ID сохраняют числовую подпись;
выполнение задания по клику ещё не подключено.
[Источники и проверка](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-NAMES-RU-11316.md).

Прежний breakaway запуск проверил выход dispatcher / Stop и 50 synthetic
sessions. Redmi / HK тогда вошёл в мир, получил ID 1854 / Quest 110120;
heartbeat 232 / 232 после выхода launcher. Позднейший перезапуск Codex
не пережит; актуальный способ и ограничения описаны выше.
[Предыдущая проверка](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-DETACHED-OWNER-11316.md).

Current QuestUpdate sender / lookup коллизий / state getter / position wrapper
проверены целиком в 640 native сценариях, 160 дошли до send fixture.
Engine / сеть / destructor — fixtures; маршрут и выполнение квеста не проверены.
[Матрица и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SENDER-11316.md).

Для запуска по клику уточнены current QuestUpdate input fields:
QuestInfoId / TargetId / QuestTaskIndex. Найден sender по текущей модели;
клик HUD, маршрут и выполнение ещё не доказаны, команды не отправлялись.
[Producer и ограничения](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-PRODUCER-11316.md).

Входящий ID 1854 подключён к отдельной quest-модели и правой панели через
общий адаптер: полученные записи / raw progress, без игровых команд.
Проверены 50 synthetic owners, HTTP и браузер; настоящего нового списка пока нет.
Itel-сессия завершилась при перезапуске Codex. Названия по каталогу требуют
current key binding. [Результат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-QUEST-MODEL-11316.md).

Для правой панели заданий найден входящий ID 1854 / QuestSyncNotify,
который уже посчитан живой Itel-сессией. Его полный current decoder прошёл
96 native тел / 172 коротких префикса с настоящими constructors / callbacks /
typed copy. Модель и UI ещё не подключены; персонаж не перезапускался.
[Формат и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-SYNC-READER-11316.md).

В журнал основного прототипа подключено последнее сообщение обучения через
адаптер. Проверены 16 живых записей и сохранение той же Itel-сессии после
обновления UI: heartbeat 178 / 178. Это наблюдение, не активный шаг квеста.
[Проверка журнала](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-JOURNAL-11316.md).

Itel / HK вошёл в мир: current decoder получил 16 реальных tutorial records,
запись 1001 имеет raw0c 2 / raw10 1 / state 2, ошибок 0.
Соединение оставлено работать; активный локальный шаг ещё не установлен.
[Живые данные](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-11316.md).
Current consumer ID 9905 проверен в 160 native сценариях; application / free
остаются fixtures. [Очередь](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-DRAIN-11316.md).

Обновление существующих tutorial server/local records проверено в 384 native
сценариях; gate / insertion / launch остаются fixtures.
[Границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-POPULATED-11316.md).
Часовая живая сессия завершилась по TTL: 701 Ping / 702 ответа, один пустой
ID 302 без ошибок. Повтор получил BlockedIp; ожидается новый телефон.
[Итоги](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-LIVE-MAP-CLOSE-11316.md).

Current fresh-startup application / bootstrap проверен в 192 native сценариях:
серверная запись отделена от локального selector. Table / storage / launch —
явные fixtures; действия и populated state ещё не перенесены.
[Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STARTUP-11316.md).

Native ID 9905 handler / gate / deferred deep copy проверены в 192 сценариях.
Связь gate с headless lifecycle и application maps ещё открыта;
исходящих команд не добавлено. [Доказательства](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-DISPATCH-11316.md).

OnePlus PGP110 / HK вошёл на JP 256: живые HP/MP и маркер мира 10012
проверены в основном прототипе, ручной сдвиг сохраняется после polls.
[Живая карта и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-LIVE-MAP-11316.md).
ID 9905 текущего клиента проверен whole native replay: 73 тела и 835 префиксов.
Будущие владельцы сохраняют последнее raw сообщение обучения изолированно;
application handler / действия ещё не подключены. Действующий owner не перезагружался.
[Контракт](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-UPDATE-11316.md).

Готовая проекция Map10/11 перепроверена для 1.13.16 и подключена к адаптеру:
мир 10012 → Map10, центрирование / приближение при первом получении позиции,
обычные клики и ручной сдвиг сохраняют вид. 14 тестов и браузерный fixture прошли.
Живой realme-вход дал HP/MP и мир, но был без проекции; её повторная live проверка
остановилась сначала на NID, затем на game 58 / BlockedIp. Текущий приоритет —
стартовые задания персонажа уровня 1; последующая живая проверка маркера описана выше.
[Источники и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-MAP-POSITION-11316.md).

Живая проверка окружения 26 октября: SDK / лобби пройдены через OPPO / HK,
но JP 256 вернул `58 — BlockedIp`; world / SightEnter не получены. Повтор
через этот выход не выполнялся, тестовый транспорт закрыт. Нужен другой выход.
[Порядок и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-INITIAL-ENVIRONMENT-LIVE-ATTEMPT-11316.md).

SightEnter ID 301 подключён к изолированной модели окружения: NPC и другие
игроки, имя игрока, уровень, начальные HP/MP и XYZ. Собственный персонаж исключается
по подтверждённому ключу; его vitals не смешиваются с окружением. Проверены
50 synthetic owners, две HTTP-страницы с 512 игроками и таблица в браузере.
Живой поток окружения, текущие изменения / движение и живой маркер ещё не проверены.
[Доказательства и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-INITIAL-ENVIRONMENT-11316.md).

SightEnter: полный portable wire decoder проверен с native outer reader, всеми
callbacks, временными stack records, copies и cleanup CharacterOther / NPC /
Gadget / ground / tether / projectiles. 1170 cases и 6 trailing checks прошли;
final поля сверены после cleanup временных записей, все tracked buffers освобождены.
Storage / map reset / final-array iteration остаются bounded fixtures.
[Проверки и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-SIGHT-ENTER-WHOLE-11316.md).
Current registration / handler → model / typed actor проверены статически;
ID 301 подключён к частичной модели выше. Живой поток и engine/listener ещё не проверены.

Частичное окружение подключено к сессиям и основному UI: NPC create / sight leave,
начальные HP / MaxHP и XYZ, очистка по миру / close и отдельная кнопка просмотра.
Проверены 50 изолированных synthetic owners и браузер через loopback API;
это не новый live proof. Начальный SightEnter / players подключены выше; изменение NPC stats /
движение и карта остаются открытыми. [Контракт и доказательства](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-OBSERVED-ENVIRONMENT-11316.md).

Полный NPC create ID 324 проверен offline: 323 native/portable сценария,
454 обрезанных префикса, вложенные effects / appearance / map / stats / move /
owner / quest records. Добавлен ограниченный source-bound wire decoder;
Create/leave association и частичная модель описаны выше; начальный SightEnter,
players и живой поток остаются открытыми.
[Формат, проверки и ограничения](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-NPC-CREATE-11316.md).

В ветви окружения отдельно проверена вложенная `PktEffectData`: 7656 native
сценариев полного reader / optional vector с каждым префиксом ввода.
Эта вложенная запись также включена в полную проверку NPC create выше;
actor / видимость и live-модель ещё не подтверждены.
[Доказательства и следующий шаг](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-NPC-EFFECT-11316.md).

В основной прототип добавлен режим выбранной живой сессии через общий адаптер:
HP/MP, параметры, существующее меню с доступностью по данным и кнопка журнала.
Большая карта принимает подтверждённую позицию; текущая проекция подключена выше,
живые задания / окружение и следование ещё открыты. UI проверен локально на явно обозначенных
fixtures, без повторного игрового входа. [Контракт и проверки](UI-PROTOTYPE-LIVE.md).

Добавлены [онлайн-журнал и локальный обработчик](../vampir-headless/LIVE-DIAGNOSTICS.md),
который перечитывается во время работы отдельного владельца сессии. В браузере
проверены пауза / фильтр журнала. Через новый OPPO / HK подтверждены смена
локального обработчика и восстановление после SyntaxError при той же игровой
сессии: heartbeat 12 → 45, 207 stats, decoder errors = 0.
[Живой журнал](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-JOURNAL-11316.md).

Живые HP/MP и уровень подключены к общему компоненту: через Xiaomi / HK
получены HP 2700/2700, MP 2000/2000, уровень 1 и 207 stats. На 315 секундах
нет stat decode errors; 63 periodic Ping / 64 ответа. Stop и очистка UI проверены.
Native: 1119 сценариев ID 321 / 322 и 203 начального массива / модели.
Окружение / карта и реальные 50 аккаунтов остаются открытыми.
[Данные, UI и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-STATS-CHECK-11316.md).

На новом Redmi / HK постоянный owner проверен 315 секунд в мире: Login / Select /
world — 0, 63 periodic Ping / 64 ответа, Stop API — HTTP 202 и `session_stopped`.
Состояние очищено, тестовый транспорт закрыт. Отказ 58 на новом выходе не повторился.
HP/MP и окружение ещё требуют декодирования; 50 реальных аккаунтов не проверены.
[Живой результат и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-PERSISTENT-SESSION-11316.md).

25 октября добавлены изолированные live-сессии, общий запускатель аккаунтов и
адаптер существующих HP/MP-компонентов. Локальные проверки пройдены; неизвестные
параметры остаются `null` / «—». Живая проверка постоянного режима через HK
получила Game Login 58 `BlockedIp` до списка персонажей. Транспорт остановлен,
пользователь готовит новый телефон. Предыдущий Login 16 исправлен; новый отказ
не связан с подтверждением постоянной сессии.
[Запуск, API, проверки и ограничения](../vampir-headless/LIVE-SESSIONS.md).

25 октября существующий персонаж `bot-hk-test@vampir.top` на Franz 2 вошёл
через HK в мир на 1.13.16: Login / Select / world result codes 0, серверная цель
получена. Проверены 120 секунд: 24 periodic Ping / 25 ответов без ошибок.
Сессия и тестовый транспорт закрыты; движение и квесты ещё не запускались.
[Текущий bounded профиль, проверки и живой результат](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-ENTRY-11316.md).

25 октября исправлен Game Login `bot-hk-test@vampir.top` через HK на Franz 2:
сервер вернул 0 и список с одним персонажем. Ошибочное условие старого SHA
исключало свежие I_ConnectIP / I_CountryCD из metadata 1.13.16.
Initial Ping также перенесён, но отдельно отказ не устранил. Выбор / world /
длительная сессия новой сборки ещё не подтверждены.
[Исправление, сравнение и границы вывода](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-GEO-FIX-11316.md).

Повторная проверка расположения: [по каждому окну и контролу](UI-GEOMETRY-TASKS.md).
Повторная проверка иконок, оформления и событий: [по каждому окну и контролу](UI-APPEARANCE-TASKS.md).
Блок портрета / HP / MP: [исходное дерево, реконструкция и оставшиеся runtime связи](UI-PLAYER-STATUS.md).

Прототип игрового интерфейса: [этапы, подзадачи и отметки выполнения](UI-TASKS.md).
Общая задача: [автоматический сборщик интерфейса по данным клиента](UI-BUILDER.md).
[Автоматизация разбора и подтверждённых проверок](UI-AUTOMATION.md): пакетный проход всех 635 UI вариантов.
Текущая фаза: [сканер характеристик и связей](UI-PROPERTY-SCANNER.md) и аудит
каждой характеристики; проверенные правила подключаются по готовности через
[единый конвейер](UI-PIPELINE.md), остальные характеристики остаются открытыми.
[Полнота свойств](UI-PROPERTY-COVERAGE.md) и [игровые данные / объекты карты](UI-GAME-DATA.md)
проверяются отдельными чеклистами в том же конвейере.
Рабочая локальная демонстрация: [запуск, покрытие и ограничения](ui-prototype/README.md).
В запрошенной проверочной пересборке добавлено [общее меню с исходными иконками](UI-MENU.md);
аудит неизвестных свойств остаётся открытым.
Отдельные окна и компоненты: [чекбоксы восстановления](UI-WINDOW-TASKS.md).
Приоритетный проход: [551 имя с заглавными UI](UI-NAMED-WINDOW-TASKS.md), со ссылками на те же UI-W чекбоксы.

Текущая цель пользователя — существующий персонаж `bot-hk-test@vampir.top`
на Franz 2, постоянная сессия и обработка команд движения с карты / из квестов.
24 и 25 октября через HK прошли NID / SDK / lobby и Game Version, но Game Login
вернул 16 до списка персонажей. Сессия в мире не открыта; туннель остановлен.
[Результат и условия продолжения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-HK-EXISTING-CHARACTER-11316.md).

Для отдельного тестового `bot-tw-test@vampir.top` код 37 на JP 251 расшифрован по текущим native dictionary pairs и RU
таблице: CreateRestrictedServer — создание персонажа недоступно на этом сервере.
16 подтверждён как InvalidState; причина отказа JP 256 остаётся неизвестной.
Четыре patch message компонента сверены: кнопки/root classes совпадают, девять
text exports изменились. [Доказательства и следующий шаг](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-MESSAGE-COMPONENTS-11316.md).
Свежий повтор JP 256 после паузы снова дал 16. Initial Ping не отправлен из-за
неперенесённого clock SHA; следующий игровой шаг — current clock/bootstrap
проверки, затем отдельный live эксперимент. Причина 16 пока не установлена.

Живая проверка текущего профиля 1.13.16 через HK прошла SDK, каталог и lobby.
Game Version принят на двух JP-серверах; Game Login вернул 37 (251) и 16 (256).
Свежего списка нет, персонаж не создан. Далее по уточнению пользователя сначала
компоненты окон и переводы, затем их связь с кодами. [Результаты и компоненты](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LIVE-CANDIDATE-11316.md).

По запросу пользователя проверен вход через HK: текущий SDK launcher sign-in
принят. Игровой этап остановился на `game_profile_source_changed`; персонажи
не запрашивались и не создавались. Приоритет — закончить игровой профиль и
повторить вход/создание. [Результат проверки](../vampir-headless/LIVE-HK-CHECK.md).

Текущий путь WaitingEndNotify → запрос ID 101 подтверждён в 24 native сценариях.
В ответе ID 102 проверены внешние поля и чтение счётчика: полный ответ с пустым
списком требует 38 байт. Поля CharacterRecord уже сверены с декодером в 128
сценариях с пустыми расширениями. Непустые коллекции внешности и optional map
также проверены отдельными компонентами, включая повторные ключи и коллизии.
Целый reader списка уже прошёл общий прогон на одной памяти: разные записи
сохраняют свои строки и коллекции, частичные ответы отклоняются.
Регистрация и handler ответа проверены отдельно в 101 сценарии. Пустой список
в native UI сохраняет index 0; это не наличие персонажа и не команда создания.
Далее — ограниченный source-bound профиль для отдельной живой проверки и
оставшиеся clock/transport/create checks.
[Инициатор](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-WAITING-END-11316.md),
[ответ и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-LIST-ENVELOPE-11316.md).
[Проверка записи персонажа](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-RECORD-11316.md).
[Непустые коллекции](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-EXTENSIONS-11316.md).
[Общий reader списка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-LIST-RECORDS-11316.md).
[Регистрация и handler](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-CHARACTER-LIST-HANDLER-11316.md).
Профиль текущей сборки ещё не активирован; живое создание не выполнено.

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

Входной буфер LoginResult теперь создают native concrete/base constructors:
72 проверки полей / ABI и общая цепочка чтения прошли без ручной записи cursor.
Далее — handler/dispatch; storage primitives остаются fixtures.
[Результат и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-BUFFER-11316.md).

Актуальный offline-план: [четыре выбранных направления](../vampir-headless/OFFLINE-PLAN.md).
LoginResult теперь исполняет native FString/std::string/UTF-8 input вместе с
числовым archive: 160 различных полных сценариев, границы 15/16 и 127/128,
короткие тела и cleanup. Storage primitives остаются fixtures; строгая локальная
UTF-8 policy сохранена. Далее — concrete input construction и handler/dispatch.
[Результаты и malformed limits](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-STRING-11316.md).

В LoginResult включены native числовые archive методы, raw IO и bool normalization:
320 полных случаев, 332 коротких префикса и 25 отказов прошли повторно.
FString/UTF-8 input, concrete buffer constructor и handler/dispatch ещё открыты.
[Реальный cursor/count и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-INPUT-11316.md).

Reader игрового LoginResult 1.13.16 привязан к ID 4 и проверен вместе с nested
constructors/readers: 320 полных случаев, 332 коротких тела и 25 отказов.
Archive primitives / UTF-8 пока fixtures; handler/dispatch остаются открыты.
[Привязки, поля и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-11316.md).

Metadata pipeline включён в целый Login на одной памяти: 448 сценариев проверили
проекцию в `+d8`, единый SDK manager и общий cleanup. Готовые exports использованы
повторно. Реальные SDK/string/map/variant boundaries и writer/results ещё открыты.
[Общая проверка и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-METADATA-11316.md).

Metadata Login 1.13.16 проверена целой цепочкой из шести функций: 288 сценариев,
33 связи полей UserInfo с ключами, условия включения и cleanup. Реальные SDK
значения и строковые primitives пока fixtures, целый Login ещё требует интеграции.
[Поля, источники и следующие обновления](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-METADATA-11316.md).

Login 1.13.16 теперь включает три native SDK getters и шесть leaf getters:
2 016 сценариев проверили cache branches, поля, lifecycle и ABI. Отдельно
закреплены 27 статических metadata key/consumer links; значения ещё не доказаны.
[Результат, источники для пресетов и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-SDK-11316.md).

Целые Login prepare / constructor 1.13.16 прошли 672 сценария с явными SDK
fixtures: проекция полей, отдельные gates, post-send уведомления, cleanup и ABI.
Проверка подключена к обновлениям; реальные SDK getters / result reader ещё открыты.
[Поля, границы и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-11316.md).

Selector / store / lookup теперь исполняются внутри whole Version prepare вместе
с Windows / CPU / NM / combiners: 288 сценариев. FName/type/resolver/value-at
сохраняют явные границы fixtures; whole Login prepare/results ещё открыты.
[Общая цепочка и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-PLATFORM-11316.md).

Объединение строк Version 1.13.16 проверено на 256 сценариях и 2 overflow;
native combiners включены в 64 whole prepare сценария с Windows / CPU / NM.
Context/platform в общей цепочке ещё fixtures, Login prepare/results остаются.
[Сборка поля, ownership и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-COMBINERS-11316.md).

Windows / CPU / NM включены в целый Version prepare: 64 сценария на общей памяти
проверили поля, cleanup и send 0 / 1. Context/platform и combiners ещё fixtures;
дальше их перенос и whole Login prepare / result readers.
[Доказательства интеграции и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-SYSTEM-11316.md).

Windows helper прошёл 48 native сценариев, CPU formatter / getters / trim — 72.
Дальше их интеграция в whole Version prepare и перенос Login; сеть не запускалась.
[Источники, fixtures и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-SYSTEM-11316.md).

Selector / store / lookup подготовки Version 1.13.16 прошли 116 native сценариев
с явными fixtures; whole prepare integration, Windows / CPU и Login ещё открыты.
[Доказательства и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PLATFORM-11316.md).

Далее сохранены результаты последовательных этапов. Формулировка «следующий шаг»
в старой записи относится к моменту её проверки; актуальный порядок — в плане выше.

Version NM provider / getter 1.13.16 исполнены в 36 сценариях cache / storage,
затем включены в 64 whole prepare сценария с initialized synthetic cache.
Реальные ключи не менялись; дальше platform/context и Windows / CPU helpers.
[Источники, fixtures и проверки обновлений](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-NM-11316.md).

Целые Version prepare / constructor 1.13.16 прошли 64 сценария проекции до
send и cleanup после него. OS/context/string getters ещё fixtures; их перенос,
Login prepare и result readers остаются до живой проверки игрового профиля.
[Адреса, границы и автоматизация](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-11316.md).

Native archive 1.13.16 проверен: 45 случаев primitives и 64 полных тела
Version / Login с реальными string / UTF-8 / archive methods. Байты совпали;
дальше preparation и result readers, runtime profile ещё не активирован.
[Связи, границы и автоматические проверки](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-ARCHIVE-WIRE-11316.md).

Полный string writer 1.13.16 прошёл 228 native сценариев с реальными UTF-8
helpers: NUL / count gate, inline / heap, возврат ошибки и cleanup.
Следующий пробел — native archive encoding; профиль игры пока не активирован.
[Проверка и автоматизация повторов](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-STRING-WRITER-11316.md).

Повторный launcher-вход JP-аккаунта после официального клиента принят SDK:
1203 не повторился, страна JP, регион GLOBAL. Статус панели — `sdk_created`.
Новый каталог бот ещё не запрашивал: игровой профиль 1.13.16 не прошёл guard.
[Живая проверка, границы и следующий этап](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-JP-SDK-RETRY-20261024.md).

Официальная JP-запись 24 октября дошла до каталога и выбора Evans 1 (261):
лобби приняло вход, Game Login четыре раза вернул 58. У бота прежний SDK 1203
возник раньше; два поля устройства совпали, HTTP-контекст скрыт TLS.
[Эталон, сравнение авторизации и следующая проверка](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-JP-LAUNCHER-CAPTURE-20261024.md).

24 октября `bot-tw-test@vampir.top` зарегистрирован в Netmarble через JP;
проверенный callback подтвердил страну JP. Повторный вход остановился на SDK
HTTP 400 / 1203 до каталога серверов; персонаж не создавался.
Другие почты остаются для Global EU без VPN, их регистрация не запускалась.
[Результат, сохранённая запись и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-JP-REGISTRATION-20261024.md).

Для 1.13.16 нативные UTF-8 length / conversion / encoder прошли 222 сценария,
включая повреждённые суррогаты и нехватку буфера. Готовые exports сохранены;
дальше — полный string writer и archive encoding.
[Адреса, границы и повторная проверка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UTF8-11316.md).

Для 1.13.16 исполнены целые Version / Login writers: 160 сценариев порядка
полей и отказов операций. Проверка включена в update; string / archive methods
пока fixtures, wire encoding и полный игровой вход ещё не подтверждены.
[Привязки, автоматизация и следующая проверка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-PACKET-WRITERS-11316.md).

Сверка сохранённой пары 1.13.14 → 1.13.16 подготовила отдельный launcher-профиль.
Финальный повтор занял 33,215 секунды без новых Ghidra / context replay;
38 пунктов очереди сохранены, игровой профиль не активирован.
[Отчёт, source-context Version / Login и ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RESUMABLE-UPDATE-11316.md).

Обновление поддерживает план без исполнения, продолжение сохранённого прогона,
пакеты явных exports и подготовку отдельного offline профиля. Готовность считается
по возможностям, непроверенные связи остаются в очереди.
[Команды и границы процесса](../resource-tools/vampir/knowledge/RESUMABLE-UPDATE.md).

Для поиска соответствий между сборками добавлены BinExport / BinDiff и передача
единственного кандидата в research `prepare`. Совпадения не подтверждают
совместимость автоматически; исходные Ghidra проекты открываются только для чтения.
[Команды, закрепление и проверенные границы](../resource-tools/vampir/knowledge/evidence/tools/HEADLESS-BINARY-DIFF.md).

Добавление exports теперь не требует повторного импорта всей базы: на этой
библиотеке 16,991 секунды против 66 секунд полного build, неизменный повтор
6,864 секунды. Это замер индексатора, не всего переноса игры.
[План автоматизации следующего обновления](../resource-tools/vampir/knowledge/UPDATE-AUTOMATION.md).

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

При завершении подключения подготовки SDK к панели установленный EXE изменился:
SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверки этого этапа относятся к прежнему SHA `98802d550890…`; совместимость
новой сборки ещё не подтверждена. Перед следующим живым входом сверить обновление.
