# Самостоятельный клиент Vampir

Клиент развивается для входа, удержания сессии, карты, параметров персонажа
и квестовых действий. Готовность каждого из этих контрактов проверяется отдельно.

[Обновление и запуск ярлыком](../resource-tools/vampir/knowledge/RESUMABLE-UPDATE.md)
готовят пакет следующего входа. Работающий owner сохраняет закреплённый пакет;
обновление не запускает вход и не отправляет игровых команд. Профили
`prepared-next` / `prepared:<SHA>` проходят проверку доказательств перед запуском.
Новый SHA без обязательных checks отклоняется, старый профиль не подставляется.

На последнем зафиксированном исследовании 1.13.22 подтверждены отдельные функции;
поддержка целого входа ещё не объявлена.
[Границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-11322.md).
Фактический текущий статус смотреть в журнале обновлятора и API owner;
прежний отчёт об онлайне не подтверждает существование соединения сейчас.

[Главный указатель](../vampir/README.md), [открытые пакеты](TASKS.md),
[панель аккаунтов](ACCOUNT-CONSOLE.md).

[Проверка обновлятора](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTOMATIC-UPDATE.md)
подтвердила повтор без нового native replay. Для подготовленного следующего
пакета используется явный профиль `prepared-next`; неполный вход отклоняется
до запроса учётных данных и сетевого соединения.

[Общий string writer 20 → 22](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-STRING-WRITER-11322.md)
прошёл 228 native сценариев и подключён к обновлению / кэшу. Это отдельный
offline пакет.
[Archive wire](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-ARCHIVE-WIRE-11322.md)
добавил 109 native сценариев. Preparation, framing, ответы и полный вход
продолжают требовать своих проверок.

[Version 20 → 22](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-VERSION-11322.md)
получил generic prepare и VersionResult / input buffer adapters, 191 новый native
случай. OS / SDK / helper values, response handlers и целый вход этим не допущены.

[LoginResult nested и native string/buffer input](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-INPUT-11322.md)
подключены к автообновлению: 232 + 506 native сценариев, точные матрицы и guards.
Общий повтор 19 drivers переиспользовал 57 этапов без JVM / native replay.
Этот input-пакет не включает handlers / registration / composition и целый вход.

[Continuation, ранние ошибки LoginResult и повтор публикаций](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-HANDLERS-11322.md)
подключены к автомату: 8 + 14 native сценариев. Общий повтор 21 drivers
переиспользовал 63 semantic stages и 21 publication receipts без JVM / native /
PE rebuild. Полный handler и композиция с reader описаны отдельными пакетами ниже.

[Общий result gate и post-state](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-RESPONSE-11322.md)
подключены к автомату: 16 полных gate + 227 indexed selections и 44 post-state
сценария. Общий повтор 23 drivers использовал 69 этапов и 23 публикации из кэша,
без JVM / native / PE rebuild. Это отдельный gate / post-state scope; интеграция описана новым пакетом ниже.

[Полный LoginResult handler и native gate](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-FULL-11322.md)
подключены к автомату: 48 сценариев над синтетическим пакетом 352 байта, включая
новые trailing predicate / apply / cleanup. Общий повтор 24 drivers использовал
72 этапа и 24 публикации из кэша без JVM / native / PE rebuild. Это standalone
handler scope; композиция с reader, регистрационный helper и контейнер описаны
ниже. Допуск онлайн требует собственного результата.

[Композиция native reader → handler](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-COMPOSITION-11322.md)
подключена к автомату: 77 сценариев над тем же packet 352 байта (48 полных,
28 отказов чтения, 1 tail). Общий повтор 25 drivers использовал 75 этапов
и 25 публикаций из кэша без native / JVM / PE rebuild. Прямой вызов handler
управляется координатором. Это самостоятельная композиция; native dispatch
проверяется отдельным интеграционным пакетом ниже.

[Регистрационный helper Login и окно привязки 18 → 22](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-REGISTRATION-11322.md)
подключены к автомату как `registration-v1` / `login-registration`. Полный helper
(101 инструкция, 395 байт) и настоящий ID 4 leaf исполняются отдельно от
статически проверяемого окна owner (75 байт). Клиент запрашивает для пакета 344 байта;
352 байта — размер области, зарезервированной прежними проверочными стендами,
а не размер запроса клиента.
34 native сценария и 602 теста прошли. Общий повтор 26 drivers использовал
78 этапов и 26 публикаций из кэша без native / JVM / PE rebuild
(77.785473 с). Реальные insert и name getter проверяются новым пакетом ниже.
Связь с native dispatch рассматривается отдельным пакетом; допуск онлайн отдельный.


[Реальная вставка, rehash и владение именем Login](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-CONTAINER-11322.md)
подключены отдельным `container-v1` / `login-container`: пять целых функций,
556 инструкций / 2087 байт и ID 4 leaf. Матрица содержит 120 сценариев:
68 constructor, 4 getter, 24 insert, 12 rehash и 12 совместных проверок.
Owner занимает 72 байта, контейнер — 64, node — 40; запрос packet 344 байта
отделён от проверочной области 352 байта. Native name getter заменяет insert
outpair строковым descriptor; cleanup освобождает новое имя, сохраняя
node / packet / handler. Storage reset / allocation / free / reserve, UTF-8,
logger и security сохраняют явные fixture-границы.
120 native сценариев и 655 тестов прошли. Общий повтор 27 drivers использовал
81 этап и 27 публикаций из кэша без native / JVM / PE rebuild
(93.517172 с). Связь с dispatch, TLS / archive cleanup проверяется отдельным
пакетом ниже; онлайн не подтверждён.

[Native dispatch / lookup, TLS и archive cleanup LoginResult](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-DISPATCH-11322.md)
добавлены как `dispatch-v1` / `login-dispatch`. Общая матрица — 107 native
сценариев над 29 целыми функциями и 12 leaves. Пакет связывает native создание
контейнера, lookup и dispatcher с reader → wrapper → handler / gate через
реальные vtable calls; Python не решает, вызывать ли handler после reader.
Исполняются TLS setter / reset и четыре cleanup leaf. Два paired reuse-сценария
сохраняют тот же owner и packet после success → отказа reader → неизвестного ID.

Для стенда заданы предусловия: frame не короче 5 байт, active packet и TLS
изначально нулевые. Это условия вызывающего кода; native dispatch не проверяет
короткий header. Owner занимает 80 байт с active packet slot. OS TLS provider,
heap / storage и игровые сервисы остаются fixtures; input UTF-8 исполняется
нативно, diagnostic UTF-8 сохраняет отдельную fixture-границу. Пакет не подтверждает
транспортное framing / integrity, SEH, весь вход или онлайн-сессию.
107 native сценариев и 701 тест прошли. Общий повтор 28 drivers использовал
84 этапа и 28 публикаций из кэша без native / JVM / PE rebuild
(81.942016 с).

[Post-state и continuation в native доставке LoginResult](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-STATE-FLOW-11322.md)
подключены как `state-flow-v1` / `login-state-flow`: 325 сценариев связывают
dispatch → reader → handler с исходными wrapper / getter / vtable reset.
Continuation singleton публикует native constructor; providers готовятся до
доставки, вход в handler их не перезаписывает. Допуск содержит 33 целые функции
и 14 leaves; standalone lookup уже доказан дочерним пакетом и здесь не повторяется.
Пять virtual-tail globals проверяются по PE span и ширине; backend / actor /
container helper effects сохраняют явные fixture-границы.
325 native сценариев и 773 теста прошли. Общий повтор 29 drivers использовал
87 этапов и 29 публикаций из кэша без native / JVM / PE rebuild
(150.653545 с). Все 5 экспортов исследования переиспользованы без JVM.

Native sender рассмотрен отдельным пакетом ниже; связь настоящего service
с writer / transport остаётся открытой. Version sender,
clock / heartbeat / world и current entry admission остаются открытыми.
Профиль, соединение и игровые команды этим offline пакетом не изменяются.

[Native sender и handoff подготовленного Login](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-SEND-HANDOFF-11322.md)
подключены как `send-handoff-v1` / `login-send-handoff`: 896 сценариев,
12 целых функций / 7 leaves. 224 различных prepared inputs объединены с четырьмя
pending states: 672 передачи синтетическому service sink и 224 подавления при hit.
Нативно исполняются lookup, timeout fallback и service getter; packet и UTF-16
строки сохраняют тот же указатель и содержимое. Пятый stack argument, точные
helper aliases и Win64 ABI проверены. Pending insert / delegate / service sink
остаются fixtures; source service vtable и сериализация этим не подтверждаются.

Проверки: 896 native случаев и 815 тестов. Общий повтор 30 drivers использовал
90 этапов и 30 публикаций из кэша без native / JVM / PE rebuild
(140.784932 с). Один missing sender export собран одной JVM
в готовом проекте; независимые parent suites не повторялись.

Исходный путь service singleton / vtable `+0x38` → writer и cleanup подтверждён
новым bounded native пакетом ниже. Последующие buffer и lifecycle пакеты
подтверждают свои ограниченные пути; реальный transport и полный онлайн-вход
ещё не допущены.

[Подготовка общего Login backend / wire стенда](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-BACKEND-WIRE-PREPARATION-11322.md)
закрыла недостающие source exports: publisher / backend / append / cleanup.
Машинный рецепт проверяет 29 whole roots / 13 returning leaves / 3 tail fragments,
готовые child proofs и таблицы точного SHA. Новый collector поддерживает исходный
cleanup tail; два готовых экспорта повторно не собирались. Матрица 1807 входов
и независимый byte oracle подготовлены и подключены к tooling checks.
Эта запись описывает этап статической подготовки. Общий native стенд и semantic
adapter завершены следующим пакетом ниже; онлайн-допуск этим не подтверждается.

[Native service / backend → Login writer / framing / cleanup](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-LOGIN-BACKEND-WIRE-11322.md)
подключены как `backend-wire-v1` / `login-backend-wire`: 1807 сценариев,
29 целых функций / 13 returning leaves / 3 tails. Исполняются source publisher,
один prepare / sender и исходная service thunk / backend цепочка до Login writer.
Наблюдались 1344 writer / transport captures, 448 pending hits, 6 fallback calls
и 444 sequence wrap. Packet / строки, raw flags alias, Win64 ABI и очистка outer →
inner до prepare destructor проверены. Backend binding, initial storage,
checksum / identity transform / transport effects остаются fixtures.

Проверки: 1807 native случаев и 902 теста. Общий повтор 31 drivers использовал
93 этапа и 31 publication из кэша без native / JVM / PE rebuild
(302.339482 с). Новых экспортов и JVM не было; готовые parent native
suites не исполнялись повторно. Полный онлайн-вход не допущен.

Integrity / cipher и bounded assignment / lifetime закрыты последующими
пакетами ниже. Общая композиция frame backend с native queue и реальная сеть
остаются открытыми.
Готовые native пути подготовки и wire переиспользуются по SHA / proof / cache.

[Настоящие CRC/XOR и native Login frame](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-FRAME-INTEGRITY-11322.md)
подключены как `frame-integrity-v1` / `frame-integrity`: 113 случаев,
16 целых функций / 9 returning capsules / 2 cleanup tails. Три primitive leaves
получены из source E8 anchors; проверяются инструкции и все 256 DWORD CRC table.
103 primitive сценария охватывают raw CRC state, width / signed length, fallback
и явные ключи, in-place / disjoint / unaligned. Десять direct backend entries
связывают native writer / archive / CRC / XOR / cleanup, включая paired reuse.
Prepared packet inputs синтетические и взяты из принятого parent report;
native prepare / SDK / sender / publisher в этой новой матрице не исполняются.

Проверки: 113 native случаев и 950 tooling тестов. Общий повтор 32 drivers
использовал 96 stages / 32 publications без native / JVM / PE rebuild
(236.979263 с). Прежние 1807 случаев и остальные parent suites
не повторялись. Новому integrity семейству хватило пяти готовых exports. Тогда source collect
assignment/lifetime/transport остановился на resize / unwind blocker; этот
blocker закрыт следующим buffer-transport пакетом ниже. Bounded lifetime
проверен отдельным service-lifecycle пакетом; реальная сеть и весь онлайн-вход
сохраняют открытые границы.

[Общий resize и native transport queue](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-BUFFER-TRANSPORT-11322.md)
подключены как `buffer-transport-v1` / `buffer-transport`: 65 сценариев /
95 последовательных шагов, 5 whole roots / 1 set-count leaf. Исполняются
полный chained-unwind growth, resize и оба потребителя — archive.raw и
queue.append / обычный transport wake gate. Проверены повторное использование,
нулевые байты, alignment / raw header, sizes, retirement, guards и Win64 ABI.
Allocator / free / CRT effects и wake callback сохраняют явные fixture-границы;
реальные socket delivery / drain и backend lifetime ещё не подтверждены.

Проверки: 65 native случаев и 1006 штатных тестов. Общий повтор 33 drivers
использовал 99 stages / 33 publications без native / JVM / PE rebuild
(177.023237 с). Готовые 113 CRC/XOR и 1807 backend/wire случаев
повторно не исполнялись. Source collect закрыл resize / unwind blocker:
17 missing whole functions получены одним JVM с обязательной coverage.
Следующий за buffer пакетом service-lifecycle ниже использует готовые source
links и exports для bounded assignment / constructor / refcount lifetime.
Связь frame backend с native queue требует отдельной новой матрицы.

[Native service / backend lifecycle](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-AUTO-SERVICE-LIFECYCLE-11322.md)
подключён как `service-lifecycle-v1` / `service-lifecycle`: 42 сценария /
84 poison-раунда, 12 whole roots / 1 source dispatch leaf. Исполняются publisher,
assignment, constructors, control move-release, native atomic transitions,
deleting, reset и ring cleanup. Размеры service / backend / control — 240 / 800 /
24 байта; прежний backend-wire scope на 784 байта не менялся. Проверяются
source writes, неизвестные allocator / stack bits, guards, ABI и конечные owners.
Service destructor оставляет +0x10 / +0x18 dangling; безопасный reuse не доказан.

Heap / vector / engine / registration / callback effects остаются fixtures.
Во всех сценариях `cleanup_find=end`; native unregistration не подтверждена.
Проверки: 42 native случая / 84 раунда и 1082 штатных тестов.
Тёплый общий повтор 34 drivers использовал 102 stages / 34 publications без
native / JVM / PE rebuild (118.639629 с). Новые exports и JVM не
требовались, готовые 1807 / 113 / 65 native suites не исполнялись повторно.
Следующий общий блок — композиция frame backend / writer / CRC-XOR с native
queue и lifecycle. Drain / socket / scheduler / concurrency и онлайн-вход
сохраняют отдельные границы; текущая сессия и next-profile не менялись.

[Выбранные исследования и стабильная публикация v2](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-INFRASTRUCTURE-V2-11322.md)
подключены к обычному `update --auto` через машинный recipe. Scoped admission
восстанавливает выбранные строки из SHA-checked report / receipt / pseudocode и
точного EXE, а frozen adapters получают отдельную проверенную SQLite.
Полная history этим не сертифицируется. Добавление descriptor больше не меняет
стабильный publication algorithm; выбранные inputs и final barriers сохраняются.

Прошли 1162 tooling теста. Повтор 34 drivers использовал 102 stages /
34 publications из кэша без native / JVM / native PE rebuild за 185,417547 с.
На 12 реальных exports scoped prepare занял около 4 с, finish — около 5 с;
результаты benchmark записаны в отдельную копию facts. Старый UTF-8 report
поддержан отдельным typed bridge без переписывания: повтор публикации — 1,190765 с.

Прежний v2 native repeat был медленнее v1; его продолжение — publication
memo v3 ниже. Предыдущие замеры сохраняются в связанных отчётах.
[Планирование ресурсов v2](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RESOURCE-PLANNING-V2-11322.md)
уже завершает обычные plan-only / resume: 15,5 и 15,3 с на readiness,
108 лишних historical scans пропущены, готовый архив проверен полностью.
Повтор inputs трёх реальных архивов не читает файлы заново; финальный SHA-барьер
обязателен. Первый отчёт содержит 1197 tooling тестов.
[Исправление путей Windows](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RESOURCE-WINDOWS-PATHS-V2-11322.md)
сохранило прежние ключи реальных архивов; новый итог — 1198 тестов, три пропуска
symlink из-за прав Windows. Case-alias и deterministic retarget проверки выполнены.
Полный update и онлайн-вход этим пакетом не подтверждены.
Полный `knowledge-index.py check` перед коммитом остаётся обязательным.
Текущая сессия и next-profile не менялись; онлайн-вход не подтверждён.

[Общий барьер владельца v3](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-OWNER-SCOPE-V3-11322.md)
сохраняет batch-результаты provisional до единой проверки всех использованных
файлов и sources после bundle preparation. Прошли 1218 tooling тестов;
102 этапа и 34 публикации использованы из кэша без native / JVM / PE rebuild.
Замер owner-v3 сохранял около 185 с; следующий publication memo v3
закрывает повторные child-report / tools проверки отдельным рецептом ниже.

[Publication memo v3](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-NATIVE-PUBLICATION-V3-11322.md)
подключён через машинный recipe. Точные квитанции v2 используются отдельным
bridge; новые guards и cache namespace сохраняют происхождение проверки.
Повтор 34 семейств — 104.879736 с, 102 этапа и 34 публикации из кэша,
без native / JVM / PE rebuild и новых квитанций. Прошли 1240 tooling тестов;
три прежних symlink-пропуска. Далее — полный ordinary update с ресурсами и
проверкой установленного клиента. Он пока не подтверждён этим замером.

## Сохранённые записи прежних этапов

Утверждения о версии, очереди и живой сессии ниже относятся к описанному этапу.
Они сохранены для ссылок и воспроизводимости; текущие действия задаёт инструкция выше.

<details>
<summary>Исторические результаты и прежние указатели</summary>

# Самостоятельный клиент Vampir

25 октября `candidate-11316` прошёл ограниченный вход существующего персонажа
`bot-hk-test@vampir.top` на Franz 2 через HK: Select 0, ID202/204/206 0,
серверный вектор получен. 120 секунд наблюдения — 24 periodic Ping / 25 ID17,
ошибок нет. После теста соединения закрыты. Движение и квесты не выполнялись.
ID110/206 nested остаются строгими historical parsers с проверкой конкретных
live bodies; весь формат новой сборки не объявлен подтверждённым.
[Профиль и границы результата](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-WORLD-ENTRY-11316.md).

25 октября на 1.13.16 через HK исправлен игровой вход `bot-hk-test@vampir.top`
на Franz 2: Game Login 0, список с одним персонажем. Geo-поля свежего GMC2
теперь включаются по текущему SHA независимо от guard TID. Initial Ping
проверен отдельно и подключён к явному кандидату; periodic heartbeat не расширен.
Выбор и вход в мир этой попыткой не проверялись.
[Причина ошибки клиента и результат](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-GEO-FIX-11316.md).

Текущая цель — удерживать существующего персонажа `bot-hk-test@vampir.top`
на Franz 2 и обрабатывать команды движения с карты / из квестов в той же сессии.
Проверки 24 и 25 октября на 1.13.16 через HK прошли SDK / lobby / Game Version,
но Game Login вернул 16 до списка. Вход в мир и движение не выполнены.
[Результат, границы и следующий шаг](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-HK-EXISTING-CHARACTER-11316.md).

Цель — вход, персонажи, позиция, перемещение и сценарии без запущенной игры.
Общий вход в проект: [README Vampir](../vampir/README.md).
Актуальный порядок работ: [TASKS.md](TASKS.md).

Добавлена [локальная панель аккаунтов](ACCOUNT-CONSOLE.md): отдельные игровые и
почтовые пароли под DPAPI, регистрация Netmarble с кодом из почты, выбор сервера
и персонажа, отключение аккаунтов и не более двух отдельных рабочих процессов.
Проверены 84 локальных теста и интерфейс. Свежий EU-каталог с названиями
12 серверов загружен через панель без VPN; Prelude 2 отображается у обоих аккаунтов.
Живая регистрация через панель и
одновременный вход двух аккаунтов в мир ещё не подтверждены.
Основной EU-аккаунт через панель получил Game Login 0 и одного персонажа;
назначение сохранено по ключу. Первая попытка входа в мир остановилась на NID,
последующий запуск получил серверную позицию и статус «В мире».
[Проверка EU-сессии и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-EU-ACCOUNT-CONSOLE.md).
Подтверждённые списки теперь хранятся по аккаунтам и серверам,
сохраняются после перезапуска и не очищаются ошибкой следующей авторизации.

В цепочке `probe-selected-game-login.py` можно явно выбрать `--direct`
вместо `--socks-port`; в Python API передать `socks_port=None`.
Этот выбор действует для NID, SDK, лобби и игры, без изменения маршрутов ОС.
Прямой вход в прежнее лобби проверен. Для региональных лобби добавлены
`--region EU`, `NA`, `SG`: тот же выбор применяется к CDN endpoint и свежему
серверному списку. Свежий EU-каталог подтвердил Prelude 2 / ID 384.
Game Version принят; Login вернул 59 / BlockedInfo до списка персонажей.
[Живой результат и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-GLOBAL-EU.md).
[Native selector и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-LOBBY-REGIONS.md).
[Прямой маршрут и результат](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GLOBAL-DIRECT.md).

Периодический Ping подключён явно. Новая JP-проверка после ID 206 прошла
20 секунд: четыре периодических Ping, пять ID 17, ошибок нет. Сокет и маршрут
закрыты. Длительная сессия, движение, карта и reconnect ещё не проверены.
[Проверки heartbeat и ограничения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-SESSION-KEEPALIVE.md).

В атлас подключён read-only слой сессии: live цель входа показана в мире 10010 /
Blood Pool. Вывод включается / выключается, «К персонажу» выбирает мир и центрирует
карту. Проверены 120 секунд сессии: 24 периодических Ping / 25 ID 17 без ошибок.
Маркер очищен после close, endpoint и маршрут закрыты. Это снимок цели входа;
непрерывное положение, живые сущности и движение ещё не подключены.
[Запуск, проверка UI и границы](../resource-tools/vampir/knowledge/evidence/maps/HEADLESS-MAP-SESSION.md).

## Текущее состояние

Явный `--read-quest-list` отправляет один диагностический ID 1801 с полями
0 / 0 после ID 206. Он требует наблюдение, не совмещается с подтверждением
обучения и не повторяет запрос после неизвестного результата. В живой проверке
HONOR JP получен ID 1802 code 100; успешного списка нет, смысл отказа неизвестен.

Живой ответ выявил ошибку прежнего decoder: настоящий constructor создаёт
PktItemChangeList по +0x40, а replay задавал PktQuestData. Прежний вывод о
полном списке с группами отозван. Исправленный decoder поддерживает верхние
квесты / assets и пустые item changes; непустые изменения явно отклоняются.
Настоящий constructor / reader проверен на 27 телах и 131 коротком префиксе.
[Исправление, живой отказ и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-LIST-CORRECTION.md).
[Фабрика пакетов и неизвестный штатный вызов](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-FACTORY.md).

Повторный вход через Redmi JP без отправки команды подтвердил сохранённое
изменение Tutorial 1001: raw0c / raw10 / state теперь 2 / 1 / 2 вместо 0 / 0 / 1.
Наблюдение 20 секунд прошло без ошибок; сокет и маршрут закрыты.
Это состояние обучения, выбор квеста и движение ещё не подключены.
[Повторный вход, поля ответа и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-PERSISTENCE.md).

Последняя живая проверка через новый Redmi M2006C3LG / JP прошла Login 0,
список / выбор и вход в мир с ID 206 code 0. После свежего ID 9905 сервер
принял одну команду обучения 1001 / 2: ID 9904 code 0, `accepted`.
Сокет и маршрут закрыты. Выбор квеста и автоматическое движение ещё не проверены.
[Живое подтверждение и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-TUTORIAL-ACK-ACCEPTED.md).

Добавлена явная диагностическая команда `--ack-initial-tutorial` в
`probe-selected-game-login.py`. Она требует `--read-world-start`,
`--read-world-finish`, выбора персонажа и `--observe-world-seconds`.
По умолчанию команда выключена. После успешного ID 206 и свежего ID 9905
этого соединения разрешена одна отправка ID 9903: tutorial 1001, step 2,
raw18 = 0. Локальный фильтр требует единственную запись 1001 со state 1,
raw0c 0 или 1, raw10 0 и flag false; возраст снимка — не больше 10 секунд.
Это диагностическая политика для наблюдавшегося начального состояния,
не воспроизведение неизвестного cached-поля Tutorial +0x50.

Очередь, полная передача кадра сокету и ответ сервера различаются. ID 9904
принимается как результат только после полной отправки и при совпадении
1001 / 2: code 0 — `accepted`, другой код — `rejected`. Ранний или чужой
ответ не подтверждает действие. Таймаут, обрыв и завершение наблюдения
при ожидаемом ответе дают `unknown`; повторной отправки нет, в том числе
для code 4223. Передача байтов сокету сама по себе не доказывает их обработку.

Локально проверена цепочка входа → ID 206 → ID 9905 → ID 9903 → ID 9904
через socketpair, а также частичная отправка, отказ, отсутствие ответа,
лимит очереди и очистка при обрыве. Живой сервер принял эту команду через
новый Redmi JP. Две прежние попытки через HONOR / Redmi JP остановились
на Game Login 58 / BlockedIp до отправки ID 9903.
[Сводки попыток и исправление диагностики каталога](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-LIVE-INITIAL-TUTORIAL-ACK.md).
[Отдельная проверка привязки и прямого канала Pixel](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-PIXEL-CHANNEL.md).
Подтверждение шага не является кликом QuestPanel_PanelTouch,
не выбирает квест и не доказывает запуск автоматического движения.
[Основание полей запроса](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-REQUEST-WRITER.md),
[ответа](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-RESULT.md)
и [начального перехода](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-TUTORIAL-STARTUP.md).
Проверки без авторизации и игровых действий:

```powershell
$env:PYTHONPATH='phone-exit/bots/vampir-shared;phone-exit/bots'
python -X utf8 -m unittest test_vampir_initial_tutorial_ack test_vampir_game_connection test_vampir_game_login_probe test_vampir_selected_game_login test_vampir_headless_send_drain.SocketPumpTests test_vampir_headless_send_b.OutboundStateTests
```

После замены телефонов 22 октября бот прошёл живые Login / список / выбор,
ID 204 → ID 205 → ID 206 code 0 через JP / TECNO TECNO KJ5n. Конечная серверная
целевая позиция получена; ошибки отсутствуют. Соединение и маршрут закрыты.
[Отчёт и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-WORLD-FINISH.md#живой-id-206-после-замены-телефонов).
Добавлен явный `--read-world-finish` вместе с `--read-world-start`,
`--read-character-list` и `--character-index`: после успешного ID 204 он
однократно отправляет ID 205 и ожидает полный ID 206. Это отдельная headless
политика подтверждения перехода без 3D streaming, а не исполнение engine callbacks.
Без нового флага прежняя остановка после ID 204 сохраняется.

`WorldEntryFlow.target_position` связывает мир из ID 204 с конечным вектором
из ID 206. Это серверная целевая позиция до коррекций движка; проекция на карту
и длительная готовность сессии ещё не подтверждены. При отказе, неверном ответе,
таймауте или закрытии приватные данные очищаются, повторной отправки нет.
Диагностический runner сохраняет только признак получения позиции, без координат.
[Native доказательства, локальные и живые проверки](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-RELEASE-WORLD-FINISH-POSITION.md).

Ниже — история предыдущих отказов и исследований; текущий результат смотреть
также в [главном README](../vampir/README.md).

Актуальное продолжение после обновления 1.13.14: compiled tag исправлен,
SDK / лобби / Game Version приняты на JP и HK; Game Login вернул 16.
Затем добавлен один ранний Ping из свежего ответа лобби и текущего UTC для
проверенного нового EXE. Локальный порядок Version → Ping → Login → список
проверен. Живая JP-попытка с Ping снова дала Login 16; получен ID 17. Отдельная
диагностика по запросу пользователя отправила список ID 101 после отказа Login,
но за 10 секунд ID 102 не пришёл. Полный предварительный обмен и периодический
Ping остаются открытыми. Временные маршруты закрыты.
[Источники, проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-CLOCK.md#подключение-первого-ping-к-runtime).

Предыдущие этапы:

NID / SDK и выбранное лобби проходят вход. Реальный список серверов разобран;
Game Version принят. Прежний NID flow дал InvalidState 16; новый launcher flow
через два JP-телефона и HK дал BlockedIp 58 на Franz 2 / ID 256.
После следующей замены телефонов launcher flow на новом JP дал InvalidState 16;
со вторым новым JP прямой транспорт не установился.
Запрос персонажей не отправлялся. Рабочая сессия бота пока не получена.

21 октября пользователь создал Okly на Franz 2 и вошёл в мир официальным
клиентом. После закрытия игры бот через тот же выбранный JP-телефон снова
получил InvalidState 16. Три ключа устройства совпали с текущим хранилищем
Windows; причину отказа это сравнение пока не установило.

В последних попытках выбранное лобби ответило 10036. Отдельный native mapper
связал его с IsInspect / техническими работами; этот отказ возникает до Game
Login и не объясняет прежний InvalidState 16. Свежая страна и частичная metadata
подключены, но их достаточность для игрового входа пока не проверена.

Есть bounded codecs и состояния для списка / выбора персонажа, потокового
приёма, отправки и смены ключа. Они проверены локальными/native-сценариями;
полная цепочка на сервере после успешного Game Login ещё не пройдена.

## Где продолжать

- [Вход и устройство](../resource-tools/vampir/knowledge/topics/auth.md).
- [Сеть и runtime](../resource-tools/vampir/knowledge/topics/network.md).
- [Персонажи и позиция](../resource-tools/vampir/knowledge/topics/characters.md).
- [Текущие вопросы](../resource-tools/vampir/knowledge/questions.json).
- [Правила и поиск по функциям](../resource-tools/vampir/knowledge/README.md).

Рunners `probe-selected-game-login.py` и связанные probes — исследовательские
проверки, не готовый автономный бот. Источники и актуальные ограничения
описаны в тематических страницах. Секреты — только во время запуска,
локальные профили не коммитить. Запуск live probe требует действующего
явно выбранного транспорта и свежих проверенных snapshots.

`--auth-flow launcher` явно включает NID credential → launcher/token →
launcher/sign-in. Автоматического fallback нет. [Реальная проверка](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

`--language-code 1` явно выбирает английский язык в Game Login.
`--lobby-context sdk-with-joined-country` передаёт совпавшую свежую страну SDK / NID;
`sdk-with-partial-metadata` дополнительно собирает подтверждённые поля
metadata из текущих источников. Это неполный набор, не копия старой авторизации.
Для проверенной сборки 1.13.14 добавлен постоянный I_TID самого бота:
Windows CoCreateGuid, проверенный native формат, локальное SQLite-состояние.
Он переиспользуется при следующих входах; TID установленной игры не читается,
её SaveGame не меняется. Живая JP-проверка: metadata 262 байта, SDK / лобби /
Game Version приняты, Game Login снова 16. Временный маршрут закрыт.
[Происхождение полей и сравнительные проверки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) содержит прежний полный README,
включая старые команды и результаты. Старые статусы не заменяют текущую сводку.

</details>
