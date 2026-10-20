# Самостоятельный Vampir — задачи

## H04-login-error-16: после замены выходов получен InvalidState

Свежие SDK / lobby / ID 104 приняты, прежний HK-аккаунт на JP 251 получил
Version 0 / Login 16 вместо 58. Native mapper подтвердил InvalidState;
добавлена русская ошибка, 13 проверок прошли. Новая почта и профиль устройства
не создавались. Сокеты / JP-транспорт закрыты. Далее — полный SDK / player
state и контекст Login до успешного входа, списка / выбора персонажа и позиции.
[Источники и границы](../resource-tools/vampir/HEADLESS-RESULT-ERROR-16.md).

## H04-connected-address: proxy hop отделён от игрового endpoint

Настоящий local endpoint getter → callback → Version проверены в пяти
native-сценариях. Runner использует SOCKS bound metadata; неизвестный адрес
кодирует пустой строкой. Через JP на том же server ID 251 снова Version 0 /
Login 58, send 641 / recv 94. 20 проверок прошли, сокеты / транспорт закрыты.
Далее — оставшиеся условия доступности сервера и полный контекст Login
до успешного входа, списка / выбора персонажа и позиции.
[Источники и границы](../resource-tools/vampir/HEADLESS-CONNECTED-LOCAL-ADDRESS.md).

## H04-server-country: SDK HK проходит проверку JP array50

15 native-сценариев связали SDK response field с настоящим country setter,
getters и полным predicate. Свежий SDK вернул HK; array50 всех JP 251–270
допускает эту страну. Добавлен фильтр и --server-list-only. 20 проверок прошли;
в реальной проверке игрового подключения не было, лобби / JP-транспорт закрыты.
Далее — оставшийся контекст соединения / Login и причина BlockedIp до входа,
списка / выбора персонажа и позиции.
[Источники и границы](../resource-tools/vampir/HEADLESS-SERVER-COUNTRY-POLICY.md).

## H04-server-entry-state: известное условие сброса проверено

Byte server+0x35 со значениями 2/3 сбрасывает оба сохранённых server ID;
256 native-сценариев прошли, selector исключает такие записи в заданном
регионе. Свежие JP 251–270 имеют значение 0, JP 251 снова вернул Login 58.
HK допускает JP по таблице, но полный country context ещё не проверен.
Array50 сравнивается с GetJoinedCountryCode. Далее — заполнение SDK country,
полный predicate и фактический допуск HK в JP до успешного Login / списка
персонажей. Сокеты и JP-транспорт закрыты.
[Подробности](../resource-tools/vampir/HEADLESS-SERVER-ENTRY-STATE.md).

## H04-server-region: явный фильтр перед игровым входом

Enum KR=1 / ASIA=2 / TW=3 / JP=4 и group+0x20 gate подтверждены native;
country tables совпали в двух PAK-извлечениях. Выбор JP больше не попадает
на прежний KR-сервер 101. Свежий JP server ID 251 получил Version 0 / Login 58;
сокеты и транспорт закрыты. 16 проверок прошли. Далее — SDK gameRegion /
UseNetmarbleJoinedCountry и оставшийся контекст Login до успешного входа.
[Источники](../resource-tools/vampir/HEADLESS-SERVER-REGION-SELECTION.md),
[проверка](LIVE-GAME-LOGIN.md).

## H04-login-error-58: подтверждён BlockedIp

Native mapper 58 → BlockedIp и статическая локализация связаны; runtime
показывает понятную ошибку, не повторяет вход. 11 проверок прошли.
Через другой, подтверждённый JP-маршрут server ID 101 снова вернул 58,
Version 0, body 131 байт; транспорт закрыт. Причина ограничения не доказана.
Далее — UseRegion / UseNetmarbleJoinedCountry и их потребители в контексте
SDK / выбранного сервера / Login до успешного входа и персонажей.
[Расшифровка](../resource-tools/vampir/HEADLESS-RESULT-ERROR-58.md),
[реальная проверка](LIVE-GAME-LOGIN.md).

## H04-live-game-login: получен ответ с кодом 58

Свежая цепочка SDK → лобби → ID 104 → server ID 101 → игровой Version 0
дошла до LoginResult 58 на том же сокете. Body 131 байт полностью разобран;
send 650 / recv 94. Это отказ, а не успешная игровая сессия. Причина 58
пока неизвестна. 35 проверок прошли, сокеты / HK-клиент закрыты.
Далее — источник кода / причины отказа до успешного входа и персонажей.
[Подробности](LIVE-GAME-LOGIN.md).

## H04-login-initial-context: начальная Windows SDK-ветвь подготовлена

Actual wrapper constructor → пустая строка +0x100 → Login+0x88;
policy constructor / vtable slot +8 → byte 7 → Login+0x124.
Три native-сценария и явный runtime builder; дополнительный uint32 +0x50
принимается отдельно от server ID. Прошли 15 проверок. SDK / lobby данные
ещё нужно передать в памяти до Version → Login на одном игровом сокете,
затем — список / выбор персонажа. Новых сетевых попыток нет.
[Подробности](../resource-tools/vampir/HEADLESS-LOGIN-INITIAL-CONTEXT.md).

## H04-login-policy: getters и конструкторы проверены

Login bytes +0x124 / +0x130 / +0x131 проверены в 43 native-сценариях.
Режим после constructor равен 0; policy+0x18 constructor не заполняет.
Начальная metadata остаётся пустой при отсутствии manager+0x48.
Найдена запись uint32 +0x50 через `_wtoi` в BeginGame, но контрол и его
текст ещё не связаны. Четыре новые проверки прошли. Далее — policy writes,
wrapper+0x100 и оставшиеся входы до реального игрового Login / персонажей.
[Подробности](../resource-tools/vampir/HEADLESS-LOGIN-POLICY-INPUTS.md).

## H04-live-game-version: игровой сервер принял Version

Получен ID 2 с кодом 0 после свежего SDK / lobby входа и списка ID 104.
Endpoint выбран из свежей записи server ID 101 / group ID 1; обмен —
199 / 25 байт. Явная политика lowest-valid-id служит только диагностике,
наличие персонажей и доступность сервера она не устанавливает.
20 целевых проверок прошли; сокет / HK-клиент закрыты. Далее — оставшиеся
поля Login и обмен Version → Login на одном соединении, затем персонажи.
[Подробности](LIVE-GAME-VERSION.md).

## H04-game-endpoint: record → master value → transport связан

Server key берётся из ID 104 record+0x0c; host+0x20 / port+0x30 проходят
copy slice master model и BeginGame до ConnectToServer. 16 native scenarios
на одной машине подтверждены; полный master Update остаётся вне replay.
Runtime получил явный выбор по server ID с проверкой endpoint, без выбора
по порядку массива. Десять целевых тестов прошли. Далее — свежий список,
выбор ID и реальный игровой Version / Login → персонажи / позиция.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-RECORD-ENDPOINT.md).

## H04-live-server-list: ID 104 разобран в реальной сессии

Через HK получены ID 2 / 4 / 104 с кодами 0. Полный decoder ID 104 разобрал
55 групп / 98 server records, body 11 338 байт. Native whole reader проверен
на десяти bodies с непустыми collections; runtime учитывает общий item budget.
Запрос списка необязателен, отправляется после успешного Login. Сокет / HK
закрыты; 29 целевых проверок прошли. Далее — record → endpoint / выбор
сервера → игровой Version/Login → список/выбор персонажа → позиция.
[Подробности](LIVE-LOBBY-SERVER-LIST.md).

## H04-live-lobby-login: настоящий LoginResult с кодом 0

Явная source-supported ветвь SDK auth без NID UserInfo принята лобби через HK.
Свежий SDK SignIn → LobbyVersionResult 0 → LobbyLoginResult 0, body 90 байт;
send 460 / recv 123. Kind 0 — локальная политика клиента, server ID 0 связан
с constructor. Полная metadata остаётся дополнительной ветвью, а не условием
проверенного SDK-входа. Прошли 27 проверок. Сокет / HK-клиент остановлены.
Далее — запрос / decoder списка серверов ID 103 / 104 → игровой endpoint →
игровой вход → список / выбор персонажа → позиция.
[Подробности](LIVE-LOBBY-LOGIN.md).

## H04-lobby-login-preparation: числовая ветвь и raw byte проверены

Preparation / constructor / selected-server getter исполнены до sender:
16 сценариев, Version flag false. Byte +0x80 равен 7; +0x6c остаётся 0,
platform / kind / server ID передаются по проверенным правилам.
Windows builder требует явные kind / server ID / metadata, не выбирает
неизвестные начальные значения. 18 целевых проверок прошли. Далее — источник
kind / server state в runtime и полная metadata, затем настоящий LobbyLogin.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-PREPARATION.md).

## H04-lobby-login-inputs: body и пять строк SDK / NID связаны

LobbyLogin body: шесть строк, четыре uint32, raw byte; 24 полных native writer
cases совпали с runtime encoder. Binder заполняет player ID / SDK token /
NMDeviceKey / joinedCountryCode / NID без перезаписи конфликта. Страна
связана с UserInfo +0x170. Collector использует 27 обращений к 26 ключам;
полный metadata / numeric context остаётся открытым. Далее — завершить
эти входы, связать LobbyLogin с Version и получить ответ / список серверов.
Реальный LobbyLogin в этом этапе не отправлялся.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-WRITER.md).

## H04-live-lobby-version: первый настоящий ответ лобби

LobbyVersionResult получен через HK: ID 2, code 0, body 23 байта; send 94 /
recv 28. CDN parser и connect связаны на одних globals в 20 native cases.
В новом probe исправлена ошибочная настройка ReceiveStream: lobby offset 0,
game offset 3. Прошли 36 целевых тестов; socket / HK-клиент закрыты.
Это только версия протокола. Далее — SDK LobbyLogin и decoder списка
серверов ID 104, затем игровой вход → список / выбор персонажа → позиция.
[Подробности](LIVE-LOBBY-VERSION.md).

## H04-lobby-connect-flow: порядок Version и flush подтверждены отдельно

Восемь native wrapper cases подтверждают Version перед исходным запросом
при state 2. Четыре connected callback cases проверяют перенос pending bytes,
clear и сохранение sequence. Двенадцать native кадров Version / ServerListRead
совпали с новыми runtime frame encoders. Это ещё не общий connect lifecycle:
state / preparation / lower send / queue представлены fixtures или captures.
Connect читает globals 0x14b520cd0 / 0x14b520cb0; применение CDN к ним
ещё не доказано. Далее — config handoff и подготовка / connect / очередь
вместе, затем decoder ID 104 и реальный игровой endpoint.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-CONNECT-FLOW.md).

## H04-lobby-handshake: отдельные Version и запрос списка серверов

ID 1 / 2 у LobbyVersion отличаются схемами от игровых Version. Найдены
ID 103 / 104 списка серверов, два sender callers и таблица RdLobbyPeer.
Два writer / VersionResult reader проверены: 20 bodies, четыре ответа,
23 коротких префикса; добавлены отдельные bounded runtime codecs.
Полный ID 104 reader пока только экспортирован; его коллекции не перенесены.
Далее — connect / flush send-A и полная preparation перед сетью,
затем decoder списка серверов и настоящий игровой endpoint.
[Источники и границы](../resource-tools/vampir/HEADLESS-LOBBY-HANDSHAKE.md).

## H04-lobby-login: отдельный ответ и два поля для игрового Login

Подтверждены Lobby Login → send-A и отдельный ServerListReadResult handler →
master model Update. Полный LobbyLoginResult body проверен native reader:
семь полных ответов и 72 коротких префикса. Runtime decoder учитывает отдельный
lobby context; binder переносит две строки в Login+0x10 / +0x20, отклоняет
ошибку / пустые значения / конфликт. Все 19 целевых тестов прошли.
Далее — lobby connect / первое сообщение, bindings и decoder списка серверов.
Реального ответа лобби и игрового endpoint пока нет.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN.md).

## H04-version-probe: callback найден; игровой endpoint ещё не установлен

Локальный IPv4 без порта и начальные key / sequence 0 подтверждены по коду
клиента. Ограниченный Version probe прошёл пять новых тестов; 20 смежных
runtime-тестов также прошли. Одна диагностическая отправка к CDN-лобби
через HK: 199 байт отправлено, 0 получено, timeout. Роль этого адреса для
игрового Version не доказана; CLI требует явный диагностический режим.
Login не отправлялся. Далее — lobby context и загрузка игровых server records,
затем настоящий игровой Version / Login. [Подробности](VERSION-PROBE.md).

## H04-base-profile-lobby: AppVersion выбран явно, TCP лобби доступен

Добавлен явный recovered-base профиль для собственного клиента, с проверкой
текущего EXE / PAK / snapshot / INI и row provenance. AppVersion 1.12.14
переносится в два доказанных поля. Свежий CDN получен через HK; один TCP connect
к его лобби успешен, recv timeout без данных. Пакеты / credentials не отправлялись.
16 тестов прошли; HK-клиент остановлен. Далее — callback string Version,
игровой server record и прочие Login inputs. Native active cache не заявляется.
[Подробности](GAME-SOURCE-PROFILE.md).

## H04-observed-cpu: реальные CPU inputs доступны владельцу Version

Собран маленький собственный DLL helper CPUID. Adapter проверяет build receipt
и SHA до загрузки, наблюдает CPU / Windows version и заполняет только два
проверенных поля явного Version template. Реальные значения не логируются.
Повторная сборка воспроизводима в текущем workspace; 19 тестов прошли.
До сетевого входа остаются AppVersion / config, соединение и другие Login
inputs. [Подробности](WINDOWS-SYSTEM-INPUTS.md).

## H04-version-input-binding: два поля Version связаны с проверенными источниками

CPU text подтверждён полной native цепочкой на девяти сценариях. Source
ENnOsType form 2 проведён через factory argument loads, virtual setter
и lookup до Windows. Runtime helper заполняет только +0x28 / +0x38,
отклоняя конфликт с шаблоном. Остались наблюдение CPU и другие реальные
Version / Login inputs. Игровой запрос пока не отправляется.
[Подробности](../resource-tools/vampir/HEADLESS-VERSION-CPU-STRING.md).

## H04-windows-context: наблюдённая версия Windows подключена к NID

Native suffix getter: семь сценариев; формат major / minor / build /
productType / suiteMask / 64bit. Runtime читает GetVersionExW без fallback;
реальный SDK SignIn через HK с новым osVersion успешен. Найден ENnOsType,
selector и lookup проверены на 12 сценариях. Остались actual scoped flag,
полная обработка CPU-строки и другие Login inputs до игрового запроса.
[Детали](../resource-tools/vampir/HEADLESS-VERSION-WINDOWS-CONTEXT.md).

## H04-game-inputs: восстановлены CPU inputs и статические globals

Initializer CPU и два getter исполнены на четырёх native fixtures. Уточнены
compiled tag / DWORD, AppVersion zero-fill и selector Windows → 3. Полный
runtime template ещё не строится: platform context, Windows suffix и другие
Login inputs требуют источников. Далее — их проверка, подключение к лобби
через HK и игровой Version / Login. [Подробности](../resource-tools/vampir/HEADLESS-GAME-LOGIN-INPUTS.md).

## H04-hk-account: регистрация и SDK-вход пройдены

По последнему поручению пользователя создан отдельный ящик bot-hk-test@vampir.top.
Во встроенном WebView2 через HK пройдены условия без маркетинга, письмо,
пятизначный код и пароль. NID callback вернул HK. Затем отдельно приняты
SDK SignUp с player ID и SignIn с player ID / SDK token. Игра не запускалась,
ключи устройства не менялись, серверное подтверждение не объявлялось пройденным.
Далее — реальные поля Version / Login, подключение игрового сокета через
выбранный выход и lifecycle списка персонажей. [Подробности](NID-REGISTRATION.md).

Разделы ниже сохраняют результаты предыдущих этапов, включая отказы UA-аккаунта.

## H04-socks-route: NID / GMC2 / SDK используют один HK-выход

Добавлены явный --socks-port, remote DNS / TLS и проверка маршрута снимка.
Свежий GMC2 подтвердил HK; NID callback получен. SDK SignUp через HK дважды
вернул 1602. Диагностика: NID joinedCountryCode UA, SDK body HK, сообщение
`not allowed country for game`. Смена страны аккаунта не выполнялась.
Пользователь выбрал готовый аккаунт для сравнения; ожидаются его почта и вход
через штатное окно. Новый ящик не создаётся. SDK-игрок и персонаж пока не получены.
31 тест и smoke прошли. [Подробности](SOCKS-ROUTE.md).

## H04-sdk-first-player: новый SDK-игрок отклонён по стране

SignIn 1203 сопровождается `not exist player channel`. Найдены SignUp и callback,
тело проверено четырьмя native-сценариями. Явный `--create-sdk-player` не является
автоматическим fallback. Две реальные попытки получили HTTP 400 / 1602:
`not allowed country for game`. Игрок не создан, последующего SignIn нет.
Далее — источник service settings countryCode, сравнение с текущей версией
и доступом игры из сети пользователя; затем SDK-регистрация и игровой вход.
Пользователь подтвердил необходимость JP/HK. Через доступный HK-выход Phone Exit
проверен HTTPS по локальному SOCKS: loc=HK. Клиент остановлен штатно.
Далее — общий маршрут NID / GMC2 / SDK через этот выход, затем повтор SDK SignUp.
Сам бот пока использует прежний прямой HTTP; его регистрация через HK не проверена.
[Источники и проверки](../resource-tools/vampir/HEADLESS-SDK-SIGN-UP.md).

## H04-nid-sdk-live: NID callback получен, SDK sign-in отклонён

После создания аккаунта выполнены две попытки встроенного входа: обе прошли
парсер callback и дошли до SDK POST. Ответ — HTTP 400; вторая попытка дала
числовой errorCode 1203. Значение кода не установлено, SDK-сессии нет.
Добавлена однократная отправка штатной формы с явным паролем из stdin.
14 целевых тестов и smoke прошли. Следующий шаг — установить источник
отказа и проверить фактические поля SDK-запроса; затем игровой Login и список.
[Подробности](NID-SDK-RUNNER.md).

## H04-nid-sdk-runner: аккаунт создан, нужен вход в контексте бота

Runner проверяет источники и устройство, открывает NID и после callback
выполняет один ограниченный SDK POST. 11 тестов прошли. Окно запущено,
реального callback и SDK response пока нет. В Chrome приняты обязательные
условия с разрешения пользователя; маркетинг отключён. Письмо получено по IMAP,
код принят. Отправка заполненной формы с заданным пользователем паролем
завершилась Account Registration Complete и переходом в личный кабинет
с тестовой почтой; Services In Use 0. Далее — NID callback в контексте бота,
SDK response и игровая сессия. Создание персонажа этим не подтверждено.
[Подробности](NID-SDK-RUNNER.md).

## H04-nid-browser: отдельное окно и приём callback готовы к проверке входа

WinForms / WebView2 host передаёт результат Python parser через pipes,
отменяет внешние URI / popups и не меняет системные protocol handlers.
SDK DLL закреплены вне Git. Smoke проверил synthetic callback, две отмены
и popup; восемь unit-тестов прошли. Далее — согласованные реальные настройки,
вход / confirmation в штатном окне и SDK sign-in с полученным credential.
Android host и реальный аккаунт не проверены. [Подробности](NID-BROWSER.md).

## H04-nid-web-url: URL первоначального входа готов в ASCII-профиле

Весь encoder исполнен на 99 профилях; runtime использует уже проверенный
общий escape. Контекст связывается с authWebViewUrl из SDK constants.
Не заявляется native map iteration / Unicode parity. Далее — активные
значения настроек, окно авторизации и перехват callback внутри бота,
без вызова системного handler установленной игры; затем SDK sign-in.
[Источники и границы](../resource-tools/vampir/HEADLESS-NID-WEB-URL.md).

## H04-nid-web-context: десять базовых параметров установлены

Native сборка восьми профилей и webViewType для всех 256 значений проверены.
Общий helper готовит параметры signin с NID key и gate confirmation required.
Далее — encoding helper `0x141c13850`, query serializer `0x144586a30`,
полный authWebViewUrl и доставка результата окна в бот без запуска игры.
Не считать provider credential SDK-токеном или готовой игровой сессией.
[Источники и границы](../resource-tools/vampir/HEADLESS-NID-WEB-CONTEXT.md).

## H04-windows-identity: три наблюдённых ключа получены

SDK DeviceKey, NID DeviceKeyForNetmarbleId и NMDeviceKey прочитаны из точных
HKCU-путей, сохранены с provenance в локальном основном профиле. Confirmation
unknown; серверная привязка и активный SDK cache не доказаны. Добавлены reader
без генерации и prepare_registered_login с остановкой при required.
20 тестов прошли. Далее — NID / SDK credential, свежий SDK response,
оставшиеся поля пакетов и реальный вход. [Подробности](WINDOWS-IDENTITY.md).

## H04-runtime-context: NMDeviceKey связан с обоими пакетами

Доказаны getter и поля `Version+0x48` / `Login+0x78`; общий helper переносит
ключ в обе строки, отклоняя конфликт контекстов. Отдельный helper связывает
SDK accessToken и Netmarble ID с Login, не используя player ID вместо NID.
Реальная запись NMDeviceKey в Windows существует, но её связь с аккаунтом
не установлена. Основная SDK-пара / NID identity в реестре бота ещё пусты.
Далее — согласованный device / SDK context и оставшиеся входные поля.
[Подробности](../resource-tools/vampir/HEADLESS-VERSION-DEVICE-INPUT.md).

## H04-runtime-login: Version → Login связаны с сокетом

Добавлены полный ID2 decoder и bootstrap из явных payload в общем runtime.
ID2 code 0 ставит ID3; ID4 code 0 сохраняет ответ без автоматического списка.
31 тест прошёл, включая 43 native-кадра и смену ключа через socketpair.
Далее — фактические Version / SDK / device inputs, событие входа в выбор
и реальная сессия с подтверждением устройства. [Границы](LOGIN-FLOW.md).

## H04-runtime-connection: сокет и обработка ключей связаны

Владелец уже подключённого сокета объединяет receive / outbound / selection,
ID11 → ack ID12 → новый ключ и закрытие при ошибках. Девять новых и 23
прежних локальных теста прошли. Далее — Version / Login, обязательные handlers,
фактическое событие входа в выбор, SDK / устройство и реальная сессия.
Автоматический reconnect и heartbeat пока не готовы. [Подробности](GAME-CONNECTION.md).

## H04-runtime-receive: приём кадров и локальная цепочка через сокет

Добавлен stream двух уровней с готовой распаковкой, receive-B, лимитами
работы / памяти, явным ключом каждого пакета и EOF. 11 новых и 21 прежний
тест прошли; локальный socketpair связал ID101 / ID102 / ID109 / ID110.
Далее — владелец сокета, ключи и обязательные пакеты, фактический lifecycle
входа в выбор, SDK / device context и реальная сессия. Синтетический сервер
не подтверждает совместимость с сервером игры. [Подробности](RECEIVE-STREAM.md).

## H04-runtime-selection: очередь и состояние списка / выбора

В общем runtime добавлен flow ID101 → ID102 → явный выбор → ID109 → ID110.
Один ожидаемый запрос, отдельное разрешение lifecycle, текущий rawF0, лимиты,
таймаут и закрытие очереди при ошибке / разрыве. 12 новых и 15 прежних тестов
прошли; 19 native-кадров совпали. Мир и позиция не объявляются готовыми.
Далее — владелец сетевого соединения, фактическое событие входа в выбор,
SDK / device context и реальная сессия. [Подробности](SELECTION-FLOW.md).

## H09/H10: игровая оболочка и отключаемое отображение

Согласованное направление: игровые меню и действующие кнопки вокруг
существующей 2D-карты вместо 3D-сцены. Показывать живое перемещение, квесты,
цели персонажа и атакующих его мобов по проверенным сетевым данным.
Использовать найденные ресурсы UI и масштаб; отключать визуализацию и слои
независимо от сессии и сценариев. Экономию ресурсов проверить замерами,
в том числе на Android. Подробности и ссылки: [INTERFACE.md](INTERFACE.md).
Это направление будущих этапов, сейчас продолжать H04/H05.

## H09/H10: продолжать существующую карту

Уточнение пользователя 20 октября: основой карты бота служит уже созданный
атлас с сеткой перемещения, квестами, NPC, переходами, добычей и другими слоями.
Перед реализацией H09/H10 прочитать [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md)
и [MAP-SERVER.md](../vampir/MAP-SERVER.md), проверить существующие просмотрщик,
навигационные данные и проверки. Дорабатывать их для живой позиции и выбора
цели; компактные данные runtime выделять из уже извлечённой библиотеки.
Сначала сверить SHA, привязку координат и возможность движения по маршрутам.
Сейчас продолжать H04/H05 — сетевой вход и состояние персонажа.

## H04-selected-player-record: перенос ключа и lookup проверены

Статически связан конструктор объекта с парой `manager+0x38/+0x40`, которую
читает обработчик ID110. В 20 сценариях настоящий lookup / find / accessor
сохраняет найденную запись в `player+0x138`; проверены коллизии и промахи.
Getter реестра, виртуальная таблица игрока и остальные backend остаются fixtures.
Продолжить с регистрации / parser таблицы и настоящих методов объекта.
Не назначать `main+0x30` семантику `World.Id` без подтверждения. Продолжение
состояния 1, устройство, реальная сессия и мировая позиция остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SELECTED-PLAYER-RECORD.md).

## H04-select-option-send: дополнительная отправка установлена

Производный `+0x60` готовит PktOptionSet / ID1782 при изменении значения,
подходящих метаданных и готовом транспорте. 10 сценариев, шесть wire-профилей
и три теста подтвердили условия и тело. Сокет и ответ сервера не проверены.
Не искать в этом вызове ID201 по номеру слота; вернуться к остальным действиям
ID110 и потребителям состояния 1. Вход, устройство и мировая позиция открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-OPTION-SEND.md).

## H04-select-derived-manager: переопределение после ID110 проверено

Найдены allocating factory, производная таблица и настоящий слот `+0x58`.
18 сценариев подтверждают дополнительные действия после ID110; прежняя
базовая таблица не покрывала их. Слот применения `+0x60` ещё перехвачен.
Продолжить с роли реестра и пакета в этом слоте, не назначать ему ID201 по
номеру слота. Проверить другие источники продолжения состояния 1.
Реальный вход, устройство и мировая позиция остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-DERIVED-MANAGER.md).

## H04-select-post-manager: продолжение после ID110 проверено

Настоящие constructor / getter / value setter / slot `+0x58` / refresh связаны
с ID110 в восьми сценариях. Обход 205 записей и callback gates проверены;
типы получателей и их реальные callbacks ещё не установлены.
Продолжить с регистрации получателей и других потребителей состояния 1.
Не считать ID201 обязательным после выбора: эта связь пока не доказана.
Реальный вход, устройство и мировая позиция остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-POST-MANAGER.md).

## H04-world-load-predicate: LevelPath определяет смену уровня

Настоящий слот `+0xa8` получает два LevelPath через lookup World и сравнивает
их с ASCII-приведением регистра. Проверены 101 сценарий, текущие строки таблиц
и композиция с обработкой ID204. Выбор класса уровня / loader не исполнялись.
Продолжить с инициатора резервирования после ID110 и отправки ID201–203.
Вызовы сервисных слотов `+0x60/+0x68` искать по связям, прямые E8-вызовы
методов существующим scanner не найдены. Устройство, реальный вход и позиция открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-LOAD-PREDICATE.md).

## H04-world-start-pipeline: ID204 передан в сервис

Настоящие reader → handler → фильтр → сервис исполнены вместе в 35 сценариях.
Проверены перенос данных и условия вызова ID205, включая 5 → 2 → 5 в отдельной
транспортной ветви. Внешние предикаты и границы загрузки заданы тестом.
Продолжить с `0x145dc0830`, инициатора ID201 после ID110 и отправки ID201–203.
Мировая позиция, устройство и реальная сессия остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-MOVE-START-PIPELINE.md).

## H04-world-start: тело ID204 разобрано

Общий decoder сверяется с настоящим reader: 24 полных тела, 30 коротких
префиксов, enum / bool / вектор и строгое потребление тела. Статически
проверен путь ответа резервирования через слот сервиса `+0x68` к ID203.
Продолжить с ID204 reader → handler → сервис, затем инициатора ID201 после
ID110 и отправки ID201–203. Параметры загрузки, класс уровня, устройство,
реальная сессия и мировая позиция остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-MOVE-START.md).

## H04-owner-provider: фабрика GameInstance проверена локально

Регистрации GameInstance / RdGameInstance и их таблицы связаны со слотом
`+0x3d0`. Восемь полных native-сценариев проверили путь валидного класса по
умолчанию до границы создания и возврат её результата. Настоящий метод
`+0x3e0` исполняется; получение WorldSettings и создание представлены границами.
Loader в этом пути не вызывается.
Продолжить с параметров загрузки после ID110 и значения `DefaultGameMode`
в данных нужного уровня. Ветви `GAME=` / fallback пока проверены только статически.
Устройство, реальный вход и мировая позиция остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-OWNER-PROVIDER.md).

## H04-owner-resources: классы владельцев установлены

Текущие cooked superclass и native-регистрации связывают четыре класса GameMode
с уже проверенными конструкторами и слотами ID101 / ID205. Найдены две записи
указателя `world+0x158`, но полный путь создания / выбора класса не исполнен.
Продолжить с provider `world+0x1d8`, фабричного слота `+0x3d0` и данных уровня.
Мировая позиция, контекст устройства и реальный вход остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-OWNER-RESOURCES.md).

## H04-owner-dispatch: вызов через поле объекта проверен

`0x14430da70` → `object+0x158` → настоящий owner slot `+0x7b0` → ID205
проверен на 45 сценариях. Подстановка поля тестовая; реальный выбор класса
не доказан. Продолжить с записи `+0x158`, происхождения класса и связи уровня
с выбранным персонажем. Не переносить эмуляцию движка в runtime бота.
Мировая позиция, SDK/device context и реальный вход остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-OWNER-DISPATCH.md).

## H04-world-finish-owner: локальный путь 1 → 4 → ID205 найден

Конструкторы владельцев с policy 3 → slot `+0x7b0` → service `+0x80`.
При наличии мира настоящий `0x14561b390` пишет 4; явно вызванный callback
`0x143642370` → service `+0x70` → ID205 и состояние 5. Движок callback не запускал.
Продолжить с источника вызова owner slot `+0x7b0`, связи уровня/класса с ID110
и ветви actor movement `0x14561b390` → `0x145562940` → callback.
Координаты, SDK/device context и реальный вход остаются открытыми.
[Источники, проверки и ограничения](../resource-tools/vampir/HEADLESS-WORLD-FINISH-OWNER.md).

## H04-world-finish-decoder: тело ID206 связано с обработчиком

Все пять массивов проверены непустыми; общий decoder имеет лимиты размера
и суммарного числа элементов. Настоящее чтение и обработчик исполнены вместе,
включая отказ и переход состояния в 6. Реальный приход пакета ещё не подтверждён.
Продолжить с перехода от состояния 1 после ID110 к состояниям 2–4 и ID205.
Мировая позиция, привязка устройства и реальный вход остаются открытыми.
[Источники, API, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-DECODER.md).

## H04-world-finish-reader: минимальный профиль ID206 проверен

Reader `0x145844d70` исполнил 18 тел с пустыми массивами; 81 короткий префикс
отклонён. Полное чтение непустых коллекций и общий декодер ещё открыты.
Продолжить с массива `+0xe8`: callback `0x145783790`, reader `0x145771940`,
вложенный reader `0x1457989f0` уже экспортированы. Затем все массивы вместе,
общий декодер и чтение → обработчик. Жизненный цикл и реальный вход не завершены.
[Схема, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-READER.md).

## H04-world-finish-send: ID205 проверен до очереди

Запрос с пустым телом разрешён из состояний 2–4 и записывает 5; состояние 1
после ID110 его не разрешает. Проверены все значения байта, отложенная ветвь,
конфигурационные границы и четыре кадра. Добавлен общий encoder без I/O.
Продолжить чтение ID206; затем связать переход к состояниям 2–4 и вызов слота
`+0x70` с жизненным циклом. Мировая позиция и реальный вход ещё открыты.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-SEND.md).

## H04-world-finish: вызывающий перехода найден и проверен

ID206 `PktWorldMoveFinishResult`: обработчик `0x1467a5d30` → метод сервиса
`0x145dbef80` → настоящий слот `+0x78` / `0x145dbcbe0` → базовый метод →
состояние 6. Проверены поля, фильтр результата и сохранение состояния 1
при отклонении. Объект ID206 тестовый, чтение wire-тела ещё не восстановлено.
Продолжить с отправки запроса в `0x145dc2930` и условия `0x145619bf0`.
Промежуточный обмен после ID110, позиция и реальный вход ещё открыты.
[Привязка ID, сценарии, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH.md).

## H04-status-consumer: порог и отдельный переход проверены

`0x145d7b850` читает `service+0x30`: значения ниже 6 завершают функцию до
подготовки запроса. После ID110 состояние равно 1. Явный вызов метода жизненного
цикла `0x14560d7b0` записывает 6 и открывает этот запрос. Caller и момент
перехода ещё не установлены; тест не доказывает автоматическую связь.
Продолжить с источника перехода и потребителя координат; реальный вход открыт.
[Источники, SHA, сценарии и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATUS-CONSUMER.md).

## H04-select-status: запись состояния после ответа проверена

`0x1456140f0` записывает байт в `service+0x30` и передаёт диагностический текст.
Прежняя трактовка как события с подписчиками не подтверждена. Проверены
64 отдельных сценария и 6 путей от тела ID110; принятый выбор записывает 1.
Продолжить с кода, читающего это состояние, и потребителя вектора персонажа.
Затем остаются жизненный цикл клиента, устройство и реальный вход.
[Источники, проверки и точные ограничения](../resource-tools/vampir/HEADLESS-SELECTION-STATUS.md).

## H04-select-handler: локальная цепочка применения данных проверена

Пройден путь от тела ID110 до обработчика и применения данных персонажа.
Проверены общий фильтр, отдельные ветви результата, перенос вектора / флагов
и вызов метода сервиса. Внешние подсистемы и интерфейс перехвачены.

Продолжить с потребителя координат и состояния, записанного `0x1456140f0`
с аргументом 1. Вызов `0x145dea660` относится к заголовку окна, а не к позиции.
Затем остаются жизненный цикл клиента, подтверждение устройства и реальная сессия.
[Сценарии, адреса, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-HANDLER.md).

## H04-select-decoder: тело ответа разобрано, обработчик ещё открыт

Добавлен `decode_character_select_result` в общий модуль. Он поддерживает обе
необязательные таблицы, вложенные массивы, строки и скаляры. Проверяются полнота
тела и общий лимит записей, включая повторные ключи. Схемы сверены с кодом клиента.

Дальше: обработчик `0x14675e9a0`, условия принятия выбора и применение данных
персонажа. Затем нужно установить использование мировой позиции, связать
жизненный цикл клиента и проверить реальную сессию с подтверждением устройства.
[Источники, API, проверки и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-DECODER.md).

## H04-select-collections: непустые массивы проверены offline

34 whole ID110 bodies: все 11 arrays по 1/2/8 элементов и совместно;465 short
prefixes rejected. Actual item readers/constructors/append, bounded allocator/
cleanup fixtures; enum clamps/bool/optional float vector подтверждены.
Ghidra 165 функций/63 warnings. Полный ID110 этап остаётся незавершённым.

Продолжить optional map+98: table 1498cf350→reader 145796480 и nested 1498cf308
→145796df0 (ещё экспортировать). Insert/find/copy/destroy уже экспортированы.
Затем обе непустые maps вместе с arrays, portable decoder/budgets, actual handler,
position consumer и lifecycle/SDK/device/live. Игру/сетевой вход этап не запускал.
[Точные схемы, SHA, команды и отчёты](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-COLLECTIONS.md).

## H04-select-result: минимальный native профиль, этап частичный

268 ID110 bodies (all256 heading bytes +12 vector/code cases) прошли actual
constructor/readers/math; отдельно 22 player apply cases. Экспорт 151 функций,
math discovery через Ghidra machine blocks, provenance и regression checks.
Raw main+188→player+20 подтверждён; world position semantics ещё не доказаны.

Продолжить с уже экспортированных nonempty callbacks/map98 insert, затем
полный bounded decoder/short inputs, handler 14675e9a0→player и position consumer.
После этого lifecycle/SDK/device confirmation/live вход. Минимальное тело 203 bytes
не заменяет полный decoder и не доказывает успешный выбор/готовую сессию.
[Адреса, отчёты, SHA, команды и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-RESULT.md).

## H04-select-send: два callers и источники полей подтверждены offline

Выполнено: WaitingEnd→actual service virtual 50 и UI-index caller
`0x145d43290`→signed record lookup `0x145c847c0`→virtual 50→handoff→writer/
framing/queue, 27+34 cases/19 full frames. Raw10=record+8 (indexed path),
raw18=constant0, raw20=current state+f0. 45 ID102→actual setter и 12 setter
transitions связали initial packet+40 с rawF0; UI также может менять этот state.
Shared from_character_list(body,index,state_raw_f0=...) без I/O/readiness.

Ближайшее продолжение: nested ID110 reader/handler, состояние после выбора и
точный источник позиции. Затем engine owner hook slot 7b0/CharacterSelect_02
lifecycle, фактические SDK/device inputs/подтверждение и live вход. Pending-store/
timeouts/drain/socket/runtime reconnect не доказаны этими очередными replays.
[Точные адреса, SHA, команды и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-SEND.md).

## H04-character-list-extensions/handler: offline ветви закрыты

Выполнено: actual appearance item read и optional map callback/insert/pair/value
readers, 30 full bodies/489 short prefixes. Общий ID102 decoder поддерживает
обе ветви с aggregate extension budget; last-value-wins и enum clamps проверены.
45 body→handler cases: result/policy gates, raw state writes, предпочтительное
первое совпадение/индекс 0. Общий preferred_character_index — только подсказка
после acceptance gates, empty/error→None, без отправки пакета.

Следом: доказать источники raw10/raw18/raw20 ID109 и actual caller service
virtual 50; подключить writer к request handoff/frame; разобрать nested ID110
body/handler/источник позиции; связать owner slot 7b0 с engine lifecycle уровня.
Затем настоящий SDK/device context, ручное подтверждение при необходимости и
live вход на согласованном аккаунте. Реальная сессия пока не проверена.
[Source, SHA, команды и ограничения fixtures](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-EXTENSIONS.md).

## H04-character-codecs: основной профиль списка и body выбора

Историческая запись первого этапа. Extensions/handler 102 закрыты следующим
offline этапом выше; продолжать с ID109 field sources/caller/frame и ID110.

Выполнено: actual owner constructor/table/slot+a18=1 → caller/RequestA без
policy fixture (2 cases); native ID102 reader/records (12 full/229 short cases),
bounded общий decoder; native ID109 writer и общий encoder (16 vectors).
Пять тестов прошли. Этап списка/выбора **остаётся частичным**.

Ближайшее продолжение: appearance array `0x1498ef500`/item table
`0x1498cff58`, optional map `0x1498d5038`/insert `0x1456b99b0` — callbacks
уже экспортированы, далее actual element/value readers и native scenarios.
Затем handler 102/перенос списка/источники select raw fields; owner hook slot 7b0
→ engine lifecycle/CharacterSelect_02, ID109 frame и ID110 body/handler.
Текущий decoder явно отклоняет непустой appearance array/present optional.
Реальный вход, подтверждение устройства, выбор и позиция не проверены.
[Источники, SHA, команды и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-CODECS.md).

## H04-request-caller: найти owner и его policy

Выполнено: direct getter caller scan, actual caller 0x1468f1d70 и 32 native
cases до RequestA/send capture. Следом owner/vtable, actual virtual+a18,
lifecycle policy 1 и связь с CharacterSelect_02. Response102/network/live session
остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-CALLER.md).

## H04-lifecycle: найти emitter и продолжение slot 78

Выполнено: source-bound Ghidra экспорт lifecycle, 7 event cases и leaf callback.
Далее: emitter callbacks из slot 08, продолжение 0x14561a8d0 из slot 78,
доказанный caller slot 90. Response102, network и live session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-LIFECYCLE.md).

## H04-world-label: source path подтверждён

Raw2→World.Id2→Lobby/CharacterSelect/CharacterSelect_02. Native field-store/
lookup/getter и base/current patch CSV parity проверены. Следом actual
cooked level/hooks завершения перехода и slot 90/CharacterListRead dispatch.
Полный runtime loader/mount priority, response 102/socket/live session открыты.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-STATE-LABEL.md).

## H04-state-lookup: actual hash, реальные contents открыты

13 native cases lookup/hash/accessor→label caller. Дальше заполнение
registry storage+0x18 и actual record vtable/virtual 20/source string key 2.
Generic TLS/static registry exports не доказывают contents. Slot90 lifecycle,
response102/socket/full session остаются открытыми.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATE-LOOKUP.md).

## H04-selection-state: preparation/deferred boundary

10 native virtual 40/SetState cases + 12 independent callback cases проверены.
Следом actual state-label lookup mapping и client/lifecycle hooks после
отложенного действия, доказанный slot 90 dispatch. Полный scheduler/closure
lifetime, response102/network/fresh SDK/device inputs и live session открыты.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATE-TRANSITION.md).

## H04-selection-service: targets и select handoff подтверждены

Derived table 0x1499f11f0: slot 90=requestA, slot 50=CharacterSelect builder.
Далее slot 40 SDK guard/base helper/virtual+c8/state-transition helper и
доказанный caller slot 90. Отдельно packet 109 writer/frame/response110.
Full owner ctor, свежие SDK/device inputs и live session ещё открыты.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-SERVICE.md).

## H04-waiting-end: один инициатор CharacterListRead подтверждён

ID 27/WaitingEndNotify handler 0x146768540 → predicate → requestB 0x145dbfe50
→ actual CharacterListRead constructor/send capture. 24 native cases.
Далее requestA 0x145dbd4b0 owner/slot (pointer 0x1499f1280), actual selection
virtual+0x40/+0x50 и response 102. Server notify timing и связь с обычным
Login success, frame/socket/session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## H04-character-list-boundary: reset и request разделены

8 native reset cases + 2 независимых CharacterList request entries.
После LoginResult подтверждён reset 0x1464846c0, а не direct character send.
Следующий участок: callers 0x145dbd4b0/0x145dbfe50, регистрация/условия и связь
с завершением Login; затем full ID 101 frame и reader/handler ID 102.
Живой transport/request lifecycle/fresh SDK/device inputs остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-BOUNDARY.md).

## H04-login-result-handler: covered native branches подтверждены

38 body→handler scenarios: state stores/early exit/error/SDK/server ID.
Следом actual virtual+0x28 после getter 0x146486a50 и доказанная цепочка
к CharacterListRead/выбору персонажа. Post-state 0x1467259c0 добавлен в Ghidra,
не считать его сетевой отправкой без продолжения. Request lifecycle/socket/
fresh SDK/device inputs и live session остаются открытыми.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-HANDLER.md).

## H04-login-result-reader: body подтверждён

21 full bodies, 332 short inputs, trailing policy. Ghidra расширена до
32 функций для nested readers и UTF-8. Общий LoginResultBody готов для
bounded offline decode. Далее actual handler 0x146765540/result gates,
Listener/Dispatch body linkage и следующие запросы персонажей. Request
lifecycle, fresh SDK/device/profile inputs и live session остаются открытыми.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).

## H04-login-send: handoff → queue подтверждён

34 native cases: 29 frames, 2 duplicate, 3 transport refusal. Проверены lookup,
timeout selection, getter/virtual send/writer/CRC/XOR/owning queue вместе.
Далее LoginResult reader/handler/result gates и стыковка с transport drain;
insert/notify/timeout lifecycle, fresh SDK/device/profile inputs остаются.
Live session/character selection ещё не подключены.
[Источник, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-SEND-PATH.md).

## H04-login-writer: body подтверждён

Ghidra → actual writer/UTF-8/archive IO: 25 payload vectors, 40 failures.
Общий LoginPayload готов для bounded offline encoding. +0x128 captured zero
в 16 preparation fixtures; семантика неизвестна. Следующий участок:
request handoff 0x144aa8020 → transport send, совместный prepare/writer/frame,
потом LoginResult. Real profile/device inputs и live session ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-WRITER.md).

## H04-tools: установка и границы совместимости

Правило выбора инструментов закреплено в AGENTS.md. CUE4Parse: три headers
проверены, четыре PAK без ключа индекса заблокированы; mappings/properties
не проверены. Dumper-7 собран x64; live SDK/mappings — отдельный будущий
эксперимент с согласованием. Продолжение Login: готовый Ghidra export,
затем native replay writer/handoff.
[Команды и ограничения](../resource-tools/vampir/ANALYSIS-TOOLS.md).

## H04-Ghidra: пакетный анализ подключён

22 функции успешно экспортированы и повторены из сохранённого проекта.
Далее Login writer и request handoff читать через общий псевдокод/call graph,
проверять целыми native scenarios. Межверсионное сопоставление ещё открыто.
[Установка, команды и границы](../resource-tools/vampir/HEADLESS-GHIDRA.md).

## H04-login-fields: constructor и SDK consumers проверены

Native Login prefix разделяет NetmarbleId/token/server fields и доходит
до request handoff. Далее writer/encoding и handoff0x144aa8020 → send,
device/profile input sources и полный SDK response→Login ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-FIELDS.md).

## H04-version-result: native переход к Login entry

VersionResult reader/handler/gate → 0x1467a9700 проверены. Далее actual
Login construction/SDK field sources/writer/send/LoginResult. Error helper
branches вне covered codes, live negotiation/transport ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-RESULT-HANDLER.md).

## H04-version-send: полный native путь до очереди

Wrapper/send-B/writer/frame/append проверены вместе на 18 scenarios. Далее
VersionResult reader/registration/handler → Login; отдельные задачи actual
queue drain/socket и реальные weekly inputs. Server negotiation ещё нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-SEND-PATH.md).

## H04-version-writer: переносимое тело проверено

Actual writer/conversion/archive bytes совпали с VersionPayload на 14 cases.
Далее frame/send0x1467aaa10 → VersionResult handler → Login; реальные
значения полей/weekly inputs и server negotiation ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-PACKET-WRITER.md).

## H04-connected-packet: сначала PktVersion

Game callback строит PktVersion/ID1 и вызывает send0x1467aaa10. Далее
send/writer/VersionResult → Login; реальные источники raw fields и weekly
version inputs ещё открыты. Live negotiation/session не доказаны.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECTED-VERSION-PACKET.md).

## H04-connected-delegate: игровой target связан

Native binding/bridge → game0x1467a9cd0 подтверждены. Далее тело получателя,
packet constructor/field sources и virtual send+0x38 → Login. Units storage
не refcount; AL1 bridge не server success. Live session остаётся открытой.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).

## H04-ready-notification: transport recipient исполнен

Completion code 1 → socket listener → peer broadcast → OnTcpPeerConnected
и owner virtual+0x60 call site проверены. Далее actual owner P+0x308/+0x310
vtable/target → packet Login; endpoint/configuration/retry ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READY-NOTIFICATION.md).

## H04-socket-option: actual engine body проверен

Raw level/option translation → getsockopt и readiness gates исполнены.
Далее completion code 1 recipients → peer transport notification → Login.
Live socket/scheduler/lifetime/session ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-ERROR-OPTION.md).

## H04-readiness-job: code/state gates проверены

Mode helper, одна worker iteration и completion mapping проверены.
Далее option selector 1 → syscall/translation и code 1 recipients →
transport notification → packet Login. Live readiness/threads/lifetime
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READINESS-JOB.md).

## H04-error-mapping: native таблица подтверждена

Mapper engine slot+0x68 и WSA inputs → wrapper acceptance проверены.
Далее helper 0x1445eab70 и actual job run/completion, readiness notification
и packet Login. Системный last-error source, active mode/network и
server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WINSOCK-ERROR-MAPPING.md).

## H04-connect-result: syscall boundary и bool semantics

Native endpoint connect lower/wrapper проверены. Дальше engine virtual
+0x68 error mapping, actual helper 0x1445eab70 и job/completion/readiness,
затем packet Login. Не считать wrapper acceptance готовой сессией;
реальные OS connect/wait и активный mode не проверены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-CONNECT-RESULT.md).

## H04-socket-create: recipient и creator проверены

Resolver recipient и source socket creator исполняются вместе.
Далее helper 0x1445eab70 и endpoint connect 0x1445e5c60 → 0x1445ecbb0,
реальные pending/error/readiness и callback packet Login. Socket syscall
и active network/session не проверены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVED-SOCKET-SETUP.md).

## H04-resolver-results: run/completion проверены

Job run/completion и адресные callback gates проверены на 8 fixtures.
Далее recipient action 0x141423088 → first socket/connect/readiness,
затем packet Login. Реальный DNS/vector parsing, scheduling/lifetime
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVER-JOB-RESULTS.md).

## H04-lower-connect: setup и resolver handoff проверены

Lower connect и lexical selector исполняются после endpoint construction.
Далее resolver job source vtable → run/result callback → socket readiness
и packet Login. Numeric parser, реальный DNS, duplicate/reset lifecycle
и active session ещё открыты; bool enqueue не заменяет readiness.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## H04-connect-target: host/game-port связь подтверждена

Основная пара +0x278/+0x288 и override +0x290/+0x2a0 связаны с
ConnectToServer. Далее lower connect 0x1445ea1b0 → socket/readiness
и callback packet Login. Второй word+0x28a, active endpoints/lifecycle
и server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).

## H04-server-target: source mapping проверен

BeginGame last ID/fallback/lookup/busy и target stores подтверждены.
Далее consumers transport+0x270/+0x278/+0x288/+0x28a → connection setup
и packet Login. Реальные server records/sentinel/busy lifecycle и
server-compatible session остаются открытыми.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## H04-entry-gate: разделение title/SDK state

Title head/tail и отдельный BeginGame IsSignIn gate проверены.
Далее BeginGameImpl 0x146425730, server selection и packet Login.
UI middle/blacklist и активная session validation не закрыты; клиентские
флаги не заменяют доказательства серверного входа.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-STATE.md).

## H04-title-notify: переход найден

Условная цепочка manager-child → router → slot+0x08 →
OnSuccessNetmarbleSDKAuth подтверждена. Далее значимые переходы handler
0x14641d560 и существующая entry/packet Login цепочка. Активный NID
channel/policy, первый вход и полная session validation ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## H04-game-instance: PGS ветвь отделена

Game-instance virtual+0x10 оказался Google PGS SignIn с unsupported Windows
result, не game Login. Далее manager-child 0x14560f740 и реальные title
success notification/OnSuccessNetmarbleSDKAuth; затем packet Login.
Android parity, первый credential-вход и полная session validation открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-PGS-BRANCH.md).

## H04-game-success: broadcast и title handler проверены

Первый success action оказался общей рассылкой; title slot+0x30 обрабатывает
child pointer и не доказывает Login. Далее game-instance getter 0x1450b11b0
и virtual+0x10 в game callback, а также child action 0x14560f740.
Registration реальных subscribers и network/session readiness ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-SUCCESS-BROADCAST.md).

## H04-silent-game: цепочка callback проверена

Silent dispatcher → queued thunk → bridge → game callback проверены
вместе. Далее success action 0x143b8bf10 и ненулевой game instance → Login.
Silent response JSON/session contract и credential-first вход ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SILENT-GAME-DISPATCH.md).

## H04-channel-silent: handoff подтверждён

Переход ChannelManager → Auth silent и обязательный сохранённый player ID
проверены. Далее response callback Auth impl+0xa8 → Channel/game callback;
обычный credential-first вход, expiry/refresh и game Login остаются открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## H04-game-callback: следующая связь

Проверены AutoSignIn callback gates и отдельный SDK route owner+0x170.
Getter назван по diagnostic: GetChannelManager, target — SignInSilently.
Далее provider selection в 0x1444feac0, success manager action
и virtual callback → реальная credential/session цепочка → game Login.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-AUTO-SIGN-IN.md).

## H04-result-dispatch: native handoff проверен

16 сценариев связали SignIn binder, dispatcher, очередь и invoke bridge.
Task graph и реальный bound function пока fixtures. Следующий приоритет:
найти function/storage реального игрового callback, проследить до game Login;
затем expiry/refresh и real identity/confirmation.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-RESULT-DISPATCH.md).

## H04-response-completion: частично завершено

Проверены idpInfo, channel byte, native SetSignIn и вызов dispatcher.
Добавлен общий строгий parser без I/O. Следующий шаг: исполнение dispatcher
и привязки делегатов → игровой Login; затем expiry/refresh и реальное устройство.
Подтверждение входа по одному внутреннему флагу запрещено контрактом parser.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## H04-response-variant: conversion boundary reduced

10 native cases проверили converter/AsString/real TryGetString/CRT для
string и number-string fixtures. Три regression tests OK. Native JSON parser
и double/bool/другие variants открыты. Далее idpInfo/final callback/SetSignIn
и SDK token →game Login, затем полный runtime authorization boundary.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-VARIANT.md).

## H04-response-gates: native boundaries partial

18 native cases связали response raw predicates/body/status getters, JSON
object/errorCode gates и field traversal. _wtoi исполнился в actual Windows
CRT; JSON/variant — fixtures. Далее native numeric variant conversion,
error dispatch, idpInfo/final callback/IsSignIn/SDK →game session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-GATES.md).

## H04-SDK-response: field mapping partial

13 native cases и auth constructor подтвердили playerInfo/player keys,
SDK accessToken assignment и optional field preservation. Три regression
tests прошли. Далее network/JSON/errorCode validation до slice, idpInfo
и final callback/IsSignIn/expiry/SDK →game session. Runtime response parser
пока не подключён. [Source/SHA](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-RESPONSE.md).

## H04: следующий приоритет — SDK sign-in response

Migration wrappers проверены в 10 native cases; zero-tail guarantee отсутствует
в рассмотренном wrapper path. Реальный backend/полная миграция остаются открыты.
Это отдельная задача совместимости, не доказанная предпосылка нового входа.
Продолжать callback 1444d85f0 leaf →1444cc1a0, response schema/errors →
SDK token/player/expiry →game Login, затем real identity/confirmation integration.
[Границы migration evidence](../resource-tools/vampir/HEADLESS-SDK-MIGRATION-ALLOCATION.md).

## H04-token-container и migration field

16 native container + 8 migration cases проверены. Decoder/JSON/split
primitives остаются fixtures; true caller result не доказывает auth.
ChannelKey source связан с migration branch. Далее allocator tail contract,
migration config/lifecycle, full token decode и SDK sign-in response/session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-TOKEN-PAYLOAD.md).

## H04-NID-suffix: transform и common helper

6 native suffix cases + independent AES/runtime comparison прошли.
Aligned printable ASCII derivation реализован в nid_storage_path, optional
crypto backend; Android пока не проверен. Следующее: source token/sub parsing,
migration branch/active path, SaveGame serialization и SDK auth response.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-NID-SUFFIX.md).

## H04-storage-auth-path: optional directory gate

8 native auth-context gate/Load join fixtures прошли; извлечение auth context
и suffix пока fixtures. SetupServiceSettingPath/parser сохранены статически.
Shared flag связан с Initialize/Save/post-restore sources. Далее suffix
transformations/reset lifecycle, active storage, SaveGame decode и SDK session.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-AUTH-PATH.md).

## H04-load-device-fields: восстановление и filename

16 native Load field-copy/post-dispatch и 3 constructor/path fixtures прошли.
Разные SDK/NID поля и default ServiceSetting.bin подтверждены в указанном
объёме. Дальше optional directory, active filename overrides, file parsing/type
checks/Save read-back; реальные identity и device confirmation ещё открыты.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-LOAD-DEVICES.md).

## H04-NID-device: источник web/token ключа

Три native slices проверили deviceKey/device_key → NID getter. Registry v2
с отдельными NID key/source и миграцией v1 готов; основная локальная база
мигрирована с пустыми real values. Проверены native report и 5 registry tests.
Далее NID getter lifecycle, filename/Save/load и full web-context binding.
[Source/SHA](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md).

## H04-storage: каталог и NID identity

Native directory join проверен шестью fixtures, base getter explicit fixture.
Save/Load/Initialize и отдельный NID device key экспортированы статически.
Два regression tests прошли. Открыто: полный filename, Save/load field mapping,
NID getter caller → web deviceKey, active context и реальные keys.
[Source/SHA](../resource-tools/vampir/HEADLESS-SDK-STORAGE.md).

## H04-device-setter: сравнение и запись

Native setter body/ASCII compare проверены в 56 fixtures, 12 интеграциях
с getter. Write failure не предотвращает изменение settings. Три regression
теста прошли. Дальше Save/load/path и active platform/SDKZone, реальная
identity основной почты, затем server challenge protocol.
[Source/SHA](../resource-tools/vampir/HEADLESS-DEVICE-SETTER.md).

## H04-device-lifecycle: getter branches

8 NM + 12 DeviceKey native fixtures подтвердили cache/source/save gate
и продолжение caller после ошибок write/Save. Три regression tests прошли.
Следующие зависимости: SetDeviceKey compare/write, active platform/environment,
Save/load, реальные identity и server challenge. Storage/parser остаются fixtures.
[Source/SHA/ограничения](../resource-tools/vampir/HEADLESS-DEVICE-LIFECYCLE.md).

## H04-device-source: storage и формат GUID

Найдены Windows StoredValue, NMDeviceKey/DeviceKey, platform-dependent branches
и CoCreateGuid. Native default formatter проверен тремя fixtures, два regression
теста прошли. Открыто: getter/cache/storage replay, platform/environment и
Save/load lifecycle, получение реальной identity и server challenge.
[Источники и границы](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).

## H04-device: постоянные привязки

Локальный SQLite-реестр реализован; основная тестовая почта зарегистрирована.
Три теста persistence/isolation/confirmation прошли. Открыто: source-bound
генерация и хранение обоих device keys, реальная identity, challenge protocol,
login runner gate, transfer/backup и Android adapter.
[Подробности](DEVICES.md).

19 октября: H04 SDK sign-in request preparation подтверждена: 4 native body
и 8 header/method fixtures. Общий sdk_sign_in offline plan добавлен; authUrl
из real public GMC2 связан только с synthetic context. Auth HTTP нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN.md).
Следующая зависимость: callback 1444d85f0, network/SDK result schema, SDK access
token/playerId/expiry/errors → game Login. Active context/storage/refresh открыты.

19 октября: H04 OnResult continuation/GetObject проверены четырьмя fixtures.
Provider20 преобразуется в SDK credential33 с channelAccessToken. Native Save
return не проверяется; storage/clear/JSON/map insertion — explicit captures.
Общий nid_sdk_credential builder готов только в названном объёме.
[Source/SHA](../resource-tools/vampir/HEADLESS-NID-CREDENTIAL.md).
Следующая зависимость: FAuthImpl::SignIn 1444fb800, полный authUrl/v1/sign-in
request/header/device/client context и response → SDK token → game Login.
Auto caller после result/active auth attempt, persistence и refresh ещё открыты.

19 октября: H04 percent loop проверен 147 native fixtures, UTF conversions
остаются отдельной границей. Общий sdk_percent и callback parser используют
strict ASCII/route/duplicate policy; URL → provider credential без сети/storage.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-PERCENT.md).
Далее full query/map semantics и связь с активной попыткой входа, затем settings
setters/persistence и callback после 1450ef437 → SDK session → game Login.
Не считать локальный callback parser подтверждением подлинности токенов.

19 октября: H04 integer/channel dependencies проверены actual native helpers,
13 initializers/ASCII compare и локальным CRT. 28 numeric/45 channel/6 caller
fixtures; mailUserKey=20, native numeric parser permissive. Общий nid_result
принял только decoded dict, canonical0/presence/ASCII policy документирована.
[Источники](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).
Далее query parser/encoding и context binding, settings/persistence/callback
после 1450ef437 → SDK session → game Login. Android crypto/storage ещё открыты.

19 октября: H04 получил 22 native OnResult caller/copy fixtures. Подтверждены
caller gates и раздельные access/refresh/ID/country settings arguments; missing
и empty различаются. Parser/channel return fixtures не доказывают accepted
numeric syntax или email enum. Settings/callback ещё не исполнялись.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).
Следующая зависимость: parser 1415dea40/channel mapper 14452b060 и query parser,
затем setters/persistence и post-adoption call 1450ef437 → SDK/game session.

19 октября: H04 — email result path уточнён. Обычная web ветка проходит
profile processing → nmidprovider/result с accessToken. Отдельный signin/
authorization_code не подставлять вместо неё. 12 JS fixtures и native static
OnResult/14 initializer bindings сохранены; четыре targeted tests прошли.
[Источники](../resource-tools/vampir/HEADLESS-NID-RESULT.md).
Следующая зависимость: native OnResult query parser/resultCode validation,
token adoption/SendSignInCallback → SDK session → game Login.
По просьбе пользователя создан bot-test@vampir.top (100 МБ) в DirectAdmin;
доставка писем и регистрация Netmarble не проверены. Пароль не хранить в Git.

19 октября: H04 остаётся частичным. Найдены отдельные legacy EmailAuth/NID
SDK ветки и публичный NID web contract. Общий encrypted request plan готов
локально; POST, reCAPTCHA acquisition, response/callback не выполнялись.
[Источники](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Следующая зависимость: разобрать response → callback → authorization code,
сверить native обработку и context/provider selection. Затем token/session.
При обновлениях сверять web snapshot отдельно от EXE/PAK.

19 октября: public GMC2 получен и декодирован полностью в local response profile:
DECKEY HTTP header, 93 ordinary/1 secret/94 merged, auth endpoints доступны.
ServiceCode=netmarbles подтверждён ctor/caller. Build 0/A — явный constructor-
default probe, не доказанный active state. Далее email/password/browser code,
token response/expiry и SDK→game session. [Источник](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).

19 октября: исправлен existing decode_sdk_constants_string: reused unescape
→ actual XOR/append zero omission, без дублирования decoder. Два regression tests
и 18 новых native vectors через составной путь. DECKEY slot 28/class method,
outer response и auth остаются следующими зависимостями.
[Источник](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).

19 октября: H04b native XOR helper/append подтверждены на 18 fixtures,
общий raw uint16 primitive добавлен. Далее encConstants source decode,
key/DECKEY, encSecretConstants и JSON/schema; byte XOR/UTF8 не подставлять.
[Источник](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).

19 октября: H04b RequestGMC2 headers/method arguments проверены на 16 native
fixtures с HTTP captures; общий immutable plan добавлен, без I/O/credentials
acquisition. Следом response decode/encConstants/DECKEY/auth URL values;
serviceCode/active device identity остаются отдельными зависимостями.
[Доказательства](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).

19 октября: H04b native URL assembly/getters/ASCII-view append подтверждены
26 fixtures; общий assemble_gmc2_config_url_ascii добавлен. Active inputs
и HTTP ещё не установлены. Следом RequestGMC2 headers/response decode/DECKEY.
[Source/SHA/ограничения](../resource-tools/vampir/HEADLESS-GMC2-URL.md).

19 октября: H04b bootstrap getters проверены native. Version=5.2.11,
BuildCode byte 1→B/2→C/elseA (256 fixtures), общий selector добавлен.
[Источник](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Следующая зависимость — полный GMC2 URL builder/request и response decode;
active BuildCode не подменять game AppVersion или SDKZone.

19 октября: H04b получил реальный public CDN config по профилю base INI.
Общий decoder подтверждён: Zone real/mode 2, index 6/REAL с lobby details.
[Snapshot/offline verification](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md).
Далее SDK bootstrap/auth parameters/session response; active INI/native full
validation остаются открыты. Module descriptors base/patch совпали и имеют
Default phase; это не runtime order. [Источники](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).

Обновлено 19 октября 2026. Контекст/ограничения — [README.md](README.md).
История — [WORKLOG.md](WORKLOG.md); общий реестр — [FUNCTION-INDEX](../vampir/FUNCTION-INDEX.md).
Общие результаты и runtime package — [vampir-shared](../vampir-shared/README.md).
H03a codec находится в `vampir-shared/vampir_core`, без копии в сетевом боте.
Не создавать подагентов без прямой просьбы пользователя.

19 октября: H04b startup callback уточнён. FNnNetworkVar loader вызывается
сразу при registration, до registry insertion (8 native fixtures).
Найдены owner factory/vtable и отдельная patch init chain. Следующая зависимость:
module load → PAK mount → GConfig Game cache/overrides.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-CONFIG-STARTUP.md).

19 октября: H04b получил оба Game config слоя с проверенными хешами.
Base 1.12.14/real/True отличается от patch 0.1.1/dev/False.
Следующая незавершённая зависимость — порядок startup/mount/GConfig cache
и overrides; выбирать active settings по внешнему виду значений нельзя.
[Снимки и воспроизведение](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

Статусы: готово — только в названном объёме; частично — есть доказательство,
но критерий не достигнут; осталось — ещё не сделано. При продолжении выбирать
первую незавершённую зависимость, обновлять её и добавлять запись в журнал.

| ID | Задача / зависимости | Статус | Проверяемый результат |
|---|---|---|---|
| H00 | Зафиксировать требования, задачи, общий реестр | Готово | README/TASKS/WORKLOG, ссылки из главного README; ограничения и unknown явно записаны |
| H01 | Инвентаризировать уже найденные функции и сетевые строки | Готово в ограниченном объёме | Воспроизводимый SHA-bound отчёт: 27 строк/31 проверенная LEA; общий индекс, независимая проверка bytes |
| H02 | Packet name→vtable→ID/read/write; H01 | Готово для 10 выбранных типов | 10vtable/constructor/ID/IO targets, 5 result registrations, 10 native ID cases/4 audit tests; HEADLESS-PACKET-BINDINGS.md. Не wire-schema |
| H03 | Транспорт и wire encoding; H02 | Частично: H03a готов | Реальный Ping body IO/126 native scenarios; framing, transport и остальные поля ещё unknown |
| H03a | Ping/Result primitive IO и переносимый payload codec | Готово для исследованной ветки | `<QQ`/16 байт и `<IQ`/12 байт, native constructors/primitive/raw IO; только внешний memcpy shim; 5 tests/6 replays |
| H03b | Complete framing/send/receive; H03a | Частично | Найдены output roots144aa9da0/144aaccf0 и helper 144aa6ca0; нужны доказанные размер/checksum/transform/context и complete-frame vectors |
| H03c | Остальной codec и bounded transport; H03b | Осталось | Primitive strings/arrays/limits/таймауты, send/receive контекст без смешивания IDs; offline vectors и локальный transport test |
| H03b.1 | CRC/XOR helpers и общий код | Готово в указанном объёме | CRC32+LE64 repeating XOR, 4send/receive roots, 252 native executions/5 tests; full frame ещё unknown |
| H03b.2 | Frame bounds/integrity/context и связь receive→Dispatch | Частично | Send-A Ping frame закрыт H03b.2a; receive/лимиты/key/callback targets остаются H03b.2b |
| H03b.2a | Цельная сборка исходящего Ping send-A | Готово в указанном объёме |20 native assembly cases/5 tests; length 24/CRC32/ID16/seq16/body/XOR, wrap; shared send_frame.py |
| H03b.2b | Приём/контексты/ключ; H03b.2a | Частично | Length probe 156 cases/wrapper 13 cases, static callback→Dispatch; смена ключа закрыта отдельно; transport/CRC/handler wrappers ещё неизвестны |
| H03b.2b-key | Notify→ack→peer key | Готово в указанном объёме | IDs11/12/raw64, registration, 20 native handler slices; send capture shim; server key generation/full Notify→wire неизвестны |
| H03b.2b-transport | Первый raw receive stage | Готово в ограниченном объёме | Native size 23/compressed flag/copy/decompress/compaction, 62 scenarios/5 tests; literal fixtures, не общий decoder |
| H03b.2b-block | Блочная распаковка и связь второго stage | Готово в указанном объёме | 166 valid / 86 invalid native cases; shared bounded block_decode.py/take_transport_frame; static slots38/40, не полный listener replay |
| H03b.2b-listener | Исполнить второй receive loop; H03b.2b-block | Готово в указанном объёме | 44 native cases/5 tests: probe/broadcast/receive-A/XOR/compact; snapshot lifecycle fixtures, final callback capture; общий take_receive_a_frame |
| H03b.2b-dispatch | Dispatch→reader→handler wrapper | Готово в указанном объёме |24 native cases/4 tests; receive-A→ID lookup→PingResult reader→OnHandler entry, TLS/current cleanup; registry fixtures/handler capture, не gameplay side effects |
| H03b.2b-receiveB | Keyed receive-B и дополнительные действия | Готово в указанном объёме |39 native cases/4 tests: XOR/key, ID table lookup/remove, empty notify, Dispatch; manager/registry fixtures/handler capture; session semantics и full integrity открыты |
| H03b.2b-sendB | Keyed send-B/queue ownership | Готово в указанном объёме |40 native cases/5 tests, Ping/KeyChanged/CRC/key/seq/wrap и synchronous copy, shared encoders/bounded queue; drain/socket и весь Notify→wire открыты |
| H03b.2b-drain | Queue→socket и partial send | Готово в указанном объёме |61 native cases/5 tests, ordinal send provenance, partial consume/errors; portable bounded pump/real IPv4 loopback; connect/auth/shutdown/scheduler ещё открыты |
| H04 | Авторизация почта/пароль→игровая сессия; H01 | Частично: H04a static SDK/token-form evidence | Прослеженный SDK/HTTP/session flow, параметры/сроки/ошибки, ручные challenge; секреты защищены, игра не нужна |
| H04a | SDK auth graph и token request forms | Готово в указанном объёме |24 symbols/34 LEA/24 roots, 143 constants, 512 native escaping calls/5 tests; offline code/refresh plans, не email/password login/config/response/game handoff |
| H04b | Источник SDK config GMC2 и параметры | Частично: real public response decoded | Source-bound build 0/A probe дал 200/errorCode=0/DECKEY HTTP header; 93 ordinary+1 secret=94 merged constants, auth URL fields и offline token binding. Active settings/native callback/email authorization остаются открыты; HEADLESS-PUBLIC-GMC2.md |
| H04b-settings | Class defaults и game overrides; H04b | Частично | 9 property descriptors, 4 constructor + 13 game native replays; market/game/client globals и environment→zone rule; actual singleton+48 load/call order неизвестны |
| H04b-CDN-source | Физический Game config и actual CDN values; H04b-settings | Частично | Generated key callback + точные directory SHA1; 7067 paths и два packed Game INI слоя восстановлены. Найдены defaults, active parameter/command-line/late overrides/scheme/CdnConfig ещё открыты; HEADLESS-PAK-CONFIG-RECOVERY.md |
| H04b-CDN-HTTP | Получение CDN config; H04b-settings | Частично: public HTTPS profile verified | Offline native URL/GET/response foundations плюс real 200/6000-byte public CDN snapshot; active settings/native TLS/lifecycle/прочие framing paths открыты; HEADLESS-PUBLIC-CDN.md |
| H04b-CDN-decode | Body → JSON → SDK environment; H04b-CDN-HTTP | Готово в ограниченном offline-профиле | Bounded Unicode, AES fallback с optional backend, строгий JSON dict и exact NetmarbleS/Zone → SDK selector; native crypto/parser core и Android не проверены; HEADLESS-CDN-JSON-FLOW.md |
| H04b-CDN-servers | Выбор server_list и raw lobby details; H04b-CDN-decode | Готово в ограниченном offline-профиле | 31 native replay (30 whole SetServerList), first ASCII-fold type match, четыре detail fields; общий изолированный raw plan, без endpoint validation/IO; HEADLESS-CDN-SERVER-LIST.md |
| H04b-CDN-accept | Полный ReadJson/применение/startup; H04b-CDN-decode | Частично | SetServerList проверен с JSON/FString shims; осталось проверить остальные поля ReadJson, актуальные settings/документ, полный порядок применения/ready/lifecycle и endpoint/auth handoff |
| H04b-secret | Декодирование secret constants; H04b | Готово в локальном Windows profile | Existing native primitives + real public PKCS8 RSA 3072/OAEP SHA256/list decoded; native PEM parser acceptance и Android ещё не проверены; HEADLESS-PUBLIC-GMC2.md |
| H04b-map | Merge строковых констант и auth URL getter; H04b-secret | Готово в данном response profile | Real 93 normal/1 secret ->94  string map, auth URL lookup и offline token binding; nonstring JSON отвергается local policy, full native callback/active values не доказаны |
| H04b-path | Полный адрес token request; H04a/H04b-map | Готово в указанном offline-объёме | 70 native path scenarios, bind_token_request с явной картой и сохранённым body; acquisition/HTTP/browser code/session handoff не реализованы |
| H05 | Один вход и модель персонажа; H02–H04 | Осталось | Выбрать правильный сервер/персонажа, получить ID/world/position/HP; живой тест без процесса игры |
| H06 | Общий runtime на Windows/Android; минимальный H03 | Осталось | Один сетевой/codec smoke на двух платформах, зависимости закреплены; UI/OS вне ядра |
| H07 | Боевой цикл на месте; H05 | Осталось | Доказать client/server обязанности автобоя, команды/результаты/кулдауны, stop; один аккаунт 30 мин без игры |
| H08 | Менеджер 1–20 аккаунтов; H05/H06 | Осталось | Изоляция, последовательное подключение, независимый stop/reconnect; 20 сессий, 2 часа, без смешивания состояния |
| H09 | Онлайн 2D-карта и панель; H05 | Осталось | Проверенная world→map привязка, живые слои/выбор аккаунта, старт/стоп, stale indicator; пустые неизвестные данные не выдаются за координаты |
| H10 | Движение и выбор точки на 2D-карте; H09 + H03 + подтверждённая навигация | Осталось | Проверить move schema, позиции/достижимость/остановку; выбор точки отправляет только доказанные команды |
| H11 | Безопасное восстановление; H05/H07 | Осталось | После разрыва сначала sync state, ограниченный backoff; смерть/challenge/защитное/unknown→pause; без повторения неизвестных действий |
| U01 | Manifest и снимки выпусков; H01 | Частично: immutable аудит 163 архивов; 34 changed/1 added; EXE SHA прежний | Source/build/SHA256 + зависимости генераторов, immutable snapshots, версия Windows/Android отдельно; неизвестная версия явно unknown |
| U02 | Инкрементальное извлечение и diff; U01/H02/H03 | Частично: свежие индексы 35 архивов и 1565 CSV pakchunk1; 298 без точного старого совпадения | Сравнить packets/IDs/schema, auth, таблицы, world/map; пересобрать затронутые наборы, сохранить происхождение/прошлый выпуск |
| U03 | Compatibility gate и обновление пакета; U02/H05/H07 | Осталось | Offline regression + ограниченный live canary, явный compatibility result, atomic switch, recovery; ошибочный/частичный update не заменяет проверенный |
| P01 | Компактные runtime-данные и bounded resources; H03/H09 | Частично: OutboundFrames имеет byte/frame limits; общий runtime ещё не готов | В сборке нет EXE/PAK/analysis library, данные региона по требованию, ограничены очереди/кеш/история; UI не дублирует полный мир на каждый tick |
| P02 | Профилирование и оптимизация; H08/P01 | Осталось | Размер сборки/данных, RAM/CPU/network для 1/10/20, двухчасовой soak без неограниченного роста; бюджеты принять по замерам, обещаний без измерений нет |
| A01 | Android-служба и оболочка; H06/H07 | Осталось | Тот же core, foreground/notification/Stop, экран выключен/network changes; масштаб на телефоне определить измерениями |

## Текущее продолжение

Full default GET header: 7 native blocks + 4 overrides; общий encoder и
Draft.header_bytes проверены offline. [HEADLESS-CDN-HEADERS](../resource-tools/vampir/HEADLESS-CDN-HEADERS.md).
Далее response/status/body limits/chunked/compression/JSON/callback order,
request queue/TLS и реальные Game config values/late overrides.

URI parser: 22 native URL→URI→GET-line cases; общий strict ASCII subset,
16 supported/6 rejected. [HEADLESS-CDN-URI](../resource-tools/vampir/HEADLESS-CDN-URI.md).
Draft URI/request_line готов в offline объёме; далее full headers/body,
TLS/response/status/limits/JSON/callback order и фактический Game config.

HTTP defaults: 16 native GET/1.0 request-line scenarios и frozen offline draft.
[HEADLESS-CDN-HTTP](../resource-tools/vampir/HEADLESS-CDN-HTTP.md).
Далее URI parsing/full headers/body/status/limits/TLS/late overrides/callback order;
actual Game config values остаются неизвестны, реальные requests не отправлены.

CDN preparation: 15 native AppVersion replacements + compiled Windows platform
chain + 7 return-tag branches проверены. [HEADLESS-CDN-PREPARATION](../resource-tools/vampir/HEADLESS-CDN-PREPARATION.md).
Общий offline URL из явных settings готов в указанном объёме; далее actual Game
config/late overrides, HTTP semantics и callback order. Не повторять version tail.

CDN URL tail: 16 native concat/growth сценариев и общий ASCII assembler готовы
в offline объёме. [HEADLESS-CDN-URL](../resource-tools/vampir/HEADLESS-CDN-URL.md).
Version preprocessing/platform getter закрыты следующим этапом выше; реальные
Game config/bases/prefix/late overrides остаются неизвестны, network_ready=false.

CDN selection: 16 native Find/branch cases и общий helper с явными bases.
[HEADLESS-CDN-SELECTION](../resource-tools/vampir/HEADLESS-CDN-SELECTION.md).
Loader file-global связан с Game; текущие physical config/URLs неизвестны.
Следом physical/cooked Game config и late parameter overrides, полный URL
builder; поиск 4 markers в decoded pak0 результата не дал (75 encrypted skipped).

H04b: найден CDN ReadJson → NetmarbleS.Zone → environment field+48,
7 native slices; [HEADLESS-CDN-CONFIG](../resource-tools/vampir/HEADLESS-CDN-CONFIG.md).
Далее actual NetworkSetting.CdnConfigUrl/QA/ConfigPrefix, источник настроек,
полный URL builder и callback order до GMC2. Active environment пока неизвестен.

H04b: constructor settings и game InitSetting исследованы, 4+13 native cases.
[HEADLESS-SDK-SETTINGS](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md).
Заполнение singleton 14b575630+48 из CDN JSON прослежено следующим этапом выше;
порядок с GMC2 Start, active environment и поздние изменения globals/build открыты.

После подтверждённого пользователем обновления U02 частичен: новые индексы
34 изменённых и одного нового архива сохранены отдельно; 1565 CSV pakchunk1
извлечены и сравнены. Дальше обновлять затронутые зависимости/связи, не применять
прежние offsets к текущим архивам. См. [свежие результаты](../resource-tools/vampir/CLIENT-RELEASE-INDEX.md). [Аудит и происхождение](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md).
U01 частичен: нет полной SHA-проверки остальных архивов, game/Android version
неизвестны, compatibility gate ещё не готов. EXE-bound исследования сохранены.

H03b остаётся частичным: выбранные send/receive пути подтверждены offline,
но нет server-compatible connection/session. Не повторять закрытые исследования.
H04a закрыт в HEADLESS-AUTH.md: SDK auth graph/code-refresh forms.
H04b начат: GMC2 selector проверен на 256 mode values, активный mode неизвестен.
HEADLESS-SDK-CONFIG.md. Далее settings+0x49/getters 0x144524390/0x14452b820,
response/decode → authTokenUrl/authAccountUrl/authUrl/clientId/region, browser code
и token responses/expiry→SDK session→game Login. Также connection setup, receive accumulation,
readiness/таймауты и session lifecycle. Затем полный Notify→wire и live canary.

Закрытые bounded этапы: raw stage/block decoder, listener loop/receive-A,
Dispatch до PingResult OnHandler entry, receive-B/ID bookkeeping, send-B/copy,
queue drain→Winsock send. Для drain61 native cases; portable pump прошёл real
IPv4 loopback test. HEADLESS-SEND-DRAIN.md. Native fatal close/diagnostic,
nonempty notifications/concurrent lifetime и whole transport integrity ещё unknown.
Runtime OutboundFrames хранит partial head offset; socket_send не выполняет
connect/retry и требует от session owner readiness scheduling/error handling.

Уже подтверждено:

- Ping payload и исходящий send-A кадр: HEADLESS-PING-CODEC.md и HEADLESS-SEND-FRAME.md.
- CRC32/XOR: HEADLESS-FRAME-PRIMITIVES.md.
- Length probe 0x144aa9a90 и статическая связь B callback → Dispatch:
  HEADLESS-RECEIVE-ENVELOPE.md. Вход Dispatch имеет ID+3/body+5;
  исходящий send-A — ID+7/body+11. Эти слои нельзя отождествлять без tracing.
- Смена ключа: Notify handler 0x146765050 → ack ID12 → setter 0x144aab330.
  Ключ приходит в Notify ID11; send ack вызывается до записи peer+248.
  HEADLESS-KEY-CHANGE.md, headless-key-change.json. Первичная авторизация,
  генерация ключа сервером и доставка ack этим не доказаны.

Библиотека отчётов: F:/PhoneExit Resources/Vampir/code-clues/.
Исходные адреса относятся только к указанному в отчётах SHA EXE.
Login/LobbyLogin имеют одинаковые ID3/4 при разных схемах и контекстах.
H04 (SDK auth) остаётся отдельной зависимостью. U01 делать до приёма
следующего обновления игры; новые версии без проверки не считать совместимыми.

Критерий продукта: Windows без процесса игры, 10–20 аккаунтов, управление
через живую 2D-карту, проверенный фарм, замеренная нагрузка и воспроизводимые
обновления данных. Статические связи и offline replay этот критерий не закрывают.
