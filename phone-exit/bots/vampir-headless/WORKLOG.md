# Самостоятельный Vampir — журнал работы

## 20 октября: writer LobbyLogin и SDK / NID inputs

Ghidra расширен до 331 функции / 151 предупреждения. Native writer LobbyLogin
исполнен на 24 bodies; добавлены отдельный bounded payload и binder пяти
строк. GetPlayerId подтверждён settings diagnostic; NID accessor связан
с UserInfo +0x170 / I_JoinedCountryCode. В составной metadata строке найдены
27 обращений к 26 ключам, включая параметры игры / SDK / устройства.
Полная сериализация и numeric context пока не перенесены. Прошла 21 целевая
проверка; сетевых попыток и передачи реальных Login tokens не было.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-WRITER.md).

## 20 октября: реальный LobbyVersionResult через HK

Связаны CDN globals и lobby connect на одной native машине: 20 сценариев,
host сохраняется, uint32 port сужается до word. Добавлен отдельный ограниченный
LobbyVersion probe. Первая попытка дала общий exception, вторая показала
send 94 / recv 28 и ошибку decoder. Исправлена ошибка выбора режима: lobby
сохраняет header (offset 0), game использует offset 3. Третья попытка получила
ID 2, code 0, flag false, body 23 байта. Сырые ответы не сохранялись.
Login и ServerListRead не отправлялись. Все сокеты закрыты, HK-клиент остановлен
с exit 0. Прошли 36 целевых тестов. Далее — LobbyLogin / ID 104 до игрового
endpoint и персонажей. [Источники и границы](LIVE-LOBBY-VERSION.md).

## 20 октября: порядок отправки лобби и connected flush

Ghidra расширен до 324 функций / 150 предупреждений. Проверка инструкций
обнаружила пропущенную псевдокодом отправку LobbyVersion перед исходным
запросом. Полный wrapper исполнен в восьми scenarios с captures lower sender;
connected callback — в четырёх scenarios с buffer / queue fixtures.
Callback сохраняет sequence. Настоящий send-A assembly с lobby writers дал
12 кадров; отдельные runtime encoders совпали побайтно. Пять новых и девять
смежных тестов прошли; три проверки экспорта также прошли. Внешних сетевых
попыток нет. Следующая граница — config globals, preparation / connect /
pending queue вместе и decoder ответа списка серверов.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-LOBBY-CONNECT-FLOW.md).

## 20 октября: отдельный LobbyVersion и codecs запроса списка серверов

Ghidra расширен до 318 функций / 145 предупреждений. Связаны четыре lobby
packet tables, исполнены ID getters. Таблица lobby peer доказана через
construction stores: её slot +0x40 создаёт LobbyVersion; поле +0x40 пакета
происходит из GetComputerNameW. Это отдельный handshake от игрового Version.
Два writer и VersionResult reader прошли 20 исходящих bodies, четыре ответа
и 23 коротких префикса. Добавлены bounded codecs без выбора неизвестных
settings. Новых сетевых попыток и запуска игры нет; decoder коллекций ID 104
и полный connect / flush лобби остаются открытыми.
[Подробности](../resource-tools/vampir/HEADLESS-LOBBY-HANDSHAKE.md).

## 20 октября: схема LobbyLoginResult и связь с игровым Login

Экспорт Ghidra расширен до 309 функций / 142 предупреждений. Discovery
сверил 58 direct calls в 34 корнях: Lobby Login отправляется через send-A,
а ответ списка серверов вызывает master model Update. LobbyLoginResult
не содержит списка; его две строки переходят через wrapper в игровой Login.
Reader исполнен на семи bodies и 72 коротких префиксах. Добавлены отдельный
bounded decoder и binder без подмены другого контекста. Все 19 целевых тестов
прошли. Сетевых попыток и запуска игры не было; lobby connect и decoder
списка серверов остаются следующими шагами.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN.md).

## 20 октября: Version probe и уточнение границы лобби

Ghidra экспорт расширен до 297 функций / 123 предупреждений. Connected path
сбрасывает ключ / sequence и передаёт локальный IPv4 без порта в callback.
Добавлен ограниченный Version exchange; пять новых и 20 смежных runtime-тестов
прошли. Один внешний probe через HK отправил 199 байт к CDN-лобби и не получил
ответа за 10 секунд. До попытки роль адреса для игрового Version доказана
не была; timeout не считается результатом игрового входа. Теперь CLI требует
явный диагностический режим. Проверен существующий native send drain:
на этом этапе дополнительной оболочки нет. Login не отправлялся, сокет закрыт,
HK-клиент остановлен с exit 0. Следующая граница — lobby flow и игровые записи
серверов в master model. [Источники и ограничения](VERSION-PROBE.md).

## 20 октября: recovered-base AppVersion и настоящий TCP connect к лобби

Выбран явный source profile собственного клиента; это не определение active
GConfig игры. Loader проверяет текущие EXE / PAK / INI и неизменяемый snapshot,
AppVersion привязывается к Version+0x10 / Login+0x40 с отказом при конфликте.
CDN fetch получил общий SOCKS-маршрут без direct fallback. Через HK заново
получен CDN HTTP 200 / 6000 байт, real / REAL. Один TCP connect к выбранному
лобби прошёл; за три секунды данных нет, игровых отправок нет, socket закрыт.
Все 16 целевых тестов прошли. Временный HK-клиент остановлен, exit 0.
[Источники и границы](GAME-SOURCE-PROFILE.md).

## 20 октября: собственный CPUID helper и чтение CPU текущего ПК

Собрана DLL из собственного C++ с закреплёнными MSVC / SDK, размер 104 КиБ.
Две сборки дали SHA 6a63c280d35ee267e0bea29ab0c64dda2f8a7d8fd07d84115c285144d69b964d.
Reader проверяет binary SHA и source receipt; runtime не требует analysis SDK.
Реальные vendor / brand прочитаны без вывода значений и сверены с существующим
native replay при передаче этих строк в CPUID fixtures. Binding с наблюдениями
готов для явного Version template; другие поля не угадываются. Все 19 целевых
тестов прошли, включая настоящие C ABI проверки коротких / null buffers.
Игрового запроса ещё нет. [Сборка и границы](WINDOWS-SYSTEM-INPUTS.md).

## 20 октября: CPU formatter, enum form и привязка двух полей Version

Исполнена полная CPU-цепочка initializer / getters / trim / formatter:
девять сценариев, ASCII whitespace, внутренние разделители и пустая brand.
Установлен actual enum setter по vtable constructor. Source form 2 проходит
настоящие factory argument loads / virtual dispatch, два stores и lookup,
давая Windows. Четыре сценария проверяют form / flags отдельно.
Runtime helper заполняет два поля явного Version template без изменения
прочих inputs и с отказом на конфликт. Все 16 целевых проверок прошли.
Ghidra: 295 функций / 121 предупреждение. Реального игрового запроса нет.
[Источники](../resource-tools/vampir/HEADLESS-VERSION-CPU-STRING.md).

## 20 октября: Windows suffix в runtime и повтор SDK SignIn через HK

Native Windows getter исполнен на семи сценариях с повторным чтением кеша.
Сверка структуры уточнила пятое число: suiteMask по +0x118, не servicePackMajor.
Добавлен reader GetVersionExW; его результат для процесса бота подключён к
NID osVersion. Реальный SignIn через свежий HK-маршрут принят, player ID /
SDK token получены без сохранения. Временный клиент остановлен, exit 0.
Source descriptor platform context установлен как ENnOsType; 12 native
selector / lookup scenarios проверяют обе ветви scoped flag. Сам flag ещё
не перенесён как известный в Version. Ghidra: 293 функции / 121 предупреждение.
Все 15 целевых проверок прошли.
[Источники и границы](../resource-tools/vampir/HEADLESS-VERSION-WINDOWS-CONTEXT.md).

## 20 октября: CPU inputs и оставшиеся источники игрового входа

Переиспользован экспорт Ghidra и RIP / unwind indexer. Найден настоящий
initializer двух строк Version: CPUID vendor и brand. Native initializer
с обоими getter проверен на Intel / AMD / unsupported / disabled fixtures.
Уточнены compiled pointer tag, raw DWORD 1 и источник AppVersion; значения
не объявляются неизменными active globals. Экспорт расширен до 289 функций,
120 предупреждений; три новых проверки прошли. Runtime не менялся,
игровой вход не выполнялся. [Источники](../resource-tools/vampir/HEADLESS-GAME-LOGIN-INPUTS.md).

## 20 октября: новый HK-аккаунт и успешные SDK SignUp / SignIn

Создан ящик bot-hk-test@vampir.top, квота 100 МБ. Добавлен явный режим
регистрации WebView2 через SOCKS с однократными действиями, выключенным
маркетингом и кодом из readonly IMAP. Уточнён реальный формат: пять цифр,
sender noreply@netmarble.net и отдельный subject регистрации. UID baseline
исключает старые письма. Секреты передаются pipes и не сохраняются.

После уточнения переходов и паузы из-за ограничения отправки пройден полный
сценарий; NID callback вернул joinedCountryCode HK. Отдельные реальные SDK
SignUp и SignIn приняты: первый вернул player ID, второй — player ID и token.
Игра, игровой Login и персонажи ещё не проверены. [Подробности](NID-REGISTRATION.md).
17 целевых тестов и smoke прошли. Временный HK-клиент остановлен, exit 0.

## 20 октября: общий маршрут через HK и различие стран аккаунта / запроса

Закреплён PySocks 1.7.1 с SHA wheel, установлен в игнорируемую папку runtime.
Добавлен отдельный SOCKS5 socket, без глобального monkeypatch; HTTPS сохраняет
проверку сертификата / hostname. NID WebView2, fetcher GMC2 и SDK executor
получают один порт. Проверка SHA / status / port исключает смешение снимков.

Через Phone Exit подтверждён HK; получен новый GMC2 HTTP 200 / 13 777 байт,
geoIp.isoCountry HK. Две попытки NID → SDK SignUp через этот маршрут получили
HTTP 400 / 1602. Диагностика подтвердила `not allowed country for game`,
NID joinedCountryCode UA и SDK body countryCode HK. Причинность не установлена.
В My Profile видимого поля смены страны нет; настройки аккаунта не менялись.
Пользователь выбрал готовый аккаунт для проверки; запрошена почта,
пароль можно ввести в штатном окне. Новый ящик не создавался.
Временный клиент остановлен, child exit 0; системные маршруты не менялись.
31 целевой тест и smoke WebView2 прошли. [Детали](SOCKS-ROUTE.md).

## 20 октября: реальный HTTPS через HK-телефон Phone Exit

По уточнению пользователя проверено существующее приложение Phone Exit.
Личный каталог ответил HTTP 200, найден доступный незанятый HK-выход.
Одноразовый локальный клиент установил соединение и открыл SOCKS на порту 17948.
HTTPS Cloudflare trace через socks5h вернул loc=HK, curl exit 0. Клиент остановлен
после проверки и завершился с code 0; системные маршруты и настройки ОС не менялись.
Ключи каталога / сопряжения оставались в pipes, IP в журнал не выводился.
SDK SignUp через этот выход ещё не выполнялся: нужно добавить общий маршрут
для WebView2, GMC2 и SDK HTTP; прежний executor игнорирует системный proxy.

## 20 октября: отдельный SDK SignUp и фактический отказ по стране

Уточнено сообщение SignIn 1203: `not exist player channel`. Найдены diagnostics
FAuthImpl::SignUp / ExecSignUp, Ghidra расширен до 281 функции / 112 предупреждений.
Callback invoke без unwind оказался одним JMP; экспортирован настоящий target.
Четыре bounded native-сценария SignUp подтвердили четыре поля и credential,
без playerId. Endpoint — authUrl + v1/sign-up; общий POST wrapper сохранён.
Добавлены явный режим создания, отдельный parser player_id без access_token
и запрет смешения transport endpoints. Ошибка входа не включает SignUp сама.

Две реальные попытки SignUp получили HTTP 400 / 1602; диагностическая попытка
уточнила сообщение `not allowed country for game`. Игрок не создан, SignIn
после этого не запускался. Native country getter читает settings+0x3f0;
источник записи пока неизвестен. Сохранённый GMC2 geoIp.isoCountry — UA.
Страну не подменяли. Пользователю задан вопрос о доступе установленной версии
из текущей сети. Пользователь подтвердил: напрямую игра на этом ПК не работает,
подходят Япония и Гонконг. В личном каталоге Phone Exit найден доступный
незанятый выход HK; подключение ещё не выполнено. Четыре теста SignUp,
четыре runner, шесть HTTP, три Ghidra, четыре прежних SignIn и четыре parser
прошли. [Происхождение и ограничения](../resource-tools/vampir/HEADLESS-SDK-SIGN-UP.md).

## 20 октября: настоящий NID callback из встроенного окна и отказ SDK

Добавлен отдельный script формы signin, привязанный к точному HTTPS origin
и двум путям страницы. Используются штатные поля и кнопка; после одной отправки
автоматизация останавливается. Пароль передаётся через stdin и pipes без
аргументов процесса или файлов; CAPTCHA / подтверждение остаются на странице.

Обе реальные попытки вернули callback, принятый существующим parser, после чего
выполнен один SDK POST на попытку. Обе получили HTTP 400. После первой добавлена
ограниченная диагностика только числового errorCode; вторая вернула 1203.
Его семантика не установлена, токены и тело ошибки не сохранялись.
14 целевых тестов прошли, включая шесть HTTP, четыре adapter, три runner
и один DOM fixture с положительными и отрицательными сценариями. Настоящий
WebView2 smoke сохранил прежние отмены URI / popup и synthetic callback.
Игровой сокет, SDK-сессия и персонажи этим не подтверждены.

## 20 октября: аккаунт Netmarble создан, личный кабинет открыт

Исходная вкладка после потери управления больше не обнаружена. Попытка входа
вернула сообщение о соединении с reCAPTCHA, не установив состояние аккаунта.
После перезагрузки штатная регистрация продолжена с новым письмом и кодом.
По прямой просьбе пользователя заполнены пароль и подтверждение. Next привёл
к Account Registration Complete, Confirm — к `/me/home` с тестовой почтой
и Services In Use 0. Видимой CAPTCHA в успешной цепочке не было.
Секреты в проект не сохранены, снимки результата — только в `.local/previews/`.
Это подтверждение аккаунта и входа на сайт, а не SDK или игровой сессии.
Далее — NID callback в контексте бота и настоящий SDK sign-in.

## 20 октября: письмо Netmarble получено, почта подтверждена

Доступ к Chrome появился после изменения настройки Work. На официальном
сайте из формы входа открыта Create an Account. По отдельному разрешению
пользователя приняты Terms of Service и Privacy Policy без Marketing Consent.
Письмо доставлено в тестовый ящик; полученный через защищённый IMAP код принят
сайтом. Открыт Set Password. Пароль ещё не задан, создание аккаунта и вход
не завершены. CAPTCHA в пройденных шагах не отображалась. Это браузерная
проверка, а не готовая регистрация в runtime. Секреты в документах не сохранены.

## 20 октября: runner NID → SDK и проверка почтового ящика

Добавлены воспроизводимый Windows-профиль, HTTPS executor без повторов
и runner с проверкой SHA и трёх ключей. Экспорт Ghidra расширен до 278 функций
и 111 предупреждений; публичный GMC2 GET вернул HTTP 200. Окно входа запущено,
настоящего callback и SDK POST ещё нет. 11 тестов HTTP / runner / адаптера,
три проверки Ghidra и smoke WebView2 прошли.

Пользователь уточнил, что аккаунт Netmarble ещё не создан, и поручил регистрацию
и получение письма. IMAP по TLS с проверкой сертификата успешно авторизован,
INBOX открыт только для чтения, писем нет. Пароль в проект не сохранён.
Регистрация пока не выполнена: Browser use отключён в настройках Work.
[Источники, команды и границы](NID-SDK-RUNNER.md).

## 20 октября: WebView2 host и синтетический callback

Закреплены Core / WinForms / x64 loader DLL 1.0.3856.49 вне Git. На установленной
Runtime 155.0.4283.62 прошёл невидимый smoke: synthetic callback, две отмены
внешней навигации, один popup. После завершения тестовых browser-процессов нет.
Восемь unit-тестов прошли; URL / callback в аргументы и журналы не попадают.
Настоящая auth-страница и аккаунт ещё не открывались. [Границы](NID-BROWSER.md).

## 20 октября: URL входа NID и весь ASCII encoder

Ghidra расширен до 277 функций / 111 warnings. 99 native-профилей всего
encoder совпали с общим escape; whitelist / hex исполняются настоящие.
Runtime связывает context с точным SDK endpoint, ограничивает размер и
поддержанный профиль. Публичный источник endpoint повторно проверен offline.
Браузер / реальная авторизация не запускались.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-NID-WEB-URL.md).

## 20 октября: контекст штатного окна NID

Ghidra расширен до 276 функций / 110 warnings. Проверены native инструкции
сборки десяти базовых пар на восьми профилях и весь getter webViewType
на 256 значениях. Runtime возвращает неизменяемый контекст, без сериализации
непроверенного query. Real identity / browser / account не использовались.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-NID-WEB-CONTEXT.md).

## 20 октября: три ключа Windows-устройства и gate профиля

Наблюдены три разные REG_SZ длиной 32 символа из точных HKCU-путей.
Сохранены в локальном основном профиле с источником, датой и SHA EXE;
значения не логировались, Windows registry не менялся. Confirmation unknown,
серверная привязка не проверена. Добавлены ограниченный reader и gate
required для подготовки Login. 20 тестов прошли; реальное двойное чтение
через новый reader также выполнено. [Источники и границы](WINDOWS-IDENTITY.md).

## 20 октября: общий NMDeviceKey в Version и Login

Ранее неизвестный getter связан с исследованным NMDeviceKey. Проверена
настоящая обёртка и повторное использование cache на четырёх профилях.
Runtime связывает ключ с обоими payload, SDK token и отдельный NID — с Login.
В Windows найдена точная запись NMDeviceKey; значение не логировалось,
к основной почте не привязывалось. SDK-пара / NID identity ещё не получены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-DEVICE-INPUT.md).

## 20 октября: Version → Login через сокет

Добавлен полный decoder ID2 и LoginFlow поверх готовых payload / framing.
GameConnection маршрутизирует ID2 / ID4 в зарегистрированный bootstrap;
он не выводит готовность мира или событие запроса списка из code 0.
31 тест прошёл. Все 43 native-кадра совпали; socketpair проверяет смену
ключа между Version и Login, результат и отдельное разрешение ID101.
Реальные SDK / device inputs и сервер не использованы.
[Контракт, источники и границы](LOGIN-FLOW.md).

## 20 октября: владелец подключённого сокета

Добавлен `GameConnection` с ограниченным pump, приёмом, отправкой и передачей
ответов в selection flow. Смена ключа обрабатывается до следующего пакета;
ack остаётся под старым ключом. EOF / ошибка / таймаут закрывают сокет,
очередь и данные. 32 локальных теста прошли, из них девять новых socketpair.
Version / Login и реальная авторизация ещё не подключены.
[Контракт, источники и границы](GAME-CONNECTION.md).

## 20 октября: поток приёма и локальная сессия списка / выбора

Добавлен `ReceiveStream` поверх проверенных parser / decompressor / receive-B.
Он сохраняет два уровня буферизации, выдаёт один пакет за вызов, ограничивает
работу и память, позволяет сменить ключ до следующего пакета и проверяет EOF.
11 новых и 21 прежний тест прошли. В socketpair-тесте отправлены запросы
ID101 / ID109 и приняты синтетические ID102 / ID110 по семь байт за чтение.
Реальный сервер, SDK / устройство и полный владелец соединения ещё открыты.
[API, источники и границы](RECEIVE-STREAM.md).

## 20 октября: runtime списка и выбора персонажа

Общие codecs связаны с очередью одного соединения через
`CharacterSelectionFlow`. Добавлены явное разрешение запроса списка,
ожидание ID102, выбор записи, ожидание ID110, лимиты, таймаут и очистка
при разрыве. Текущий rawF0 можно обновить до выбора. При code 0 ID110
фиксируется получение ответа, без утверждения о готовности мира.
12 новых и 15 прежних тестов прошли; все 19 сохранённых native-кадров
совпали. Проверки runtime выполняются без инструментов исследования.
Реальные сокет / SDK / device context и событие входа в выбор ещё не связаны.
[API, источники и границы](SELECTION-FLOW.md).

## 20 октября: caller RequestA/slot 90 подтверждён

Проверено 505 direct getter calls, 16 candidates unresolved, 9 roots не
декодировались. Найден caller 0x1468f1d70. 32 native cases исполнили caller →
getter → slot 90 → RequestA/constructor/send capture. Owner/lifecycle неизвестны.
Ghidra: 80 функций/44 предупреждения. Девять тестов прошли: три новых,
три CharacterList boundary и три Ghidra. Проверены 1311 локальных ссылок,
битых нет; полный набор тестов не повторялся. Runtime/network не менялись.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-CALLER.md).

## 20 октября: selection lifecycle и virtual 38 callback

Экспорт Ghidra расширен до 76 функций/42 предупреждений. Проверены 7 значений
raw32 event и callback leaf → singleton virtual 38. Девять тестов прошли:
три новых, три selection service и три Ghidra. Проверены 1298 локальных ссылок,
битых нет. Полный набор тестов не повторялся;
регистрация/emitters/backend dispatch остаются статическими или captures.
Runtime и live session не менялись.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-LIFECYCLE.md).

## 20 октября: World.Id2/CharacterSelect path связан с native getter

Registry/source diagnostics и World parsers привязали LevelPath→record48.
Actual constructor/field-store/hash/accessor/virtual 20 getter исполнились
с rows1/2 из base и current patch CSV. Выход key 2: CharacterSelect_02.
Old patch source stamp stale; использован существующий audited release snapshot,
CSV bytes совпали, полные SHA текущих архивов проверены. Ghidra: 63 functions/
36 warnings. Три новых, три lookup и три Ghidra tests прошли. Runtime loader/
mount priority/live session не проверялись; full suite не повторялся.
[Отчёт, SHA и ограничения](../resource-tools/vampir/HEADLESS-WORLD-STATE-LABEL.md).

## 20 октября: state registry lookup и неизвестная реальная метка

Ghidra lookup/registry/generic loader exports расширены: 54 functions/33 warnings.
13 native cases проверили exact key/hash collision/inline record+8/accessor,
label caller. Registry getter/record contents всё ещё fixtures; фактическая
строка key 2 не установлена. Три новых, три state transition и три Ghidra tests
прошли; full suite/runtime/network не менялись.
[Отчёт, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-STATE-LOOKUP.md).

## 20 октября: selection state preparation и deferred callback

Ghidra virtual 40 dependencies/callback экспортированы: 48 functions/32 warnings.
10 native preparation cases проверяют guard/ready/pending/state2/schedule;
12 independent callback cases — player/phase/busy/flags/raw field writes.
Scheduler/load/text/lookup backends explicit fixtures. Direct slot 90 вызов
на covered paths не найден. Три новых, три selection service и три Ghidra tests
прошли; runtime не менялся, полный suite/live session не проверялись.
[Отчёт, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-STATE-TRANSITION.md).

## 19 октября: derived selection service и CharacterSelect handoff

Ghidra ctor/derived prefix/table связали requestA с slot 90. Native prefix
allocation success/failure и base singleton getter проверены. Actual virtual 50
передаёт raw64/raw32/state+f0 в packet 109→handoff110; 4 vectors совпали.
Ghidra: 43 functions/30 warnings. Три новых, три WaitingEnd и три Ghidra tests
прошли; full suite не повторялся. Runtime не менялся; сеть/ответ/выбор не готовы.
[Отчёт, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-SERVICE.md).

## 19 октября: WaitingEndNotify инициирует requestB

Caller diagnostic идентифицировал WaitingEndNotify/ID 27, registration/table
проверены. 24 native handler/predicate cases: две комбинации достигают
CharacterListRead constructor/virtual send capture. Quick-select/next virtual
paths различаются по peer flag/policy/selected value. Ghidra: 39 functions,
26 warnings. Три новых, три boundary и три Ghidra tests прошли. Runtime не
менялся; full suite/live lifecycle/response 102 не проверены.
[Отчёт, SHA и границы](../resource-tools/vampir/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## 19 октября: post-Login reset и CharacterList request boundary

Ghidra singleton ctor/table→virtual+0x28 подтвердили reset коллекций/флагов.
8 native reset variants и 2 independent CharacterList request routines исполнены.
ID 101 и empty writer leaf проверены; Login→request caller edge не доказан.
Ghidra: 37 functions/19 warnings. Три новых, четыре LoginResult handler и три
Ghidra tests прошли. Runtime не менялся; полный suite не повторялся.
[Отчёт, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-BOUNDARY.md).

## 19 октября: native LoginResult handler

38 scenarios объединяют actual body reader и handler/covered gates. Проверены
8 state stores, signed early exit, controller server updates, raw16 conversion,
error/SDK branches. FString copies и UI/SDK/state backends явно captured.
Ghidra дополнена post-state target: 33 functions/15 warnings. Четыре новых,
четыре reader и три Ghidra tests прошли; полный suite не повторялся.
Runtime не менялся. CharacterListRead send/session ещё не доказаны.
[Отчёт, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-HANDLER.md).

## 19 октября: native LoginResult reader и общий decoder

Ghidra пакет расширен с 22 до 32 функций; export/verifier успешны, 15 warnings
сохранены. Исполнены constructor/nested readers/stdstring/UTF-8, 21 full body
vectors и 332 short inputs. Bool нормализуется; native trailing принимается,
общий LoginResultBody требует точного потребления. Четыре новых и десять
смежных Ghidra/VersionResult/Login writer tests прошли. Полный suite не
повторялся; decoder не подключён к live runner. Handler только static-read.
[Отчёт, SHA, источники и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).

## 19 октября: Login handoff → native frame/queue

Ghidra handoff/wrapper прочитаны перед native replay. 34 scenarios исполнили
lookup/timeout/getter/virtual send/Login writer/CRC/XOR/queue. 29 кадров
совпали с LoginPayload и frame primitives; 2 duplicate и 3 transport refusal
подтвердили границы. Insert/notify captures, clocks/drain/socket не исполнены.
Три новых и семь смежных tests прошли; полный suite не повторялся.
Runtime не менялся; real profile/network/session не использованы.
[Отчёт, SHA, источники и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-SEND-PATH.md).

## 19 октября: native Login writer и общий body encoder

Прочитаны готовые Ghidra exports, затем исполнены writer/UTF-8/archive IO.
25 успешных payload vectors и 40 IO failure fixtures: 30 строковых отказов
игнорируются helper path, 10 скалярных останавливают writer. Расширенный
capture снимает +0x128=0 в 16 прежних preparation cases. LoginPayload добавлен
в общий Python core с immutable/redacted inputs и атомарным byte budget.
Четыре новых tests, смежные Login fields/Version writer/Version send path
проверены; полный suite не повторялся. Live runner/сессия ещё не подключены.
[Отчёт, SHA, источники и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-WRITER.md).

## 19 октября: общее правило и дополнительные инструменты

AGENTS.md закрепляет выбор Ghidra/CUE4Parse/Dumper-7 перед ручным анализом.
Установлены CUE4Parse1.2.2.202610 и отдельный SDK10.0.402; NuGet lock,
архивы/SHA и повторная установка проверены. Три loose asset headers
совпали с действующим layout, четыре PAK имеют encrypted index.
Dumper-7 pinned commit собран x64/v143 через project вместо неполного solution;
PE DLL проверена, injection/game SDK не выполнялись. Три смежных Ghidra tests
и проверка 1100 локальных Markdown-ссылок прошли. Runtime бота не менялся.
[Пути, результаты и границы](../resource-tools/vampir/ANALYSIS-TOOLS.md).

## 19 октября: Ghidra вместо дробного ручного анализа

Официальные Ghidra 12.1.4 и Temurin21 закреплены SHA, импортирован EXE как
данные. Три exports по 22 функции; C outputs совпали побайтно. 13 warnings
сохранены. Три новых и три смежных Login tests прошли; game/profile не запускались.
[Пути, команды и static findings](../resource-tools/vampir/HEADLESS-GHIDRA.md).

## 19 октября: Login constructor/SDK поля

16 native scenarios, три новых и шесть смежных tests прошли. Native constructor/cached
getters/assignments разделили NetmarbleId и SDK token, показали old-cache
path. Handoff capture, без writer/network. Runtime не менялся; full suite379
не повторялся. Реальные profile/credentials не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-FIELDS.md).

## 19 октября: VersionResult → Login entry

39 native scenarios read/dispatch/handler/bounded gate проверили переход
в 0x1467a9700 для code 0; PktLogin ctor связан статически. Три новых и семь смежных tests
прошли. Runtime не менялся; full suite379 не повторялся. Actual game/network/
profile/credentials не использованы, Login body ещё capture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-RESULT-HANDLER.md).

## 19 октября: Version wrapper → полный кадр/очередь

18 native scenarios: 14 exact ciphertext frames и 4 pre-frame gates.
Wrapper/send-B/Version writer/CRC/XOR/queue append исполняются вместе.
Queue copy сохраняется после archive overwrite; три новых и шесть смежных tests прошли.
Runtime не менялся; полный suite379 не повторялся. Real network/session нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-SEND-PATH.md).

## 19 октября: PktVersion writer → общее ядро

14 native vectors writer/UTF-8/archive совпали с переносимым VersionPayload.
Три новых tests прошли. Полный headless suite: 379 tests за 298.328s, OK.
Getters/frame/server response не проверены.
Игра/profile/process memory/credentials/network не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-PACKET-WRITER.md).

## 19 октября: connected callback → PktVersion

6 native scenarios исполнили game body/packet constructor; первый packet
PktVersion/ID1, send target capture. Проверены raw fields, empty/Unicode/max
DWORD и send-false/gate; три новых и шесть смежных tests прошли. Getter meanings/wire/session
открыты. Runtime не менялся; полного suite не было; сеть/game/profile не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECTED-VERSION-PACKET.md).

## 19 октября: connected delegate → game target

12 native scenarios исполнили binding slice/allocator wrapper/bridge/action.
Game vtable source-bound, callback 0x1467a9cd0 пока capture. Уточнено поле
P+0x310 как units storage, не owner count. Три новых и шесть смежных tests прошли.
Runtime не менялся; full suite не повторялся; network/game/profile не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).

## 19 октября: socket ready → transport recipient

10 native scenarios связали две broadcasts с OnTcpPeerConnected и
owner callback gate. Source constructor/registration/table/diagnostic bindings
проверены. Три новых и шесть смежных tests прошли. Runtime не менялся; полного suite не было.
Owner target/endpoint/configuration fixtures, actual session/network нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READY-NOTIFICATION.md).

## 19 октября: socket option translation

8 native integrations и 95 direct selector calls: engine slot+0x60
исполняется вместо option capture. Getsockopt import/export и raw arguments
проверены; failure/output gates различены. Три новых и шесть смежных tests прошли.
Runtime не менялся; полный suite 316 не повторялся. Реальной сети/session нет.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-ERROR-OPTION.md).

## 19 октября: socket mode/readiness job

14 native scenarios, три новых и шесть смежных tests прошли. Mode
helper/source ioctl body/job slots/select state gates/completion routes
исполнены. Worker stop перед второй iteration и manual completion drain
явно записаны. Syscalls/queue/option/recipient captures, real sockets нет.
Runtime не менялся; полный suite 316 не повторялся. Game/profile/credentials/network не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READINESS-JOB.md).

## 19 октября: WSA error mapping

43 native cases, три новых и шесть смежных tests прошли. Mapper
связан с engine constructor/global/vtable и WSAGetLastError export.
Code и switch data разделены; accepted inputs 10035/10036/10037 подтверждены
через реальный wrapper. Runtime не менялся; полный suite 316 не повторялся.
Game/profile/credentials/network и реальные DLL calls не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WINSOCK-ERROR-MAPPING.md).

## 19 октября: endpoint connect/result wrapper

16 native scenarios, три новых и шесть смежных tests прошли. Native
sockaddr layout/connect call, lower/wrapper расхождение и wait gates
проверены. Raw engine codes не названы WSA errors без mapping evidence.
Runtime не менялся; полный suite 316 не повторялся. Реальные game/profile/
credentials/network/OS wait не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-CONNECT-RESULT.md).

## 19 октября: resolved recipient/socket creator

7 native scenarios, три новых и шесть смежных tests прошли. Source
vtable stores связали resolver callback с peer recipient и socket creator.
WS2_32 ordinal 23 проверен по local export socket с SHA. Syscall/engine
options/mode/connect — captures; реальные сокеты не открывались.
Runtime не менялся; полный suite 316 не повторялся. Game/profile/credentials не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVED-SOCKET-SETUP.md).

## 19 октября: resolver job results

8 native scenarios, три новых и шесть смежных tests прошли. Vtable
run/completion и PE imports getaddrinfo/inet_ntop связаны с source.
Native family traversal/swap и empty/error gates исполнены; Winsock,
vector append, scheduler и callback dispatch fixtures/captures.
Runtime не менялся; полный suite 316 не повторялся. Game/profile/network не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVER-JOB-RESULTS.md).

## 19 октября: lower connect/resolver handoff

12 native integrations, три новых и восемь смежных tests прошли.
Peer fields, обе registration insert branches, lexical numeric/hex и job
stores подтверждены. Reset/lookup/parser/scheduler — fixtures/captures;
RAX сохранён cookie-check fixture для правильного bool результата.
Runtime не менялся; полный suite 316 не повторялся. Game/profile/network не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## 19 октября: ConnectToServer endpoint mapping

13 native integrations связали BeginGame target с primary/override
host/port и реальным endpoint constructor. Signed port guard подтверждён,
lower connect и ASCII/lifetime primitives fixtures. Три новых и восемь
смежных tests прошли. Runtime не менялся; полный suite 316 не повторялся.
Реальных game/profile/credentials/network connect не было.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).

## 19 октября: BeginGame server target

11 native cases, три новых и семь смежных tests прошли. Реальные
lookup collision walk и target setters связаны с BeginGame caller.
Missing/busy paths сохраняют прежнюю цель; raw words не названы портами
без consumers. Runtime не менялся; полный suite 316 не повторялся.
Реальные profile/credentials/game/HTTP/socket connect не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## 19 октября: title state и BeginGame SDK gate

10 native scenarios и три новых/шесть смежных tests прошли. Title
country/state slices отделены от IsSignIn SDK byte gate. Skip-middle
явно сохранён, полный title/button flow не заявлен. Runtime не менялся;
полный suite 316 из runtime milestone не повторялся. Игра/профиль/HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-STATE.md).

## 19 октября: title auth-success notification

Семь native scenarios связали manager-child/router с точным title
slot+0x08. Три новых и шесть смежных tests прошли. Channel getter/idp/CDO/
policy остаются fixtures, тело OnSuccessNetmarbleSDKAuth — entry capture.
Runtime не менялся, полный suite 316 из runtime milestone не повторялся.
Реальный профиль, credentials, игра и HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## 19 октября: optional Google PGS branch

Четыре native scenarios и три новых/шесть смежных tests прошли. Точные
diagnostics/vtables связали game-instance getter с Google PGS. Native
Windows SignIn передал unsupported result args; constructor/helper captures.
Original SDK result сохранён отдельно. Runtime не менялся; полный suite
316 из предыдущего runtime milestone не повторялся. Игра/профиль/HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-PGS-BRANCH.md).

## 19 октября: game success broadcast

12 native cases, три новых и шесть смежных regression tests проверили subscriber gates,
реальный slot+0x30 из title vtable, child args (2,1) и очистку pointer.
Registration/array ownership/prune/child virtual явно ограничены fixtures.
Runtime не менялся; игра, профиль, credentials и HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-SUCCESS-BROADCAST.md).

## 19 октября: silent result до игрового callback

12 интеграционных native cases исполнили silent dispatcher, bridge и
реальный игровой callback. Source-bound request/response jump сохранён.
Три новых и девять смежных tests прошли. Runtime не менялся, полный suite
316 из предыдущего runtime milestone не повторялся. Реальные scheduler,
response JSON/session, profile/credentials/HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SILENT-GAME-DISPATCH.md).

## 19 октября: ChannelManager silent handoff

12 native сценариев подтвердили GetAuth route, передачу player/callback
и Auth gate No PlayerID. Три новых и шесть смежных tests прошли.
Context/settings/storage/TFunction и error object dispatch явно ограничены
fixtures/stops. Provider selection ещё не восстановлен. Runtime не менялся,
последний полный suite 316 не повторялся; игра/профиль/HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## 19 октября: игровой AutoSignIn callback

15 native сценариев и три regression tests прошли. Найдены diagnostic,
вложенный logging callback, weak-owner result callback и descriptor caller.
Точные diagnostic literals связали GetChannelManager owner+0x170
с FChannelManagerImpl::SignInSilently; связь с GetAuth ещё не доказана.
Также прошли три смежных SDK result-dispatch tests.
Runtime не менялся; полный suite 316 из предыдущего runtime milestone
не повторялся. Игра, профиль и HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-AUTO-SIGN-IN.md).

## 19 октября: SDK result dispatch

Исполнены dispatcher, delegate copy/cleanup, binder, реальные virtual
clone/invoke и queued thunk. 16 сценариев подтвердили response pair/refcount,
очистку исходной привязки и AL=1 независимо от callback return.
Реальные game receiver/task graph/lifetime completion пока не исполнены.
Три новых и семь смежных tests прошли. Runtime не менялся; последний полный
прогон 316 тестов не повторялся. Игра, профиль и HTTP не использованы.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-RESULT-DISPATCH.md).

## 19 октября: SDK sign-in completion и общий parser

16 native сценариев проверили idpInfo, channel byte, сравнение player ID,
фактический SetSignIn и место вызова финального dispatcher. Сам dispatcher
и его делегаты остаются captures. Флаг входа может выставляться при неполном
ответе и не доказывает игровую сессию.

Общий offline parser требует canonical errorCode 0 и свежие token/player ID,
отклоняет дубли JSON-ключей и некорректные поля. Чувствительные значения скрыты
из repr, raw idpInfo не сохраняется. HTTP авторизации не выполнялся;
реальные credentials, registry/Saved и память процесса не читались.

Полный набор: 316 тестов, 230.600 с, OK. Проверены 475 относительных
Markdown-ссылок, UTF-8 и SHA отчёта; git diff --check без ошибок.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## 19 октября: native variant converter

Исполнены converter144476940, AsString1415e48f0, actual virtual TryGetString
1415ef250 и CRT. 10 cases number-string/string; factory/vtable/tag sources
сохранены, native parser selection не заявлен. Double fallback и другие
variants не исполнялись. Три regression tests OK; runtime/auth POST без
изменений, реальные credentials/storage/HTTP не использованы.
Также прошли 6 смежных response gates/fields tests, 450 относительных
Markdown-ссылок проверены, git diff --check OK. Полный suite последнего
runtime milestone 296/296 повторно не запускался.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-VARIANT.md).

## 19 октября: SDK response gates

18 native cases связали predicates/body/status/JSON/errorCode →player slice.
4 leaf helpers исполнены. _wtoi IAT подтверждён, вызван actual local CRT с SHA.
String errorCode domain явно ограничен: JSON/variant fixtures, numeric JSON
path не выдан за готовый. Три теста OK, auth POST/storage/keys не использованы.
Также прошли 7 смежных response/request tests; 444 относительных
Markdown-ссылок и git diff --check проверены. Runtime не менялся, полный
suite последнего runtime milestone 296/296 не повторялся.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-GATES.md).

## 19 октября: SDK sign-in response fields

Native auth constructor и response field slice проверены на 13 cases.
Подтверждены nested player keys и отдельный resultData.accessToken →module78.
JSON/settings/Save/module writes fixture captures, status source explicit
fixture. Network/errorCode/full callback не исполнены. Три tests OK;
реальные credentials, storage и auth POST не использованы.
Также прошли 4 SDK request tests; 435 относительных Markdown-ссылок
и git diff --check проверены. Runtime не менялся; полный suite последнего
runtime milestone 296/296 повторно не запускался.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-RESPONSE.md).

## 19 октября: migration allocator wrapper chain

10 native scenarios исполнили allocation/count/capacity/quantize/realloc
wrappers с fixture backend. Zeroing rounded tail в wrapper path отсутствует;
реальный backend policy не установлен. Cipher results совпали с independent
AES при explicit tail bytes. Regression test прошёл. Runtime не менялся.
Также прошли 6 смежных token/suffix tests, 431 относительных
Markdown-ссылок проверены, git diff --check OK. Полный suite 296/296
из предыдущего runtime milestone повторно не запускался.
Приоритет возвращён к SDK sign-in response/session для первого нового
профиля; миграция не выдана за завершённую и остаётся в задачах.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-MIGRATION-ALLOCATION.md).

## 19 октября: token payload и migration path

Native caller проверен на 16 container fixtures; split/base64url/JSON
primitive fixtures не выданы за полную проверку JWT. Helper не проверяет
signature/alg/sub. Источник migration channelKey связан initializer/caller.
8 native migration byte/AES/HEX fixtures показали rounded allocation и
неизвестный tail contract для unaligned input. Runtime не менялся, real
tokens/keys/registry/Saved/HTTP не использовались. Три regression tests OK.
Также прошли 4 смежных suffix/auth-path tests; 427 относительных
Markdown-ссылок и git diff --check проверены. Полный suite предыдущего
этапа 296/296 не повторялся: runtime не менялся.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-TOKEN-PAYLOAD.md).

## 19 октября: NID suffix byte/AES pipeline

Исполнен caller transform sub low-byte minus1, AES-NI key expansion/rounds
и byte-hex writer loop. Dispatch, key conversion, allocation и formatting
fixtures; real token/sub acquisition не исполнялись. 6 cases, aligned outputs
совпали с независимым AES-256 ECB. Добавлен общий strict ASCII aligned helper
nid_storage_path без I/O, keys не нормализуются. Три regression tests прошли.
Полный headless suite: 296 тестов, 216.125 с, OK; 480 относительных
Markdown-ссылок проверены, git diff --check без ошибок.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-NID-SUFFIX.md).

## 19 октября: auth-specific directory

Исполнены auth gate, reused native compare и Load filename continuation.
8 fixtures auth type/context success × prior shared flag. Выявлен netmarble
gate и sticky byte 14b4f13fd; Save/Initialize читают тот же byte (static refs).
SetupServiceSettingPath и command-context extraction сохранены source-bound,
суффикс/реальные аргументы не читались. Regression test прошёл.
Четыре смежных storage/load tests также прошли; 415 относительных
Markdown-ссылок и git diff --check проверены. Runtime не менялся, полный
headless suite предыдущего этапа 290/290 повторно не запускался.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-AUTH-PATH.md).

## 19 октября: Load device fields и filename

16 native fixtures исполнили две Load field-copy slices и post-restore gate/tag
dispatch. 3 constructor/path fixtures установили разные ServiceSettings.bin
и ServiceSetting.bin; Load continuation использует второе поле +0x2f8.
UObject/config/file I/O не исполнялись, active path не заявлен. Реальные
Saved/registry/keys не читались. Два regression tests прошли.
Смежные 2 storage tests также прошли; 412 относительных Markdown-ссылок
проверены, git diff --check OK. Runtime не менялся; полный suite
предыдущего этапа 290/290 повторно не запускался.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-LOAD-DEVICES.md).

## 19 октября: NID web/token device identity

Native key/getter/pair slices web/code/refresh подтвердили отдельный NID getter,
body getter и real identity остаются fixtures/unknown. Добавлены schema v2,
nid_device_key/source и идемпотентная запись без замены. Миграция сохраняет
профиль и прежние поля; первое NID identity сбрасывает confirmed по local policy.
Основная локальная база мигрирована, значения ключей не генерировались.
5 registry tests и native context regression прошли; HTTP/registry/Saved нет.
Полный headless suite: 290 тестов, 270.284 с, OK. 465 относительных
Markdown-ссылок проверены; git diff --check без ошибок.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md).

## 19 октября: SDK storage directory и NID key

Добавлен static index из 26 fragments: Save/Load/path/Initialize/NID key.
Шесть native path fixtures проверили predicate true, wrapper, join/slash append;
base directory/FString helpers fixtures. Найден отдельный DeviceKeyForNetmarbleId
в settings+0x628. Связь с web deviceKey не объявлялась. Реальные profiles/registry/
keys не читались, Save/Load не исполнялись. Два regression tests прошли.
Проверены также 11 device tests (10.579 с), 398 относительных Markdown-ссылок
и git diff --check. Полный headless suite повторно не запускался.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SDK-STORAGE.md).

## 19 октября: native SetDeviceKey

56 setter fixtures и 12 getter integrations исполнили native setter body
и ранее проверенный native ASCII compare/table. Platform/TLS block явно
заменён переходом; StoredValue/FString остаются fixtures. Проверены force gate,
сравнение и settings update после write=false. Save/path fragments сохранены
статически, реальные registry/Saved/keys не читались. Три regression tests OK.
Все 11 device tests прошли за 9.299 с; 398 относительных Markdown-ссылок
проверены. Общий suite в предыдущем этапе: 282/282; повторно не запускался.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-DEVICE-SETTER.md).

## 19 октября: native device getter lifecycle

Исполнен full GetNMDeviceKey без verbose logs и DeviceKey slice после выбора
platform. 8 NM fixtures с повторным вызовом и 12 DeviceKey fixtures. Проверены
приоритеты источников и отсутствие проверки write/Save return в caller.
Native GUID constructor/default formatter/hex writer reused; storage/parser/
platform/SetDeviceKey/Save — явные fixtures. Три regression tests прошли.
Реальные registry/profile/identity не читались, авторизация не выполнялась.
Полный headless suite: 282 теста, 190.412 с, OK. Проверены 389 относительных
Markdown-ссылок; git diff --check без ошибок.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-DEVICE-LIFECYCLE.md).

## 19 октября: источники идентификаторов устройства

Source-bound export сохранил 19 fragments и PE imports вне Git с SHA256.
NMDeviceKey имеет cache/StoredValue/GUID fallback; DeviceKey — отдельный
settings/storage lifecycle. CoCreateGuid import подтверждён, не вызывался.
Native default format=0 и hex writer проверены на трёх synthetic fixtures.
Два regression tests прошли, реальные identity/profile/registry не читались.
[Source/SHA и следующие действия](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).

## 19 октября: реестр почта — устройство

По указанию пользователя основная почта — ранее созданная тестовая.
Добавлен общий SQLite device_registry, создана её локальная запись real/main.
Реальные identity не подставлялись, confirmation=unknown. База исключена из Git.
Три теста проверили restart, idempotence, main uniqueness, запрет замены identity,
изоляцию и повторный запрос подтверждения. Авторизация/подтверждение не выполнялись.
[Поля, источники и оставшиеся задачи](DEVICES.md).

## 19 октября 2026 — SDK SignIn JSON/default headers и request plan

После fe0512e разобран FAuthImpl::SignIn. Четыре native caller fixtures:
nmDeviceKey/deviceKey/countryCode/os и optional playerId/credential. Key playerId
прослежен service+150 → wrapper ctor → leaf1444bc380 impl+30 → SignIn;
leaf без unwind исполнен, factory/getter/wrapper chain сохранена статически.
Восемь CreatePost default header/method fixtures с build0/1/2/255 и empty/nonempty
SDK account field: Content-Type/Accept JSON, gameCode/buildCode, optional
accessToken/authToken из одного поля; provider token не смешивается с ними.
JSON/maps/getters/credential/HTTP — explicit fixtures/captures; actual HTTP нет.
Общий sdk_sign_in plan: explicit context/credential33/constants, HTTPS/local
ASCII/body/header budgets, redacted immutable output. Existing SDK path/build
helpers reused. AuthUrl связан с real public GMC2 offline, active profile не заявлен.
Четыре targeted tests прошли. [Source/SHA](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN.md).
Далее response1444d85f0/token/player/expiry/errors → SDK/game session.
Полный набор: 274/274 теста, 180,0 с. Синтаксис трёх Python-файлов,
UTF-8 восьми документов, 420 относительных ссылок и diff check прошли.
Для следующего этапа: callback 1444d85f0 — leaf JMP в 1444cc1a0 (777 instructions).
Static investigation сохранена вне Git в code-clues/sdk-sign-in-response-investigation.json;
response handler ещё не исполнялся, его schema не заявлена готовой.

## 19 октября 2026 — native credential adoption после Save

После d18b9e1 установлено: 14453cdf0 — UNMServiceSettings::Save, не session
создание. OnResult игнорирует его return и продолжает clear credentials,
base ctor DL=33, accessToken copy в +58 и SetCredential/manager insert33.
GetObject по vtable slot 1 и base GetObject исполнены: channelAccessToken и
channelCode33. Email provider20 и SDK credential33 не взаимозаменяемы.
Четыре fixtures: Save false/true × два tokens; Save/clear/JSON/map insertion
и retain count явно captured/shim, persistence/SDK SignIn не исполнялись.
Narrow ASCII key ctor 141420f70 проверен отдельно от wide 141421150;
исправлена capture-модель до сохранения итогового отчёта.
Общий nid_sdk_credential builder возвращает redacted immutable object,
перепроверяет email inputs, не хранит refresh и не выполняет I/O.
Четыре targeted tests прошли. [Source/SHA](../resource-tools/vampir/HEADLESS-NID-CREDENTIAL.md).
Далее full SDK SignIn request/response/context → SDK token → game Login.
Полный набор: 270/270 тестов, 173,7 с. Синтаксис трёх Python-файлов,
UTF-8 восьми документов, 414 относительных ссылок и diff check прошли.

## 19 октября 2026 — native percent loop и общая callback boundary

После 4b89a90 статически связаны URI/query getter/OnResult map builder.
GetQuery декодирует whole query до повторного split в OnResult; generic
unquote_plus не подходит: + остаётся плюсом. Исполнены native byte loop,
append NUL и strlen на 147 fixtures; UTF8 buffers/capacity заданы явно,
%u conversion/memcpy — shims, full Unicode/URI/map не исполнялись.
Malformed escapes дают permissive outcomes, NUL сокращает видимую строку.
Общий sdk_percent строго принимает printable ASCII/%HH, single decode;
parse_nid_email_callback проверяет explicit game route и decoded fields,
reject duplicates/ambiguous extra fields, возвращает redacted credential.
Это local policy, не full native URI parser или nonce/token-validity check.
Четыре targeted tests прошли. [Source/SHA](../resource-tools/vampir/HEADLESS-SDK-PERCENT.md).
Новых сетевых запросов/аккаунтов нет. Далее query/context, setters/persistence,
post-adoption callback и SDK/game session.
Полный набор: 266/266 тестов, 169,7 с. После уточнения reject %26
повторены восемь affected field/callback tests: passed, 6,1 с. Синтаксис
четырёх Python-файлов, UTF-8 восьми документов, 406 ссылок и diff check прошли.

## 19 октября 2026 — actual NID integer/channel и общий decoded result validator

После 61cef92 исполнены parser 1415dea40, mapper 14452b060, compare leaf и
13 compiled initializers. CRT imports связаны через существующий import_at;
реальный локальный ucrtbase вызывается ctypes, DLL path/SHA сохранены.
28 numeric и 45 channel fixtures с output guards, 6 OnResult integration
fixtures уже без integer/channel return shims. Остальные map/settings и
initializer allocation/atexit/free зависимости явно ограничены.
mailUserKey=20; ASCII uppercase/swapcase работают, spaces не trim.
Native parser принимает 0abc/0.1 как zero; общий nid_result требует точный
canonical0. Добавлены source-bound channel mapper и decoded fields validator,
redacted immutable provider credential, без URL/I/O/storage/session.
Четыре targeted tests прошли. [Source/SHA](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).
Новых сетевых запросов/аккаунтов нет. Далее query/context, setters/persistence,
post-adoption callback и SDK/game session.
Полный набор: 262/262 теста, 166,2 с. Синтаксис трёх Python-файлов,
UTF-8 восьми документов, 399 относительных ссылок и diff check прошли.

## 19 октября 2026 — native OnResult caller validation и adoption arguments

После fb522c3 исполнен slice 1450ee94a..1450ef437 и copy constructor 141420cc0.
22 fixtures: missing/empty каждого поля, integer return failure/nonzero,
channel return zero и несколько owner auth mode values. Map/hash/allocation/
memcpy/parser/channel/getters — explicit shims, settings/country — captures.
Missing access/refresh/channel/ID/country при map return -1 дали null-read
address 0x18; записан fixture outcome, не заявлен crash живого клиента.
Изначальный copy shim, подменявший missing refresh пустой строкой, заменён
исполнением настоящего copy constructor до сохранения итогового evidence.
Пустой refreshToken достигает settings call; остальные обязательные empty
поля отклоняются. Access/refresh/ID/country идут в разные settings calls;
точные setter diagnostics сохранены статически. До callbacks replay остановлен.
Четыре targeted tests прошли. Новых сетевых запросов/аккаунтов нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).
Далее реальный parser/channel/query, setters/persistence/callback/session.
Полный набор: 258/258 тестов, 169,3 с. Синтаксис двух Python-файлов,
UTF-8 семи документов, 341 относительная ссылка и diff check прошли.

## 19 октября 2026 — email result path и native OnResult binding

После 9fd66fd проверен сохранённый public JS, новых запросов нет.
Почтовый вход: profile processing → W → doneSignInDeepLink → result command.
Это отдельная ветка с accessToken; прежний следующий шаг через обязательный
authorization_code уточнён. Получение профиля и policy checks нельзя пропускать.
Четыре refresh/query fixtures и восемь dispatch fixtures исполнены из actual
helpers; profile/policy/delivery/timer fixtures явно ограничены.
В pinned EXE выделен OnResult 1450ee6b0, найден caller 1450ed92b и 14 global
initializer bindings. Native handlers ещё не исполнялись. Четыре targeted
теста прошли. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-RESULT.md).
По отдельной просьбе пользователя в DirectAdmin создан bot-test@vampir.top,
квота 100 МБ. Success page и строка списка проверены браузером; пароль оставлен
на вкладке подтверждения, в репозиторий не записан. Доставка писем и Netmarble
registration/login не проверены. Далее native result validation/token/session.
Полный набор: 254/254 теста, 162,1 с. Синтаксис трёх Python-файлов,
UTF-8 семи документов, 336 относительных ссылок и diff check прошли.

## 19 октября 2026 — публичный NID email contract и локальный план входа

После b8582e0 сохранён EXE index: 19 symbols / 20 LEA / 18 roots, без native
execution. Legacy FEmailAuth не смешивается с Netmarble ID. По authWebViewUrl
из проверенного GMC2 получены публичные HTML/JS: три GET с первичным осмотром,
без cookies/account parameters/POST. Assets и immutable manifest вне Git.
Подтверждены RSA PKCS1v1.5, charCodeAt/CESU-8, members_signin/reCAPTCHA,
endpoint /api/signin/netmarble и context headers. Из выбранных JS helpers
воспроизведены девять padding и три interceptor fixtures; RNG/state/BigInteger
явно заменены fixtures, полное приложение не запускалось.
Общий nid_email шифрует явные email/password, требует context/public key/
captcha token, скрывает содержимое плана в repr. Предел encoded bytes k-11
строже исходного character-count guard. Семь новых тестов проверяют источник,
replay, synthetic RSA roundtrip, headers, границы и immutable captures.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Реальной авторизации нет; далее response/callback/code/token/session.
Полный набор: 250/250 тестов, 174,1 с. Синтаксис пяти Python-файлов,
UTF-8 восьми документов, 382 относительных ссылки и diff check прошли.

## 19 октября 2026 — real public GMC2 response и полный offline constants decode

После f9b7c52 source serviceCode связан с ctor+190/Refresh R8/Request stack+60:
netmarbles. Profile producer сохранил literals/offsets/SHA и явный build 0/A
constructor-default profile с production/nmp/thered; active settings не заявлены.
Выполнен один public HTTPS GET, без identity/account/token: 200/errorCode=0,
13788 bytes, DECKEY в response header. Snapshot immutable вне Git.
Общий bounded response decoder переиспользует JSON/XOR/RSA/list/map: 93 ordinary,
1 secret (nidEncryptKey), 94 merged constants. Значения не логируются/не сохранены
отдельным plaintext; key/geo metadata есть только в исходном snapshot вне Git.
Backend исправлен для canonical DER PKCS1/PKCS8: реальный DECKEY — PKCS8 RSA 3072,
старый жёсткий PEM label не принимал его. OAEP SHA256/MGF1 SHA256 подтвердился.
Outer encrypted NUL разрешён отдельно; plaintext/CDN policy осталась строгой.
Семь новых тестов проверяют source/real snapshot/synthetic formats/negative
policy/transport/immutability. Token plan привязан offline к real config со
synthetic inputs; HTTP auth не было. Следом email/password/browser/token/session.
[Source/SHA/пределы](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).
Полный набор: 243/243 теста, 155,1 с. Offline CLI повторил тот же analysis SHA;
синтаксис семи Python-файлов, кодировка двенадцати Markdown-файлов,
395 относительных ссылок и diff check прошли. Сетевых запросов был ровно один.

## 19 октября 2026 — интеграция actual XOR в существующий SDK decoder

После 52b70f5 сверены старые SDK-VALUES/UNESCAPE/SECRET/OAEP results.
Unescape 1444f2670 и static DECKEY flow уже исследованы, повторное исследование
остановлено. Найдено расхождение: existing constants decoder использовал raw
append capture XOR, сохранявший zero outcomes. Исправлен только составной путь:
unescape → canonical xor_gmc2_utf16_units. Старый математический raw helper/
его historical reports сохранены с явными границами. Existing local budgets
сохранены; empty key reject уточнён. Два новых regression tests: zero omission
и 18 full native-output vectors через composed decoder. Все 7 unescape tests
прошли. DECKEY class/method и whole response/auth остаются открыты.
[Источник](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).
Полный набор: 236/236 тестов, 171,8 с; синтаксис двух Python-файлов,
кодировка десяти Markdown-файлов, 376 относительных ссылок и diff check прошли.

## 19 октября 2026 — полный DecryptXOR и native zero append gate

После 647fb76 исполнены полный 1444ddf50 и append 1414242a0: word XOR по
source count/повторяющемуся key count-1; zero output units пропускаются.
18 fixtures: low/high units, surrogates, zeros, повтор ключа и 1024 units;
output guards/terminator сохранены. Growth — shim, logging-disabled fixture.
Общий bounded xor_gmc2_utf16_units принимает raw LE units, empty key reject;
не делает Base64/Unicode/JSON или key acquisition. Четыре теста прошли.
Далее preceding decode/key/DECKEY/secret constants/schema; сетевых запросов нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).
Полный набор: 234/234 теста, 175,5 с. После уточнения diagnostic fixture
address по RIP reference повторены 4 XOR tests: passed, 6,0 с. Ранее diagnostic
путь также не выполнялся; неправильная запись в соседний байт устранена.
Синтаксис трёх Python-файлов, кодировка девяти Markdown-файлов,
366 относительных ссылок и diff check прошли.

## 19 октября 2026 — RequestGMC2 header gates и offline request plan

После 1c79cd1 исполнены constructor name prefix, RequestGMC2 header/method
slice и build getter. 16 fixtures: шесть постоянных headers, eTag и token gates;
playerId/accessToken добавляются вместе по token. Device/player getters —
return fixtures, HTTP vtable calls — captures. Реальные профили/ключи/токены
не читались, сети нет. Общий frozen Gmc2RequestPlan с явными inputs,
header tuple/repr redaction/local HTTPS+ASCII budgets. Четыре теста прошли.
Далее response decode/DECKEY/auth URL values; active service/device inputs
и игровая сессия открыты. [Источник](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).
Полный набор: 230/230 тестов, 168,0 с; синтаксис трёх Python-файлов,
кодировка девяти Markdown-файлов, 357 относительных ссылок и diff check прошли.

## 19 октября 2026 — GMC2 URL assembly native replay

После a63298f исполнен Refresh URL slice1444f3a68..3d7d, version/build getters
и actual ASCII-view append14175be40. Первичный literal-view shim неверно
предполагал UTF-16; заменён native append до фиксации результата. 26 fixtures
подтвердили строки, лишние слэши, пустые фрагменты, raw query characters,
вызовы growth для длинного base. FString/allocator/copy/free/growth/singleton
остаются явными shims; весь Refresh/HTTP не исполнен. Общий ASCII helper
добавлен в sdk_config.py, четыре теста прошли. Active values не выбраны,
сетевых обращений нет. Далее RequestGMC2 headers/response decode/DECKEY/auth URLs.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-URL.md).
Полный набор: 226/226 тестов, 145,8 с; синтаксис трёх Python-файлов,
кодировка десяти Markdown-файлов, 357 относительных ссылок и diff check прошли.

## 19 октября 2026 — native SDK version/BuildCode и общий selector

После 0f759fe прослежены два getter из GMC2 Refresh/Request callsites.
144524390 возвращает 5.2.11, 14452b820 выбирает B/C/A по settings BuildCode.
Три compiled initializers и 256 getter fixtures исполнены с явными FString/
allocation/copy/atexit shims; guards сохранены. Source bytes/offsets/SHA и
полный replay сохранены. В общем sdk_config.py добавлен select_sdk_build_code.
Четыре новых теста прошли. Active BuildCode и весь GMC2 builder/response
ещё не установлены, сетевых запросов нет. Следом request/response decode →
auth URLs/DECKEY → auth session.
[Доказательства](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Полный набор: 222/222 теста, 149,0 с; синтаксис трёх Python-файлов,
кодировка девяти Markdown-файлов, 345 относительных ссылок и diff check прошли.

## 19 октября 2026 — реальный public CDN и module descriptor snapshots

После 7f0e824 сохранены четыре verified descriptor payload из base/patch:
ProjectRED.uproject/NkPatch.uplugin совпали, NnNetwork/NkPatchRuntime объявлены
Default. Runtime module order этим не определён. Выполнены два public HTTPS
GET по base INI profile (первичный probe и воспроизводимый producer), оба
200/6000 bytes/одинаковый body SHA. Общий decoder разобрал документ:
Zone real -> mode 2, select server index 6/REAL/lobbyPort12000. Body/headers/
source profile сохранены отдельно; snapshot offline replay не вызывает сеть.
HTTPS добавлен локальной политикой, native HTTP wire/TLS не воспроизводился.
Auth/лобби не запускались; active INI/full native validation ещё открыты.
Добавлены два producer и восемь тестов. Следом SDK bootstrap/auth params/
session response. [CDN доказательства](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md),
[module evidence](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).
Полный набор: 218/218 тестов, 163,8 с. Offline CLI snapshot verification,
синтаксис четырёх Python-файлов, кодировка девяти Markdown-файлов,
296 относительных ссылок и git diff --check прошли.

## 19 октября 2026 — NetworkVar callback вызывается сразу при регистрации

После e100595 найдены FNnNetworkVar constructor, leaf thunk, owner factory/
vtable и registration helper. Native slice helper, actual context getter и
thunk исполнены в 8 inline/external fixtures: loader callback раньше map insert.
Loader body и registry insertion — capture shims, TLS/static-init не исполнялись.
Сохранена отдельная статическая patch init chain; порядок её вызова относительно
NetworkVar пока неизвестен. Добавлены producer/report и четыре теста.
Полный набор: 210/210 тестов, 117,4 с; синтаксис двух Python-файлов,
кодировка семи Markdown-файлов, 239 относительных ссылок и diff check прошли.
Следом module loading/PAK mounting/GConfig Game cache/reload/late overrides;
active слой из двух INI не выбран, сетевых обращений нет.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CONFIG-STARTUP.md).

## 19 октября 2026 — base Game config и сравнение с patch

recover-base-game-config.py подтвердил полный SHA основного архива, native key
callback и SHA1 main/full directory; 12425 имён. Два Game INI сохранены
отдельно, старые данные не менялись. Base AppVersion=1.12.14,
ConfigPrefix=real, CdnConfig=True отличаются от patch 0.1.1/dev/False.
WindowsGame.ini совпадает. Три новых теста проверяют воспроизведение snapshot
и ранний отказ при изменении источников. Полный набор: 206/206 тестов,
117,4 с; синтаксис двух Python-файлов, кодировка Markdown, 230 относительных
ссылок и git diff --check прошли. Номер релиза, active settings и
runtime precedence не доказаны. Далее startup/mount/GConfig cache/overrides;
не подменять их выбором внешне подходящего INI.
[Source/SHA/снимок](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

## 19 октября 2026 — повторная сверка обновления по сообщению пользователя

Повторно запущен audit-client-release.py на установленном клиенте. Получен
прежний immutable манифест 0f179fda…11114: 34 changed, 1 added, 128
sample_matches_unverified, EXE matches_research=true. Полные хеши 35 архивов
и EXE совпали с учтённым снимком; новых отличий в объёме аудита нет.
Старые данные сохранены. Полная идентичность остальных архивов, версия релиза
и совместимость с сервером не установлены. U02 остаётся частичным:
следом сверка производных карт и связей с новыми таблицами/ресурсами.
[Объём проверки и манифест](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md).

## 19 октября 2026 — PAK key callback → directory → packed Game config

После 1572295 через missing-key diagnostic прослежены zero-GUID delegate,
initializer 141291600/binder 14155fd00 и generated callback 1468e62d0. Callback
исполнен native на четырёх fixtures; его output подтвердил plaintext SHA1 main
и full directory. Получены 7067 names/593 directories и два Game INI слоя.
Уточнено: encrypted record header SHA1 относится к ciphertext; прежний record
plaintext candidate comparison не проверяет ключ. Directory trial остаётся
независимым контролем. Producer/probe/tests/documentation исправлены.
Packed defaults дают scheme-less CDN bases, AppVersion 0.1.1, dev/False;
active overrides не доказаны, HTTP запросов нет. Старые кеши сохранены.
Полный набор: 203/203 теста, 112,3 с. Синтаксис четырёх Python-файлов,
кодировка Markdown, 315 относительных ссылок и git diff --check прошли.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).
Следующий шаг — parameter/command-line/late overrides и actual prefix/base/scheme.

## 19 октября 2026 — H04b-CDN-source: проверка нового key candidate

После ff02e97 trial compiled CDN-derived key на свежем pakchunk0: 8 plain
method-0 hash controls passed; 18 encrypted method-0 SHA1 mismatches; 23 records
bounds-skipped и 34 compressed не проверены. Encrypted directory candidate
также без hash match при trim 0–15. Никакой trial plaintext не сохранён или
передан native decompressor. Actual source/key/config не заявляются найденными.
Сохранены три verified EncryptionKey LEA/context roots как clues без PAK binding.
Полный набор: 198/198 тестов, 107,2 с; после уточнения metadata повторены
3 probe tests. Синтаксис трёх Python-файлов, кодировка Markdown, 298
относительных ссылок и git diff --check прошли.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SOURCE-PROBE.md).
Следующий приоритет — PAK-key registration/физический Game config/late overrides.

## 19 октября 2026 — H04b-CDN: server_list и raw lobby detail plan

После d2b26cc установлен diagnostic _SetServerList у 145661a70. Type-load slice
select_server/type → config+28 и 30 whole SetServerList executions (31 cases
всего) подтвердили первый ASCII-fold match и четыре detail fields. Native
comparator/moves/port _wtoi исполнялись; JSON/FString/diagnostic helpers — shims,
reference-control pointers — zero fixtures. Missing fields сохраняют прежнее
synthetic состояние; shared raw plan вместо него возвращает None без globals.
Полный набор: 195/195 тестов, 106,2 с. Синтаксис трёх Python-файлов,
кодировка Markdown, 290 относительных ссылок и git diff --check прошли.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SERVER-LIST.md).
Actual config/endpoint readiness/full ReadJson/startup/auth handoff ещё открыты.

## 19 октября 2026 — H04b-CDN: JSON document → SDK environment

После 2b433c7 исполнены 12 native parser-return/object/ReadJson/validation
branch slices. Full parser/ReadJson/validation имеют return fixtures, не native
execution; secondary check и дальнейшие lifecycle ветви не выдаются за ready.
Shared cdn_config.py связывает plain/AES body → bounded JSON object → exact
NetmarbleS/Zone → существующий SDK selector. Missing не получает default dev.
Policy: duplicates/nonfinite/invalid Unicode/depth/items/numbers отвергаются;
полный набор: 188/188 тестов, 102,3 с. Синтаксис трёх Python-файлов,
кодировка Markdown, 287 относительных ссылок и git diff --check прошли.
TASKS разделён на HTTP acquisition, offline decode и полное acceptance/startup.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-JSON-FLOW.md).
Whole ReadJson/validation/actual settings/TLS/startup order ещё открыты.

## 19 октября 2026 — H04b-CDN: fallback AES envelope

После 2c81193 найдена запасная расшифровка 145653dd0 после неуспешного JSON.
Static compiled seed/descriptor/name binding и 21 native orchestration replay
подтвердили key/IV/ciphertext arguments, getter и error cleanup. SHA/EVP crypto
primitives заменены явными hashlib/cryptography backend shims; native core
не исполнялся. Shared decrypt_cdn_fallback bounded to 2 МиБ, strict PKCS7,
raw bytes, optional crypto; Android ещё не проверен. Полный набор: 181/181
тест, 98,6 с. Синтаксис трёх Python-файлов, кодировка Markdown, 281 относительная
ссылка изменённых документов и git diff --check прошли.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-FALLBACK.md).
JSON acceptance/актуальные settings/TLS/HTTP compression ещё открыты.

## 19 октября 2026 — H04b-CDN: body/BOM decoder и status gate

После 706a88e исполнен whole body helper + wide ctor/per-unit converter:
31 fixture replay и 9 CDN status prefix slices. UTF-16LE byte/unit mismatch
подтверждён synthetic guard зависимостью; реальная память игры не читалась.
Shared decode_cdn_body_text/LengthResponse.decode_text строго ограничен body,
исправляет UTF-16LE units/surrogate pairs, отклоняет NUL и malformed Unicode.
Это явная local policy, а не побайтная копия native overread.
Полный набор: 174/174 теста, 116,1 с. Синтаксис трёх Python-файлов,
кодировка Markdown, 275 относительных ссылок и git diff --check прошли.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-BODY.md).
Compression/chunked/EOF/JSON acceptance/settings/TLS ещё открыты; network_ready=false.

## 19 октября 2026 — H04b-CDN: Content-Length и ожидание тела

После c40e52b исполнены prefix parser с двумя lookups, native whitespace trim,
atoi/write slice и receive unsigned comparison: 30 complete scenarios.
Один folded fixture исчерпал instruction budget и сохранён как bounded abort.
Range validation/diagnostics middle и полный receive loop не исполнялись.
Общий take_cdn_length_response ждёт полное fixed-length тело, сохраняет trailing
bytes через consumed; строгие local limits/status/duplicate/encoding правила.
Полный набор: 167/167 тестов, 95,2 с. Синтаксис трёх Python-файлов,
кодировка и 271 относительная ссылка изменённых документов, git diff --check
прошли. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-LENGTH.md).
Chunked/compression/EOF/JSON/settings/TLS ещё открыты, network_ready=false.

## 19 октября 2026 — H04b-CDN: начало разбора ответа и сверка обновления

После 12c7b23 проверены native boundary/status/available-body getters: 52 сценария,
actual Windows CRT scanner с первыми 12 байтами, bounded strstr shim. Добавлен
общий head-only parser с явной локальной политикой HTTP/1.x, 16 КиБ/64 поля,
сохранением дубликатов. Полнота тела/Content-Length/chunked/JSON ещё неизвестны.
Полный набор: 161/161 тест, 90,4 с; синтаксис трёх Python-файлов, кодировка,
264 относительные ссылки изменённых документов и git diff --check прошли.
Подробный source/SHA в
[HEADLESS-CDN-RESPONSE-HEAD](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-HEAD.md).
Повторный release audit дал тот же immutable снимок: 34 changed/1 added, EXE
прежний. Сервер, игра и аккаунты не использовались; network_ready=false.

## 19 октября 2026 — H04b-CDN: полный базовый GET header

После f5d12c8 исполнен full header builder 0x1445e4b20 после native URI parser
и request-context prefix. Настоящие Host/port/Content-Type/Length/Cookie/Range
builders выполняются на empty body/query/cookie/range fixtures; не подменяются
готовыми полями. Native std::string append/growth и decimal port formatter
также исполняются. Allocator/memory/search/compare/cookie-check bounded shims.

Native format helper 0x1445da240/options getter 0x141435030 сохранены и исполнены.
__stdio_common_vsprintf импорт подтверждён, вызван actual System32/ucrtbase.dll
с переводом одного %s va_list argument в реальные bounded buffers. Это analysis
мост для известных форматов, не общий variadic emulator. Путь/SHA CRT сохранены.

11 native cases: 7 default+4 overrides. Default block GET/1.0, Host с decimal
port даже 443/80, User-Agent Aqua/1.0, CRLFCRLF; нет Content-Length/Type/Connection.
Overrides: +0xa8=true добавляет Connection: Keep-Alive; пустой UA убирает поле;
custom UA заменяет значение; Referer появляется перед UA. Это fixtures, не
утверждение о текущих settings и поздних изменениях запроса в живом клиенте.

Общий encode_cdn_get_headers(url) и Draft.header_bytes выдают точные bytes
default empty-body GET; 7 блоков совпали побайтно с native. Nonempty body/query/
cookie/range/custom headers и override API не реализованы; URI policy/bounds/
редактирование repr сохранены. Никаких HTTP/DNS/TLS/socket вызовов нет.

Артефакт code-clues/headless-cdn-headers.json SHA256
dda2fc591b6fc57441ec8fbde13699f2772507eb7ff80030370ad9ab2fb72bc6.
17 roots/48 fragments/2888 instructions. HEADLESS-CDN-HEADERS.md,
общие README/FUNCTION-INDEX/shared/TASKS обновлены. Пять новых тестов прошли;
полный набор 156/156 (87,1 с), синтаксис трёх изменённых Python-файлов,
317 относительных ссылок и diff check прошли. Игра/аккаунты/сеть не использованы.
Далее HTTP receive/status/headers/body limits/chunked/compression/JSON/callback
order, queue/TLS и actual Game config values/late overrides. network_ready=false.

## 19 октября 2026 — H04b-CDN URI parser → request line

После cd90e6e исполнен parser 0x1445e6460, native string constructor 0x1421e1620
и существующий request-line 0x1445ec6f0 на 22 полных искусственных URL. Поля
scheme+8/host+28/port16+48/path+50 передаются между этапами без подмены.
Native parser снимает ровно один leading slash, не нормализует host case,
percent escapes и dot segments. HTTP/HTTPS default ports 80/443 подтверждены.

Port conversion на 0x1445e6b96 проверен как импорт atoi; вызов перенаправлен
в настоящий Windows System32/ucrtbase.dll на bounded artificial ASCII.
Путь и SHA256 DLL сохранены; запись результата в uint16 остаётся native.
Allocator/CRT memory/search/compare/cookie ограничены shims. Никаких socket/API
и аккаунтов не использовано, query collection owner остаётся явно пустой.

Наблюдения native: uppercase HTTPS даёт port 0, :65536 оборачивается в 0,
:abc/:0 дают 0; query/fragment остаются в path. Общий cdn_uri.py реализует
ограниченный subset: lower-case http(s), ASCII host token, positive decimal port,
без userinfo/IPv6/query/fragment/backslash/whitespace, max 4096 ASCII bytes.
Из 22 fixtures 16 совпадают с common parser, 6 отклоняются local policy.
CdnConfigRequestDraft валидируется при создании, хранит frozen CdnUri и выдаёт
только request_line bytes, без headers/blank line/body. URL/host/path скрыты в repr.
Проверка исходных HTTPS bases и authority preservation сохранена.

Артефакт code-clues/headless-cdn-uri.json SHA256
a64ddfdb123c1be323d140f0ea67afb7aa465e14be85610424c5598f952b9f02.
10 roots/24 fragments/2246 instructions/22 cases. HEADLESS-CDN-URI.md,
общие README/FUNCTION-INDEX/shared/TASKS обновлены. Пять новых тестов прошли;
прежние четыре CDN HTTP tests отдельно прошли после parser integration.
Полная регрессия: 151/151 (83,4 с), синтаксис четырёх изменённых Python-файлов,
311 относительных ссылок и diff check прошли. Pinned Capstone 5.0.6/Unicorn 2.1.4
дополнительно сверены в текущей среде.
Следом full headers/body, late overrides/request queue, TLS и status/limits/
decode/JSON/callback order; actual Game config values всё ещё неизвестны.
network_ready=false, реальных запросов и полноценного входа пока нет.

## 19 октября 2026 — H04b-CDN HTTP defaults и offline draft

После 71a8a98 прослежена передача собранного URL в HTTP factory/queue:
CDN call 0x14563fcda→0x1445e7be0→ctor 0x1445e21f0→context 0x1445e25d0,
call 0x14563fd0d→0x1445ea140 с R8/R9=0→AddPendingRequest 0x1445e4870.
Root headers builder 0x1445e4b20 вызывает request-line 0x1445ec6f0.
Factory/queue/callback/URI links сохранены статически, lifecycle не исполнялся.

Prefix ctor 0x1445e25d0..0x1445e26ac и настоящий request-line builder/append/
growth исполнены на 16 fixtures: 8 parsed paths × poison 00/A5. Method code 1
сопоставлен с GET; version 1.0, User-Agent field Aqua/1.0. Поле UA ещё не
доказывает полный wire header. Empty query collection задана явно; URI parser,
query/body/headers/TLS/status/response и поздние изменения defaults открыты.
Allocator/CRT/cookie bounded shims; сама сборка native, game/network не используются.

Общий cdn_request.py создаёт frozen CdnConfigRequestDraft URL/GET/1.0 из явных
настроек; URL не попадает в repr, отправки/headers serializer нет. Strict local
policy проверяет обе HTTPS bases до concat и результат после. Найден и исправлен
случай hostless https:// → https://window/...; отдельно запрещена смена authority
выбранной базы при concat без разделителя. Native string helper сохранён отдельно,
не выдаётся за URL validation. Ошибки не включают URL или входные данные.

Артефакт code-clues/headless-cdn-http.json SHA256
e75b2e0bfdf86300f4d851a33dfa388e556c966f020e0aa2b868e2f1c3dd417c.
12 roots/33 fragments/3131 instructions/16 native cases. HEADLESS-CDN-HTTP.md,
общий реестр, README/shared указатель и TASKS обновлены.
Четыре новых теста прошли; полный набор 146/146 (84,6 с). После добавления
проверки authority отдельно повторены 4/4 (2,1 с). Синтаксис трёх новых Python-файлов,
305 относительных ссылок и diff check прошли. Игра/аккаунты/сеть не использовались.
Следом URI parser, full headers/body, response/status/limits/TLS/callback order,
actual Game config values и поздние overrides. Полный вход/бот ещё не готовы,
network_ready=false.

## 19 октября 2026 — H04b: CDN version и Windows platform

После 30c4373 исполнены version replacement 0x1445daf80, string copy
0x1445d8e60 и replace helper 0x1445de490. В 15 ASCII fixtures подтверждена
замена каждой точки на underscore, исходная строка не меняется. Caller
0x14563f17e/195/275/27a/287 связывает именно поиск точки и замену underscore.
Allocator/free/CRT search/compare/copy/security-cookie ограничены shims;
весь replacement loop и helpers исполняются настоящими инструкциями.

Прослежен platform getter 0x1445e75b0 → global 0x14b4f39c8 → vtable slot 0x38.
Native initializer slice 0x1445eae1b..42 выделяет 8 байт, записывает объект/global
и vtable 0x1495045d0; slot 0x149504608 → 0x141484e40 возвращает 2.
Настоящий CDN caller выбирает window. Это compiled initialization, не live game.
Дополнительно 7 branch cases с return-tag fixtures подтверждают 1→ios/2→window/
otherandroid. Android/iOS binaries/перенос runtime не проверялись.

Общий sdk_config.py дополнен prepare_cdn_version_ascii,
select_cdn_platform_label и prepare_cdn_config_url_ascii с явными settings.
Интеграционный offline тест сопоставляет результат с native preparation+URL tail.
HTTP method/headers/действующий адрес не предполагаются. Реальные Game config
values/AppVersion/late overrides/порядок callbacks остаются неизвестны.

Новый отчёт code-clues/headless-cdn-preparation.json SHA256
7df9b499766246bd408bf08ee47f47cf605f2960c694669630d649fa49ab4819.
Источники/границы в HEADLESS-CDN-PREPARATION.md; общий реестр, README/shared
указатель и TASKS обновлены. Пять новых тестов прошли. Полная регрессия 142/142
(81,0 с), после дополнительных caller assertions отдельно повторены 5/5 (2,2 с).
Синтаксис трёх изменённых Python-файлов, 299 относительных ссылок и diff check прошли.
Игра/аккаунты/сеть не использовались. network_ready=false.
Следом фактический Game config, late overrides, HTTP request semantics и callback
order; затем подтверждённые CDN config/Zone → GMC2 → полный вход/игровая сессия.

## 19 октября 2026 — H04b-CDN URL tail

После 2d30938 продолжен источник Game config и builder. File-global 14b2743f8
по-прежнему logical Game; physical config/реальные bases/prefix не установлены.
Ограниченные проверки кандидатов для encrypted PAK не дали подтверждённого
ключа; зашифрованные записи не декодированы и не выданы за config.

Native slice 0x14563f758..0x14563f9d8 исполнен с настоящими concat 0x145630d40
и append/growth 0x1445d8310; только allocator/free/memcpy/memmove bounded shims.
16 fixtures (8 наборов × exact/SSO либо spare capacity) подтверждают
base+platform+'/'+prefix+'/'+version_fragment+'/config.json'. Между base и
platform slash не добавляется, остальные separators/query text не нормализуются.
Pointer 0x14b149ba0 → literal 0x1498b9eb8 подтверждает имя config.json.
В fixtures 26 allocations/13 frees/91 memcpy/15 memmove, не продуктовый benchmark.

Общий sdk_config.assemble_cdn_config_url_ascii требует четыре явных готовых
printable ASCII fragments, ограничивает аргументы/результат 4096 байт; нет HTTP,
platform inference или AppVersion conversion. Version 1.2.3 остаётся 1.2.3:
preprocessing helper 0x1445daf80 ещё не исполнен, source/prefix неизвестны.
Не-ASCII conversion остаётся открытым, runtime отклоняет его как local policy.
Platform branch статически 1→ios/2→window/other→android, active getter ещё не проверен.

Артефакт code-clues/headless-cdn-url.json SHA256
8267c74f094ec5521f8488c4e4e41f06de20da0c1f5c164926e85c2f2bb2289e.
HEADLESS-CDN-URL.md, README/shared index/FUNCTION-INDEX/TASKS обновлены.
Четыре новых теста прошли: source/bytes/filename pointer, 16 native replay,
select→assemble/slashes, ASCII/size policies и отсутствие implicit conversion.
Полная регрессия 137/137 (75,1 с), синтаксис трёх изменённых Python-файлов,
295 относительных ссылок и git diff --check прошли.
Следом version preprocessing/platform getter, Game config/late overrides,
получение подтверждённого CDN response и GMC2. network_ready=false.

## 19 октября 2026 — H04b-CDN selection: Game config и substring rule

После 50e337d прослежен file-global 0x14b2743f8 из loader 0x1445bc080:
root 0x14152ca00 создаёт logical name Game на 0x14152ca91..cac4. Конкретный
physical INI/cooked config и итоговые overrides ещё неизвестны.
Post-load helper 0x1445bb3a0 создаёт map entry с параметром/callback/hash/bucket;
lifecycle обновлений не исполнен. Открытого ProjectRED/Config нет,
StagedBuild_ProjectRED.ini пуст, именованный Saved/Config/Game.ini не найден.
Остальные файлы профиля не читались.

Реальный Find 0x141428640/comparator 0x1414599a0 и ветвь Initialize 0x14563f3e9..424
исполнены на 16 explicit prefix fixtures. Наличие ASCII-ignore-case подстроки
real выбирает CdnConfigUrl, отсутствие — CdnConfigUrlQA. unreal/pre_real_post/
real-space тоже выбирают normal; SDK Zone использует отдельное точное equality.
😀real возвращает UTF16 index 2. Общий select_cdn_config_base требует явные
prefix/normal/qa; никакого endpoint default/HTTP или active-config inference.
Остальные режимы Find и полный URL builder не реализованы.

Свежий pak0 проверен по полному SHA256
7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179.
6912 decoded records проверены на NetworkSetting/CdnConfigUrl/QA/ConfigPrefix
ASCII/UTF16, совпадений 0/errors 0, encrypted skipped 75/size skipped 10.
Index и reader/Oodle dependencies сверены; это не поиск всех ресурсов.
Старые индексы/CSV не перезаписаны.

Новый отчёт code-clues/headless-cdn-selection.json SHA256
6550ba9156fe7d998b1cf584ac24de0cda2d71abaf219969358c1fce698dbc77.
HEADLESS-CDN-SELECTION.md, README, shared index, TASKS и FUNCTION-INDEX обновлены.
Шесть новых тестов прошли: source/bytes, 16 native replays, distinction equality/
substring, local limits, Game global linkage, повторный public marker scan.
Полная регрессия: 133/133 (70,7 с); синтаксис трёх изменённых Python-файлов,
289 относительных ссылок и git diff --check прошли.
Следом physical Game config/actual URLs/prefix, late overrides и full builder,
затем подтверждённый CDN response/Zone → GMC2/auth. network_ready=false.

## 19 октября 2026 — H04b-CDN: найден JSON источник environment

После 2185611 продолжена цепочка singleton 14b575630+48. Constructor 145631210
обнуляет поле, vtable 1498bacd0 slot 8 указывает 145647da0, где начальное dev
передаётся в поле через 141421dd0. Default не выдан за active environment.
Найдены FNnCdnConfig::Initialize 14563f080, OnHttpPageLoaded 145642a30 →
ReadJson 14565a5d0 через call 145643110. ReadJson получает NetmarbleS/Zone
через 14563da10, conversion 1415e48f0, copy 141421d80 в object+48.

Новый build-headless-cdn-config.py сохраняет 11 roots/literals/bytes/SHA и
7 native slices: lookup arguments/branch/copy destination. JSON lookup,
conversion, FString copy/free capture shimmed; весь JSON parser не исполнен.
Missing key уходит 14565f540 diagnostic, останавливаемся до error handling;
это не успешная конфигурация с fallback dev.

Найдены NetworkSetting.CdnConfigUrl/QA/AppVersion/ConfigPrefix и globals
14b520cf0/d00/d10/d20. Loader 1445bc080 вызывает config virtual slot 0x58 с fileglobal,
потом дополнительную обработку 1445bb3a0; текущий файл/значения/overrides неизвестны.
Initializer 1411dca50 задаёт ConfigPrefix dev; полный CDN URL builder пока не исполнен.
Caller 145618910 вызывает InitSetting 14561a930, но полный startup порядок
CDN callback → InitSetting → GMC2 Start ещё не установлен.

Артефакт code-clues/headless-cdn-config.json SHA256
6fff1429a765f0be0d80b1d495f7c1db3846d5902887ff0178ea78dcad94c34a.
Доказательства и границы в HEADLESS-CDN-CONFIG.md; главный README, общий реестр,
задачи и журнал обновлены. Три новых теста проверяют source bytes/hash,
7 native replays и static anchors. Полный набор 127/127 прошёл (66,0 с);
после включения 11-го root отдельно повторены 3/3 (1,9 с).
Игра/аккаунты/сеть/файлы профиля не использовались. network_ready=false.
Далее source NetworkSetting, актуальные URLs/prefix, builder и callback order;
после подтверждения адреса — публичный config/schema/Zone, затем GMC2/auth.

## 19 октября 2026 — H04b-settings: class defaults и game override

После e37d580 продолжен auth-source flow на прежнем EXE SHA. Найдены
NMSDKSettings registration/accessor1444ab740/1444ab7f0, ctor thunk1444ac680
→1444ac9f0. Сохранены 9 property descriptors и array membership/packed offsets.
Constructor prefix исполнен на 4 заполнениях объекта: market empty/game thered/
build0/zone1/SDKType Global, email/client strings empty. Base UObject/FString
constructors shimmed; config loading/CDO lifecycle не исполнялись.

Поиск callers класса выявил game function с diagnostic
FNnNetmarbleSDKService::_InitSetting(), root 14561a930. Она копирует globals
14b5740c0/4080/4090 в market/game/client ID. Initializers141258b10/8ae0/8ab0
задают nmp/thered/public client ID, но поздние изменения globals не исключены.
Environment getter 14563d960 читает 14b575630; поле singleton+48 передаётся
141433970 и результат сравнивается с ASCII real через 141459730.
Реальные copy/compare/zone-write инструкции проверены на 13 входах:
ASCII-case real→2 production, прочие проверенные строки→1 Dev.
Environment conversion/singleton/growth/memcpy/free shimmed; активное значение
не прочитано. Конструктор 145631210 сохраняет singleton и обнуляет+48.

Общий sdk_config.select_game_sdk_zone требует явного environment, ограничивает
128 UTF16 units, отвергает NUL. Правило не получает конфигурацию и не выбирает
реальный endpoint самостоятельно. Дополнены главный README, общий реестр,
shared README, задачи и HEADLESS-SDK-SETTINGS.md. Артефакт
code-clues/headless-sdk-settings.json SHA256
dca370b3cb47525bc16879fad4a6e0e116ea70dbe9d7a7c27df9caaa26fce573.

Четыре новых теста проверяют происхождение/bytes, descriptor offsets,
4 constructor replays, 13 game replays и portable rule/ошибки входов.
Полная регрессия 124/124 (64,6 с), синтаксис трёх изменённых Python-файлов,
279 относительных ссылок и diff check прошли. Игра/аккаунты/сеть не использованы.
Следом заполнение environment singleton+48 до InitSetting, порядок с GMC2 Start,
поздние изменения globals/build, затем подтверждённый config request plan.
network_ready=false, полный email/password вход и игровая сессия ещё не готовы.

## 19 октября 2026 — U02: новые индексы и сравнение CSV

После 4d4d5b2 добавлены index-release-archives.py и extract-release-tables.py.
35 архивов проверены по полному SHA256 и заново пройдены по локальным headers;
прежние offsets/entry IDs не использованы. Сохранены 127375 записей и их
stored hashes; decoded 125122, encrypted skipped 75, size skipped 2178,
decode errors 0. Все проходы достигли index_offset; 62167 gaps явно сохранены.
Каталог PAK не разобран, полного охвата ресурсов и истинности path bindings нет.
Сводка SHA256 0880bdc08270fdea077372c8985b6597882c7646cb4369ba6f568adee8679463.
Подробные зависимости/границы — CLIENT-RELEASE-INDEX.md.

Pakchunk1: 1565 новых CSV, errors/skipped 0 при лимите 16 MiB. 1267 имеют точный
старый content hash, 298 нет. По уникальной схеме выделены 389 кандидатов,
для 73 изменённых проверены строки; 62 compared, 11 duplicate_first_column.
Кандидаты прежних Quest1448/QuestTask1454/Action1455 изменили только поле
ServerServiceGroupId в 11/144/91 строках, без добавления/удаления строк.
Схема сама по себе не доказывает игровую идентичность. Tutorial1551/Step1555/
UI1556/WorldSpot1573 имеют точные прежние SHA256 содержимого.
CSV report SHA256 1d6ff109a5ecebef084f509d06ae859d9d0a9f657abb2e3f4401b303af4f864f.

Ранее сохранённые CSV/индексы/манифесты не заменены. Повторный запуск проверил
SHA256 всех 35 архивов и использовал кеш: набор файлов снимка, размеры и mtime
полностью сохранились. 4 ASCII/UTF16 SDK markers не найдены в decoded части;
зашифрованные/крупные записи/промежутки не проверены на эти строки.

Проверки: полный набор 119/119 (64,1 с); после добавления row diff отдельно
повторены 3/3 table tests, включая новый тест duplicate keys/row shape/fields.
Синтаксис четырёх новых Python-файлов, 253 относительные ссылки и diff check
прошли. Реальное извлечение и повторный cache replay также прошли.
Игра/аккаунты/сеть не использовались. U02 остаётся частичным, network_ready=false.
Следом проверить зависимости/актуальные overrides и ServerServiceGroupId;
H04 — active UNMSDKSettings/GMC2, затем полная авторизация и игровая сессия.

## 19 октября 2026 — U01: обнаружено обновление ресурсов

Пользователь подтвердил небольшое обновление игры. Вместо применения старых
PAK offsets выполнен новый read-only аудит. Из 163 архивов 34 changed, 1 added,
128 sample_matches_unverified; UE PAK v11 — 107. EXE сохранил исследованный
SHA256 c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8.
Полные SHA256 новых/изменённых файлов охватывают 9 025 734 163 байта.
34 кешированных индекса stale; 72 других только sample_only_unverified.
Совпадение выборочного хеша не выдаётся за полную идентичность.

Новый audit-client-release.py сохраняет immutable manifest в release-snapshots,
не меняя исходный pc-pak-inventory.json, source.json и entries.json. SHA256
манифеста 0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114.
Полные пути, зависимости и границы — в CLIENT-RELEASE-AUDIT.md.
Чтение ограничено публичными архивами и EXE; аккаунты/настройки не читались,
игра не запускалась, сеть не использовалась. Версии game/Android неизвестны.
compatibility=not_established, network_ready=false, U01 остаётся частичным.

Регрессия: 114/114 тестов прошли (62,0 с), синтаксис двух новых Python-файлов,
234 относительные ссылки и git diff --check проверены.

Три новых теста прошли: выборочный хеш пропускает изменение середины;
immutable snapshot сохраняется повторно и не затирает повреждение;
новый/изменённый архив выявлен, старый индекс stale, baseline/cache сохранены.
Следом U02: свежие индексы 35 архивов в отдельном снимке и diff затронутых
ресурсов/SDK settings, затем продолжение H04. Старый scan-resources.py
не использовать для обновления прежнего кеша, поскольку он его перезаписывает.

## 19 октября 2026 — H04b-path: полный offline token request

После 2c63e30 исполнен path helper `0x14142c9d0`: 70 сценариев, включая
пустые FString count 0/1, слеши с обеих сторон, backslash и Unicode.
Разделитель добавляется условно; двойные слеши и завершающий backslash базы
не нормализуются. Growth не исполнялась, memcpy ограничен shim.
Code/refresh callers `0x1450e2b01/3451` используют literal v2/access-token.

Общий append_sdk_path и bind_token_request дают immutable BoundTokenRequestPlan
из явной карты SDK и существующего form plan; body не меняется, repr скрывает
URL/body. Binder отклоняет hostless/userinfo/query/fragment/backslash/control
и invalid port как локальную политику, более строгую, чем native prefix.
HTTP и реальное получение конфигурации отсутствуют.

Статически уточнены ветви `0x144476940`: IDs 2/3/4, string virtual slot 0x58,
fallback numeric formatter и true/false. Исполнение форматирования и конкретных
JSON values не заявляется. Следом active settings/GMC2/DECKEY, callback → SDK map
и семантика value conversion, затем live auth flow.

Отчёт code-clues/headless-sdk-path.json, SHA256
734ffd3259ff35d1a2bfcae55af4f6f528176816a492f2417202323ff393a00c.
Пять тестов проверяют provenance/replay, metadata/repr/ошибки и интеграционный
offline путь RSA secret list → merge → token form → полный адрес. Private key
искусственный и остаётся в памяти; игра/сеть/аккаунты не использовались.
Главный указатель, общий реестр и задачи обновлены. network_ready=false.
Регрессия: полный набор 111/111 без skip (68,3 с); после уточнения запрета
Unicode whitespace отдельно повторены 5/5 новых тестов (3,0 с). Синтаксис
изменённых Python-файлов, 212 относительных ссылок и git diff --check прошли.

## 19 октября 2026 — H04b-map: приоритет secret и чтение auth URL

После ce19fbe прослежены normal/secret insertion calls в один map, helper
`0x14150df70` и его existing-key replacement. Secret идёт вторым и заменяет
key/value при совпадении. Native hash и comparator не различают регистр ASCII;
для остальных единиц подтверждено точное сравнение.

SDK getter `0x144553700` использует map+`0x310`, helper `0x144502730` и prefix
checker `0x144584280`. Auth caller `0x1450e2895` передаёт authTokenUrl.
24 native lookup, 3 отдельные replacement slices и 5 hash calls прошли.
String/memory helpers shimmed, карта с одним bucket; весь insertion/growth,
callback и lifetime не исполнены. Prefix принимает даже https:// без host;
это не подтверждение готовности endpoint и не HTTP-запрос.

Общий sdk_config.py объединяет только уже строковые карты, сохраняет новое
написание заменённого ключа, не меняет входы. Aliases внутри одного input map,
NUL/нестроковые значения/превышение бюджетов отклоняются. Stringify JSON-типов
не подменяется str(). Отчёт code-clues/headless-sdk-map.json, SHA256
3bfe3a2fffed8ef40037c6f5bcc9cbed857f727cc56c1a5a802c13accc050560.
Пять тестов и HEADLESS-SDK-MAP.md фиксируют source/границы/replay.
Общий реестр и задачи обновлены. Далее stringify `0x144476940`, callback →
SDK map, path append `0x1450e2b01` → `0x14142c9d0` и DECKEY lookup.
Игра/сеть/аккаунты не использовались; H04b частично, network_ready=false.
Регрессия: 106/106 тестов без skip (64,0 с), синтаксис новых Python-файлов,
207 относительных ссылок изменённых документов и git diff --check прошли.

## 19 октября 2026 — H04b-secret: список элементов → JSON

После 5ff908c прослежен assembler `0x1444ddc10`: извлечение компактного списка,
split, вызов chunk helper, проверка непустого результата, append фрагментов
и замена последней запятой на `}`. Native orchestration исполнен в 9 основных
и 4 граничных сценариях с ограниченными string/crypto/UTF-8 shims.
Захват останавливается до native JSON parser/пустого контейнера/cleanup.
Они не объявляются исполненными. Пустые/ошибочные элементы прерывают сборку.

Общий decode_sdk_secret_constants использует настоящий chunk backend,
строгий UTF-8/JSON и один trailing NUL по chunk conversion path. Пустой список
даёт {}; неоднозначные/ошибочные данные не возвращают частичный dict.
Лимиты 2048 UTF-16 units / 16 chunks / 8192 plaintext bytes — локальная политика.
Native допуски null/[""] не перенесены, повторные JSON keys отклоняются явно.

Отчёт code-clues/headless-sdk-secret-list.json, SHA256
75f5ff4b8b577929cc8fdabb2c335d77a744b2afd1f161de8c3e3522403d9d1a.
Private test key не сохраняется, ciphertext меняется при пересборке.
Шесть тестов сверяют source/code/anchors, native assembly/replay с plaintext
fixtures, реальные multichunk RSA roundtrips и отказ без частичного результата.
HEADLESS-SDK-SECRET-LIST.md/общий реестр/задачи обновлены; игра/сеть не использовались.
Далее normal/secret merge и authTokenUrl lookup `0x1450e2895` → `0x144553700`,
а также метод получения DECKEY. H04b частично, network_ready=false.
Регрессия: полный набор 101/101 без skip (56,3 с); после добавления отказа
на числовое переполнение JSON повторены 6/6 тестов нового декодера (2,8 с).
Синтаксис изменённых Python-файлов, 203 относительные ссылки изменённых
документов и git diff --check прошли.

## 19 октября 2026 — H04b-secret: native OAEP и один chunk

После 45ec607 исполнен сам OAEP checker `0x148405020`: 24 корректных и
69 ошибочных входов. Hash/MGF1/memory/error/stack helpers заменены ограниченными
shims; клиентские RSA arithmetic и PEM reader не исполнялись. Независимый backend
cryptography 48.0.0/OpenSSL 4.0.0 проверяет искусственные RSA 2048/3072/4096;
raw pow используется только для аналитического encoded message. Проверены
публичная RSA-связь, output bounds, неизменность при ошибке и освобождение буферов.

Найден точный multiline PEM-формат `0x1494e2540` и caller `0x14451d6f2`:
BEGIN RSA PRIVATE KEY / тело / END RSA PRIVATE KEY. Printable-only scanner
его пропускал. Диагностические имена RSA/PEM/OAEP в caller также сохранены;
прежнее косвенное сопоставление уточнено. Реальное значение DECKEY не получено.

Общий sdk_secret.py расшифровывает один chunk через optional backend, с явными
лимитами и ошибками без входных данных. Windows synthetic roundtrips проверены;
Android и список secret constants/UTF-8/JSON/auth bindings ещё не готовы.
requirements-crypto-analysis.txt закрепляет Windows wheels с SHA256 отдельно
от native replay зависимостей; архивы и private keys в Git не входят.

Отчёт code-clues/headless-sdk-oaep.json, SHA256
f5bc01b7b1a68a7bacbc1dc9cb2a948bfd08321a0330be7c68d4a290f7b29fc5.
Новые ключи генерируются при пересборке, хеш отчёта меняется; private material
не сохраняется. Пять тестов и HEADLESS-SDK-OAEP.md фиксируют границы проверки.
Далее полный secret list и auth bindings, lookup DECKEY. network_ready=false.
Регрессия: 95/95 тестов без skip (55,3 с), синтаксис новых Python-файлов,
199 относительных ссылок изменённых документов и git diff --check прошли.

## 19 октября 2026 — H04b-secret: Base64 и параметры RSA/OAEP

После 5a545b0 продолжено исследование `0x14451d5c0`. Найдены private-key reader
и RSA/OAEP chain; в EXE есть OpenSSL 1.1.1t и исходные пути crypto/pem/rsa/bio.
Сопоставление с официальными исходниками этой версии указывает на raw private
RSA, затем OAEP с SHA-256/MGF1 SHA-256 и пустой меткой. Это документированный
вывод, а не найденные exports и не доказательство всей библиотеки.

build-headless-sdk-secret.py исполняет Base64 core: 26 корректных и 8 граничных
входов. Ещё 16 сценариев исполняют удаление нулевого префикса и подготовку OAEP;
сам OAEP перехвачен с искусственным возвратом. RSA, private keys и серверный
ответ не исполнялись. Общий decode_sdk_base64 использует только stdlib,
ограничивает вход и отклоняет неканонические формы без частичного результата.

Отчёт code-clues/headless-sdk-secret.json, SHA256
7467d8fd1507ef093a10a693f5942e971729df9a07a276815d9d2eea67ae011f.
Пять тестов проверяют происхождение, native результаты и повторное исполнение.
HEADLESS-SDK-SECRET.md, общий реестр и задачи обновлены. Метод lookup DECKEY
ещё открыт. Далее private-key формат и настоящий RSA/OAEP на искусственных
данных, затем результат secret constants и auth bindings. network_ready=false.
Регрессия: 90/90 тестов без skip (51,4 с), синтаксис изменённых Python-файлов,
195 относительных ссылок изменённых документов и git diff --check прошли.

## 18 октября 2026 — H04b: unescape ответа и передача DECKEY

После 463d1be прослежены extractor `0x1444e3bc0` и helper `0x1444f2670`:
разбор строковых escape выполняется перед XOR. Constructor хранит имя DECKEY
в manager+`0xB0`; root `0x1444c8c60` получает значение через virtual slot `0x28`
и передаёт локальную строку ключа parser на `0x1444c9587`. Точный класс/метод
lookup не доказан; HTTP-заголовком источник пока не называется.

build-headless-sdk-unescape.py исполняет helper: 43 корректных входа,
7 граничных и 3 цепочки unescape→native XOR→искусственный JSON.
Использованы ограниченная аллокация и powf shim только для 16**{0,1,2,3};
импорт подтверждён PE/IAT. Таблицы переходов после RET сохранены как данные.
Ошибочные escape в native helper иногда возвращают только начало строки.
Общий sdk_constants.py отклоняет их явно, без содержимого в сообщении ошибки.
Граница 4096 байт сохраняется; полный JSON-ответ нельзя unescape повторно.

Отчёт code-clues/headless-sdk-unescape.json, SHA256
66081739dd40ebce4a8ccb38bc1195b3f19d832b0bd2a2b05422a29cfc78282e.
Пять тестов сверяют source/code/data/literals, native результаты, составные
примеры, повторное выполнение 16 входов и ограничения. Документация:
HEADLESS-SDK-UNESCAPE.md; общий реестр и задачи обновлены. Аккаунты/сеть/игра
не использовались. Следом метод lookup DECKEY, secret constants и auth bindings;
H04b частично, network_ready=false.
Регрессия: 85/85 тестов без skip (42,5 с), синтаксис изменённых Python-файлов,
191 относительная ссылка изменённых документов и git diff --check прошли.

## 18 октября 2026 — H04b: параметры SDK и общий XOR GMC2

После коммита 1f86279 прослежены getters `0x144524390` и `0x14452b820`:
строка `5.2.11` и выбор глобальных строк build, инициализированных `A/B/C`.
Аргумент build читается из settings+`0x48`, окружение GMC2 — из settings+`0x49`.
Активные настройки и изменения глобальных строк после запуска не установлены.

Новый build-headless-sdk-values.py исполняет цикл `DecryptXOR` на 42 искусственных
входах. Захват append ограничен, логирование отключено; FString allocation,
полный parser и HTTP не исполняются. Сохранены инструкции, литералы, смещения,
хеши и входы/выходы в code-clues/headless-sdk-values.json, SHA256
fe583b60880a5e1186158cce82ff572ecb4dd18380495f29ac1643b9c03835cf.

Общий sdk_constants.py сохраняет UTF-16 единицы, нули и суррогаты, ограничивает
вход 4096 байтами и ключ 1024 байтами. Непустой вход без ключа явно отклоняется.
Пять тестов проверяют source provenance, все native результаты, повторное
исполнение семи сценариев и границы. Подробности — HEADLESS-SDK-VALUES.md.
Следом callback/parser: внешний decode, источник DECKEY, authTokenUrl/clientId.
H04b остаётся частичным, network_ready=false; игра и аккаунты не использовались.
Регрессия: 80/80 тестов без skip (38,4 с), синтаксис трёх новых Python-файлов,
187 относительных ссылок изменённых документов и git diff --check прошли.

## 18 октября 2026 — H04b: источник GMC2 config и выбор адреса

После коммита ядра 09815f8 и вычитки Markdown b3a373b продолжено исследование
авторизации. Новый build-headless-sdk-config.py связывает 7 точных diagnostic
literals с 8 LEA / 7 unwind roots; 48 constants сохранены с bytes/offsets/SHA.
Найдены constructor/Start/RefreshSDKConstants/RequestGMC2/callback/parser/decryptor.
Повторная ссылка DecryptXOR внутри parser не считается именем всего parser root.

Native slice 0x144501a11..0x144501a46 исполнен для всех 256 byte values:
settings+0x49 выбирает manager field +0x150/160/170/180. Constructor связывает
их с alpha/dev/production/DR GMC2 bases; значения 4–255 выбирают dev. Settings
inputs явные, strings/network не исполняются; активный mode установленной игры
не доказан. Поэтому production не выбирается автоматически для auth plans.

Статически прослежены template-groups path, game=v5/country=G9/build/engine/market
части URL и GET. Runtime template/getter values и active settings ещё unknown.
Ключи encConstants/encSecretConstants/DECKEY найдены как имена полей, не полученные
секреты; response/schema/decode ещё не восстановлены. Игра/Saved/launcher memory/
account tokens не читались, внешних HTTP запросов не было. H04b partial.

Report code-clues/headless-sdk-config.json,
SHA256 b6f3418f9d9bb44f2feb748c4bc662059110080c54117d9d52f6448da668799c.
HEADLESS-SDK-CONFIG.md/общий реестр/README/задачи обновлены. Три теста проверяют
source bytes, literals/LEA boundaries, constructor field binding, все mode outputs
и повторное native исполнение. Далее source settings+0x49, getters 0x144524390
и 0x14452b820, callback response→auth bases/client ID. network_ready=false.
Регрессия: 75/75 тестов без skip (35,5 с); синтаксис двух новых Python-файлов,
230 локальных ссылок и git diff --check проверены успешно.

## 18 октября 2026 — коммит ядра и вычитка документации

Накопленные код, инструменты и доказательства сохранены коммитом 09815f8
«Добавить переносимое сетевое ядро Vampir и исследование авторизации SDK».
Перед ним повторно прошли 72 теста; внешний Git push не выполнялся.

По замечанию пользователя проверены все 111 Markdown-файлов проекта.
Склейки находились в самих записях, в том числе в недавних заметках этого чата,
а не возникали при отображении или из-за кодировки. Правка затронула 73 файла:
пробелы между словами, числами и пояснениями, склеенные русские фразы.
Дополнительно исправлены две явные опечатки: «закрыбийство» → «за убийство»
и «автовходпонакругу» → «повторный автоматический вход».

Проверка относительно 09815f8 подтвердила: остальные непробельные символы,
блоки кода, inline code, назначения ссылок, хеши, десятичные числа и время
сохранены. 385 относительных ссылок ведут к существующим файлам; для 46
исправленных якорей заголовков сохранены прежние HTML id. Код не изменялся.
Словарные подсказки использовались только локально с ручным отбором: термины
«автобой», «пересборка», «токен» и имена API не разбивались по словарю.
При следующих записях проверять читаемость прозы до коммита; git diff --check
сам по себе не обнаруживает склеенные слова. Содержимое протокольных
доказательств и статусы незавершённых исследований не пересматривались.

Работа по H04 продолжается: следующий источник — FGMC2ManagerImpl,
загрузка SDK constants/config и выбор authTokenUrl/authAccountUrl/authUrl.

## 18 октября 2026 — H04a SDK auth graph и offline token forms

Предыдущий transport этап дал concrete progress; повторное исследование codecs
не требовалось. Начат H04. Из установленного EXE индексированы 24 точных SDK
signature literals/34 проверенных LEA/24 roots; 143 constants с file offsets,
source/tool/fragment hashes. FAuthImpl authUrl/v1/sign-in отличается от
NetmarbleID authTokenUrl/v2/access-token. Выделены authorization_code и
refresh_token forms: grant_type/client_id/device_key/code или refresh_token,
Content-Type form-urlencoded. Caller1450e2d80/1450e36e1→14451c570→CreatePost14451c600.

Native byte whitelist141c06750 и uppercase hex1415ad670 исполнены для 256 байтов
каждый (512 executions); безопасные -.A-Z_a-z0-9~, пробел %20, плюс %2B.
Общий auth_request.py создаёт redacted offline TokenRequestPlan, ASCII subset,
field4096/body 32768 budgets; no HTTP. Unicode/full native map serializer не
проверены. Browser password/code, config base URL/client IDs/region, responses,
SDK session и game Login handoff остаются неизвестными. Кодовые токены не
выдаются за игровой пароль. 5 tests/provenance/source/call anchors/escaping/plans.

Report code-clues/headless-auth-index.json,
SHA256 42543d7c32c3fc1d4d00abde017ebe8f605a6175b5b6b05dd642bdeb7f1296e3.
HEADLESS-AUTH.md/общий реестр/задачи обновлены; entry README очищены от длинной
накопленной ленты progress и содержат текущие ссылки, история остаётся здесь.
Saved/webcache, launcher profile, память процессов, live токены/аккаунты не
читались; внешних запросов не было. H04 partial/network_ready=false.
Регрессия: 72/72 теста без skip (31.9 с), syntax трёх новых Python файлов,
271 локальная ссылка и git diff --check — успешно.
Следующая точка config: диагностические имена FGMC2ManagerImpl::RefreshSDKConstants,
ParseConstantsTemplateGroups/DecryptXOR уже видны в EXE; их roots ещё связать.

## 18 октября 2026 — native drain и portable partial socket send

Constructor table 149503b58/peer+50 slot 20→1445e8b70 доказан по instructions.
Native drain читает ту же queue178/180, исключает NUL, вызывает ordinal import.
PE import + export установленной WS2_32.dll подтверждают имя send; DLL SHA/bytes
в отчёте. 61 native cases: partial/full/zero, error query 22/23/37 без consume,
прочие diagnostic/close capture, empty/no socket. Consume1445e5ef0/memmove
настоящие; send/error/query и fatal shutdown fixtures, listeners отсутствуют.
Engine имена error enums не доказаны. Zero native не закрывает соединение.

OutboundFrames дополнен readonly peek/consume и head offset; socket_send.py
ограничивает число send за проход, сохраняет partial tail при blocked/interrupt,
пробрасывает fatal errors. Local zero-send policy ConnectionError строже native.
Byte budget pending; удержанный префикс головы до 26 bytes сверх него для текущих
типов. 5 tests с native replay/fake partial→blocked→resume и настоящим local
IPv4 TCP: ack(old key)+Ping(new key) byte-for-byte. Sockets закрыты после теста.
Это не game session и не live server compatibility.

Report code-clues/headless-send-drain.json,
SHA256 61f5072331f239b46bbd00f648040d803721fece554156dccba80691a991a251.
HEADLESS-SEND-DRAIN.md/общий реестр/задачи обновлены. Игра/аккаунты/внешняя
сеть не использовались, network_ready=false. Далее connection/endpoints/H04auth,
receive accumulation, readiness/таймауты, session lifecycle и полный Notify→wire.
Регрессия: 67/67 тестов без skip (31.5 с); syntax четырёх новых/изменённых
Python файлов, 272 локальных ссылки и git diff --check — успешно.
Дополнительно проверен pop оставшегося хвоста после partial consume: budget
освобождается корректно, остаток следующего кадра не затрагивается.

## 18 октября 2026 — send-B и synchronous queue ownership

Slice144aace6d..144aacf89 исполнил настоящий ID getter, archive ctors/writers,
sequence peer+240, CRC32, XOR peer+248, queue1445eac20 и append1445e4a90.
40 native scenarios: Ping/KeyChanged, 4test keys, 5sequences включая wrap,
existing prefix и wake/no-wake. Preallocated capacities и CRT memory shims;
wake callback capture. Queue peer+178/180/188 получает копию ciphertext до
возврата. Source overwrite и смена test key после slice не меняют queued bytes.
Настоящий archive destructor/drain/socket/allocator growth не исполнены.
Дополнительный replay покрывает pristine queue и append второго кадра.

Общие send-B encoders и OutboundFrames: явные byte/frame limits, immutable
frames, sequence wrap, ack под старым ключом до переключения следующего кадра.
BufferError атомарно сохраняет состояние — локальная policy строже native
send-false→key-set; session owner обязан обработать отказ, retry не реализован.
5 tests/provenance/all native frames/copy/backpressure/key ordering.
Полный Notify handler→handle send→wire совместно ещё не replayed.

Report code-clues/headless-send-b.json,
SHA256 4e627e9ec4527427007e0468646d7510591f3aca85cda96ed3c62032919c0577.
HEADLESS-SEND-B.md/общий реестр/задачи обновлены. Сеть/игра/аккаунты не
использовались, network_ready=false. Далее drain/socket/session setup и H04auth,
Notify→wire интеграция и оставшиеся integrity/error/lifetime paths.
Регрессия: 62/62 теста без skip (29.2 с), syntax четырёх новых/изменённых
Python файлов, 267 локальных ссылок и git diff --check — успешно.

## 18 октября 2026 — keyed receive-B и ID bookkeeping

Реальный wrapper 144aacb50 после XOR(frame+3, key=subobject+48) читает IDword+3,
вызывает singleton getter 144aa7c40 и table lookup 144aa8120. При совпадении
native remove144aa7f40/sparse free14142eff0 удаляет запись; если таблица пуста,
вызывается notify144aa7870. Затем тот же pointer/size передаётся в Dispatch.
Не CRC/sequence header. Семантика manager/подписчиков не объявляется ACK flow.

Добавлены build-headless-receive-b.py, take_receive_b_frame и
decode_game_ping_result_b. 39 native cases/4 tests: 4 test keys, empty/match/miss,
short lengths0..11, unknown IDs; подтверждены bit/free/bucket state и порядок
remove до reader. Short body не отменяет удаление. Dispatch/TLS cleanup настоящий;
OnHandler capture и прежние registry/lifetime/diagnostic fixtures сохранены.
Native empty notification loop, его zero-array cleanup shim; nonempty callbacks
и collisions не проверены. В исполняемом B пути CRC нет; вывод не распространяется
на весь socket/library/server путь. Runtime helpers требуют explicit limit/key,
не меняют session state, используют только stdlib.

Report code-clues/headless-receive-b.json,
SHA256 b27499eb764c50e6bf1ceb87546c5777b1c55e084d048e81aad44f918b050ef0.
HEADLESS-RECEIVE-B.md/общий реестр/задачи обновлены. Сеть/игра/аккаунты не
использовались, network_ready=false. Далее send-B/очередь, первичная авторизация,
полный lifecycle и оставшиеся integrity/error branches.
Проверка: 57/57 тестов без skip (27.3 с), syntax четырёх изменённых/новых
Python файлов, 260 локальных ссылок и git diff --check — успешно.
Следующая точка: send-B call 0x144aacf7d→0x1445eac20 после XOR0x144aacf63;
проверить ownership/copy очереди до archive cleanup0x144aacf89. Пока unknown.

## 18 октября 2026 — native Dispatch до PingResult OnHandler entry

Предыдущий этап дал проверенный listener loop, поэтому callback capture заменён
на настоящий Dispatch14679f510. Synthetic registry ID17→native PingResult object→
handler table 149d810f8. Native constructor/reader/archive ctor/destructors, ID hash
lookup, TLS setter 144aa6240, current packet и cleanup исполнены. Wrapper141535f20
переходит со slot 8 на slot 10; PingResult OnHandler1467670c0 перехвачен на входе,
args/decoded fields/context проверены, gameplay side effects не выполнялись.

24 native cases: 8 successes включая trailing data/max bits, short lengths0..11,
4 unknown IDs. После всех current packet/TLS очищены; ошибки не доходят до handler.
Snapshot lifetime/registry fixtures, checked cookie shim, unknown logger capture.
Reader failure diagnostic formatting пропущен; native cleanup возобновлён.
Receive-A изолированно передаёт вход в game Dispatch, не доказывает выбор A в сети.

Общий receive_packet.py: decode_game_ping_result, exact body 12 и один frame —
локальная политика строже native trailing tolerance. 4 tests, включая mixed
повторные native replays после ошибок. Report code-clues/headless-dispatch.json,
SHA256 d0db813874494cf8da7edb77fded572505f8e1da2554b7b24ad625296859a20b.
HEADLESS-DISPATCH.md/общий реестр/задачи обновлены. Сеть/игра/аккаунты не
использовались; network_ready=false. Далее receive-B/integrity/layout, send queue,
первичная авторизация; native lifecycle/error formatting остаются неполными.
Проверка: 53/53 теста без skip (24.1 с), syntax трёх новых Python файлов,
255 локальных ссылок и git diff --check — успешно.

## 18 октября 2026 — второй receive loop с фиксированным listener fixture

Добавлен build-headless-listener-loop.py: 44 native cases, slice
0x1445ed572..0x1445ed730, настоящий probe/broadcast helper/virtual thunks,
receive-A/XOR, возврат в loop и compaction. Snapshot/cleanup/free/expired cleanup
заменены проверяемыми fixtures; атомарный reference count остаётся native,
баланс checked. Final callback capture, не Dispatch. Конкурентный lifetime,
несколько listeners, destructors/allocator/error paths ещё не исполнены.

Общий receive_frame.py дополнен take_receive_a_frame: один complete opaque
receive-A frame с fallback XOR, immutable input, explicit size limit; не CRC
или body codec. Пять тестов покрывают provenance/all vectors, continuation,
none/expired listener, partial/coalesced input. Связанный native replay переносит
внутренний header/body через три compressed transport blocks: оба кадра
доставлены без потери/дублирования. Native allocation bounds сохранены.

Report F:/PhoneExit Resources/Vampir/code-clues/headless-listener-loop.json,
SHA256 d89a0da84def91cbd57b567c821f0cf883531ed172fcc97b91bdbe9ddbaffeb1.
HEADLESS-LISTENER-LOOP.md/общий реестр/задачи обновлены. Игра/аккаунты/сеть
не использовались, network_ready=false. Далее фактический Dispatch/handler
wrapper, входной CRC/layout и send queue; целый lifecycle остаётся отдельной проверкой.
Регрессия: 49/49 тестов без skip (21.6 с), syntax новых файлов, 248 локальных
ссылок и git diff --check — успешно.

## 18 октября 2026 — распаковка с повторами и связь listener stage

Добавлены build-headless-block-decode.py, общий block_decode.py и
take_transport_frame с явными лимитами. Реальный native decoder0x14141ba60
исполнен с copy tables из EXE: literals, LE16 offsets, overlapping matches,
extended lengths, несколько matches, exact output capacity. 166 успешных
и 86 отрицательных native проверок совпали с общим кодом. CRT memory shims
ограничены; direct decoder replay до 4096 output, runtime limit до 1 MiB.
Offset0 отклоняется локально; malformed parity на всех входах не заявляется.

Статически доказана связь второго stage: length slot 38 через 1415f6848,
callback slot 40 через 1437113e4/helper 1445dede0; native full listener loop
ещё не исполнен. Несколько compressed blocks дополнительно прошли
native staging→append→compact. Native decoder errors проверены отдельно,
peer diagnostic/error path после них остаётся. Сеть и игра не использовались.

Отчёт F:/PhoneExit Resources/Vampir/code-clues/headless-block-decode.json,
SHA256 591c7ecb60d0fa70c5c7e4c85b190409bd4651bb7659b983ba226d825b765d21.
HEADLESS-BLOCK-DECODE.md содержит offsets/anchors/границы/reproduction.
Следом полный listener replay, входной CRC/layout, send queue и handler wrapper.
Итог: 44/44 теста без skip; syntax новых файлов, 242 локальные ссылки и
`git diff --check` прошли. Первоначальный integration replay выявил старый
лимит memcpy shim256; новый block harness явно ограничивает его 4096,
не меняя Ping harness и не подменяя native распаковку.

## 18 октября 2026 — первый транспортный этап приёма

Точная строка UxTcpPeer::_HandleRecvBuffer привела к root 0x1445ed3e0.
Raw header содержит size 23 и compression bit 23. Native цикл работает с
NUL-terminated byte vectors, копирует/распаковывает кадр во второй buffer,
сдвигает неполный остаток. Это раньше length probe0x144aa9a90: прежние
наблюдения LE24 относятся ко второму слою, а не raw framing.

Builder build-headless-transport-stage.py исполнил slice0x1445ed403..0x1445ed562:
реальные parser/decompressor0x14141ba60/append/resize/compaction, explicit TLS
и preallocated buffers; только memory CRT shims. 62 native cases покрыли
partial/coalesced/mixed frames, existing output, skip0/3, literal compressed
fixtures. Общий compressed grammar пока не реализован/не заявляется.

Shared transport_header.py: size 23/flag inspection и извлечение несжатого
кадра с явным лимитом; compressed complete frame отклоняется явно.
receive_frame.py уточнён как второй слой. 5 тестов прошли, включая 3 native
replays; source SHA прежний. Report:
F:/PhoneExit Resources/Vampir/code-clues/headless-transport-stage.json,
SHA256 f60ef311ba43cf781abd069f061be307786db10627d678678df68a3ba05f6696.
HEADLESS-TRANSPORT-STAGE.md/реестр/задачи обновлены. Далее listener loop,
полный decompressor/error path, второй framing/CRC и send queue.
network_ready=false, игра/аккаунты/сеть не использовались.
Итоговая регрессия: 38/38 тестов без skip, синтаксис новых файлов,
51 локальная ссылка и `git diff --check` — успешно.

## 18 октября 2026 — Notify→ack→новый ключ соединения

Найден реальный virtualcall setter через регистр r8 в handler 0x146765050;
поиск только прямого call[rax+40] пропускал его. Exact diagnostic
PktKeyChangeNotifyHandler::OnHandler() подтверждает имя. IDNotify11/ack12,
vtable/ctors/readers/writers/name/IDgetters и registration в factory связаны.
Старый candidate0x144aab330 теперь доказанный setter peer+248 через handle+10;
это то же поле для send-B и receive-B subobject+48.

Создан build-headless-key-change.py и shared key_change.py.10nativepayload
roundtrips/16 short cases/20 handler slice cases прошли. Native ackconstructor,
singletongetter/setter исполнены, sendcapture shim фиксирует oldkey/ackbits.
После sendsetter вызывается даже при false return; не выводить доставку или повторы.
Sharedpayloadcodec repr скрывает key; реальные ключи не логировать. 5 tests прошли,
включая 4 native replays. Report `F:/PhoneExit Resources/Vampir/code-clues/headless-key-change.json`,
SHA256 `bf48a4ff2541effc83799ee9e69a0155f8d0675701797708bb09edb422504aa5`.
HEADLESS-KEY-CHANGE.md/общий реестр/задачи обновлены. Следом receiveintegrity/
layout/transport и sendqueue; initialauth/keygeneration unknown, network_ready=false.
Игра/сеть/аккаунты не использовались, все keyvalues синтетические.
Итоговая регрессия: 33/33 теста без skip, синтаксис новых файлов,
48 локальных ссылок и `git diff --check` прошли. Раздел продолжения TASKS
переписан по актуальному состоянию, старые candidate-инструкции убраны.

## 18 октября 2026 — H03b.2b partial: длина/receive/dispatcher

Прочитаны README/TASKS, vtable pointers и конструкторы peer implementations.
Length probe0x144aa9a90 в slot+38 двух table 0x14961af58/0x14961b8f0,
receive wrapper в+40; ctor назначает table subobjectmain+200.
156 native length vectors подтвердили available<5→0 без read и LE24declared,
причём declared1..4 допускается при available≥5. Локальный helper намеренно
отклоняет такие размеры и требует явный memorylimit; не выдавать это за client behavior.

WrapperA исполнен 13 буферами 0..512 до исходного callbackcall; nativeXOR без shim,
callbackobject/context синтетические. Проверены pointer/length/аргументы.
Найдена static цепочка factory0x14678ec40→setter 0x144aab300→peer+238→wrapperB
callbackslot8→Dispatch0x14679f510. Полный end-to-end replay не исполнялся.
Найден keysetter candidate0x144aab330/pointertables0x14961b780/0x149d84e90;
caller/источник 64 бит/semantics ещё unknown, runtime не использует его.

Builder `build-headless-receive-envelope.py`, shared `vampir_core/receive_frame.py`,
6 tests прошли(все vectors, bytes/SHA, localpolicy, 7 native replays).
Report `F:/PhoneExit Resources/Vampir/code-clues/headless-receive-envelope.json`,
SHA256 `bb3d9ff7c93420f74fead019b52beca765b8eb43c3d98c94c34e50f5cb49a382`.
HEADLESS-RECEIVE-ENVELOPE.md/общий FUNCTION-INDEX/задачи обновлены.
Следом transport pipeline/CRC/incominglayout/keyflow; network_ready=false.
Игра/аккаунты/сеть не использовались.
Итоговая регрессия: 28/28 тестов без skip, синтаксис новых Python-файлов,
46 локальных ссылок и `git diff --check` — успешно.

## 18 октября 2026 — H03b.2a: полный исходящий Ping кадр

Просмотрены README/TASKS, static pointers receive/Dispatch и direct CRC callers.
Обнаружен pointer Dispatch в 0x149d80538+8 и LEA в factory/destructor, но receive
callback к нему ещё не привязан. Прямой поиск CRC вызовов нашёл только 2send
sites; отсутствие receive checksum этим не доказано.

Выполнен цельный send-A assembly slice0x144aa9e6a..0x144aa9f45: nativepacket ID,
sequence, payload, length, CRC, append и XOR. Archives созданы native ctor с
explicit preallocated buffers, allocator/socket/prologue/cleanup исключены;
только внешний CRTmemcpy shim. Первая попытка потребовала добавить IDgetter
code page0x1414079a0; после mapping и bounded evidence slice прошёл 20 cases.
Подтверждены length 24LE (полная длина), CRC32 внутреннего ID16+seq16+body,
XOR от offset 3. Ping frame 27 bytes, connection counter+228 wrap 65535→0.

Shared `vampir-shared/vampir_core/send_frame.py`: encode_ping_frame, только
Ping send-A, без сети и generic login frames. 5 tests прошли: все 20 native vectors,
originalbytes/SHA/slice boundaries, layout/CRCscope/inputvalidation и 2 native
replays. Builder `build-headless-send-frame.py`; report
`F:/PhoneExit Resources/Vampir/code-clues/headless-send-frame.json`, SHA256
`1bf470e99750c675890ee3f51ab5380a4c0b14f9fab948d8d5860902c9d3de57`.
Подробности в HEADLESS-SEND-FRAME.md, общий FUNCTION-INDEX обновлён.

Receive dispatcher input имеет другой layout (ID+3/body+5), поэтому send
frame не объявлен входным протоколом. Следом H03b.2b: framing/CRC checks,
callbacks→Dispatch, sessionkeysource и handler wrappers. H03b. 2 частично,
network_ready=false; игра/аккаунты/сеть не использовались.
Итоговая регрессия: 22/22 tests без skip, syntax parse, 43 локальные ссылки и
`git diff --check` прошли. Полный транспорт по-прежнему не заявляется готовым.

## 18 октября 2026 — H03b.1: CRC32/XOR и receive wrappers

Создан `build-headless-frame-primitives.py`. CRC init0x1418ba360/update0x1445f1230,
table 0x1495046f0 (все 256entries сверены по polynomialEDB88320). XOR0x144aa6ca0
использует LE64 key/fallback 0x9ab378c9d02084a7. Entry boundaries доказаны E8calls.
21CRC/210XOR=252 native executions с init, без shims. Проверены длины 0..512,
граничные byte patterns, ключи, in-place/disjoint и sentinel. Первый disjoint
эксперимент выявил ошибку аргументов в эксперименте: RCX=source/R8=destination;
исправлено до записи отчёта, предположение не стало подтверждённой схемой.

Receive roots0x144aa9c00/0x144aacb50 имеют size guard≥3, transform+3,
callbackslot8. Key в B из state+48, sendB из+248; происхождение key/полная длина/
CRC validation и callback→Dispatch ещё не доказаны. Shared module
`vampir-shared/vampir_core/frame_primitives.py`: payload_crc32/xor_transform.
5 tests прошли: bytes/SHA, все native vectors, 24 дополнительных native replays.
Доказательства в HEADLESS-FRAME-PRIMITIVES.md и общем FUNCTION-INDEX.
Report `F:/PhoneExit Resources/Vampir/code-clues/headless-frame-primitives.json`,
SHA256 `3dd125f16da9922e14247ba16e96c74dce6253dcb82f88b8e63ddfd92f15a8d5`.
Следом H03b.2; network_ready/full_frame_verified=false. Игра/сеть/аккаунты
не использовались; эмулятор/proof данные не входят в runtime.
Итоговая регрессия 17/17 без skip; syntax parse, 40 локальных ссылок и
`git diff --check` прошли. H03b остаётся частичным до полного согласования кадра.

## 18 октября 2026 — общий код всех направлений Vampir

По уточнению пользователя выделен `vampir-shared/README.md`: общий указатель
результатов, данных, инструментов и исполняемых компонентов. Ping package
перенесён из `vampir-headless/vampir_core` в `vampir-shared/vampir_core` без
дублирования; импорт `vampir_core.ping` сохранён. Старые пути в исторических
записях ниже описывают прежнее расположение. Текущие README/реестр/ссылки и
test import обновлены. Машинные proof JSON и их SHA не изменены.
Проверка после переноса: 12/12 headless tests, 30 локальных ссылок,
единственная копия исходника codec и `git diff --check` — успешно.

## 18 октября 2026 — направление открыто, H00/H01

Пользователь запросил самостоятельный клиент: Windows без игры, вход по почте/
паролю, фарм текущего места, 10–20 отдельных аккаунтов одновременно, переносимое
ядро для будущего Android. Дополнения: общий индекс находок, еженедельное
обновление данных игры, небольшой размер/нагрузка, управление через онлайн 2D-карту.

Прочитаны главный README/TASKS Vampir, RESOURCE-INDEX, NATIVE-ENTRY,
UNLOCK-REGISTRATION/RESULTS, ATTRIBUTES, код генераторов/Android build config.
Найдены пригодные данные: таблицы/связи, отдельная регистрация packet-handler,
изолированные stat readers/writers, ветки SDK-входа и исследования navmesh.
Ни wire encoding, ни независимая авторизация, ни живой бой пока не восстановлены.

Текущий EXE SHA256:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
С исходным файлом независимо сверены байты трёх старых отчётов:
entry-code 2060, lock-registration-events1109, stat-packet-evidence483 диапазона;
всего 3652, расхождений 0. Stat IO в прежних 1392 roundtrips синтетический,
поэтому эти прогоны не объявляются decoder реальных пакетов.

Создан `build-headless-network-index.py`, использующий существующий PE/unwind/
Capstone-инструментарий с проверкой версии 5.0.6 и полного SHA EXE. Выход:
`F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
27 точных literals/31 проверенная LEA/27 roots/32 fragments/1020 instructions;
missing0/rejected0. В том числе Dispatch root 14679f510,
GetPacketHandler14679f7b0; это ссылки на диагностику, не доказанный end-to-end
приём. Адреса и ссылки включены в общий FUNCTION-INDEX, а не спрятаны в журнале.

Разработаны задачи H00–H11, U01–U03, P01/P02, A01. Следом H02: имя→реальная
vtable→ID/reader/writer и registration. Ранее изменённые файлы исследования
карты сохранены; её состояние не переписано. Игра не запускалась, аккаунты и
сеть игры не использовались, APK/пакеты не публиковались.

Проверки: `test_vampir_headless_index.py` — 3/3, независимые SHA/fragment/literal
и Capstone xref re-decode; `test_vampir_native_entry.py` — 7/7 (включая отказы
на неполной инструкции и неверных unwind). `git diff --check` прошёл.
SHA256 нового отчёта:
`e2dc03ab67b09d4ba714e7891ed324a040d7cf408c2194404830004b5e491003`.

## 18 октября 2026 — H02: привязки десяти пакетов

Создан `build-headless-packet-bindings.py`. Для 10 выбранных типов связаны
точные имена→vtable→constructor/ID/IO targets; 11 прямых вызовов доказывают
границы конструкторов, включая leaf без unwind; запись vptr проверяет начало
таблицы. Для пяти Result прослежены handler table/method и регистрация с
packet/handler аргументами. Отчёт содержит 17 fragments/20007 instructions,
17leaf checks/72data anchors. SHA клиента прежний, игра/сеть не использовались.

Важная новая связь: Login/LobbyLogin имеют ID3, их результаты ID4, но разные
таблицы, IO targets и статические фабрики/registration functions1467a7250 и
1467a7150. Нельзя делать глобальную ID→schema таблицу без контекста. Runtime
выбор соединения остаётся unknown. Вариант 1467a7150 также подтверждает name
slot+0x38; оба регистратора ID slot+0x28 и word key. Неразобранный root 1457491b0
из широкого поиска vtable refs не включён в доказательства.

Новый `test_vampir_headless_packet_bindings.py`: 4/4 проверки прошли,
включая 10 native исполнений ID-getters в Unicorn, независимый разбор PE и
сверку байтов/слотов/коллизий/constructor calls. Подробности и VA:
`resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md`, общий FUNCTION-INDEX обновлён.
Выход `F:/PhoneExit Resources/Vampir/code-clues/headless-packet-bindings.json`,
SHA256 `35d1a72b6302a66cd19548b3da7caef362ccbd67d98eb8d26621d3c04512c508`.

H02 закрыт в объёме 10 типов/5 ответов, wire-schema у всех false. Следом H03:
простые Ping/Result serializers→primitive IO→framing/context; H04 auth
остаётся отдельным направлением. Ни один запрос аккаунту не отправлялся.

Итоговая проверка обоих headless test-модулей: 7/7, без skip.
Syntax parse новых Python-файлов, 22 локальные ссылки и `git diff --check` прошли.

## 18 октября 2026 — H03a: настоящий Ping body codec

Прочитаны актуальные указатели/задачи H02; прослежены Ping/Result IO calls до
конкретных buffer archive vtables. Receive Dispatch14679f510 передаёт body+5,
length−5, swap=0 в ctor 144aa6260 и вызывает packet reader+20. Подтверждены
raw read 144aa5ce0, u64/u32 readers, cursor/counters и optional bswap. Writer
ctor 144aa62f0/vtable14961a5c0→primitive writers→raw write144aa6120.

Создан `build-headless-ping-codec.py`: реальные native constructors и primitive/
raw IO исполнены в Unicorn. Только внешний VCRUNTIME140.dll!memcpy заменён
ограниченным copy shim; имя импорта доказано PE descriptors/IAT. Writer buffer
предвыделен 256 байтами, growth branch не исполнялась. Payloads в подтверждённой
ветке `<QQ`16 байт и `<IQ`12 байт. Поля остаются raw bits без догадок об epoch.
45 roundtrips/32buffer cases/4swap cases=126 native packet executions прошли.

Созданы `vampir_core/ping.py` и package marker: portable dataclasses encode/decode,
только stdlib. Decoder требует exact payload size; native reader допускает
trailing bytes и при failure уже частично изменяет объект/cursor. Это различие
явно документировано, протокол/heartbeat loop не имитируются.

Пять тестов сверяют native vectors с core, bytes/SHA/import, short/trailing/swap,
и повторно исполняют 6 native boundary/failure scenarios. Все прошли без skip.
Report: `F:/PhoneExit Resources/Vampir/code-clues/headless-ping-codec.json`,
SHA256 `b38d335947eac5836eb59161fb3656e2f0c3b51b29e42335c808afb2c62b590a`.
Подробности — HEADLESS-PING-CODEC.md, общий FUNCTION-INDEX обновлён.

Найдены output callers144aa9da0/144aaccf0 с тем же archive constructor;
служебные поля/size/checksum/transform ещё не разобраны. Нельзя посылать body
как complete frame. Следом H03b: helpers1445f1230/144aa6ca0, receive path и
handler slot+8→OnHandler+10. H03 partial, network_ready=false. Игра/сеть/аккаунты
не использовались; тяжёлые proof данные и эмулятор не входят в runtime.

Итоговая регрессия: 12/12 headless tests прошли без skip; syntax parse,
25 локальных ссылок и `git diff --check` прошли. Исходники текущего core
занимают 1709 байт (без интерпретатора/оболочки/данных); это не замер полной
сборки, памяти или производительности 20 сессий. P01/P02 остаются открытыми.
