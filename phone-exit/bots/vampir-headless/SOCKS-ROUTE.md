# Явный SOCKS-маршрут бота через Phone Exit

20 октября 2026. Добавлен общий локальный маршрут окна NID, публичного GMC2
и SDK HTTP. Системные маршруты и proxy-настройки Windows не меняются.
Игровой сокет этим адаптером ещё не подключён.

## Зависимость и запуск

Используется [PySocks](https://github.com/Anorov/PySocks/blob/master/README.md)
1.7.1: отдельный socket с SOCKS5 и remote DNS. Глобальный socket не подменяется,
неподдерживаемый urllib handler из пакета не используется. HTTPSConnection
оборачивает полученный socket обычным TLS с проверкой цепочки и hostname.
Закрепление wheel — в `requirements-runtime.txt`, SHA256:
`2725bd0a9925919b9b51739eea5f9e2bae91e83288108a9ad338b2e3a4435ee5`.
Pure Python пакет установлен в игнорируемую папку, без изменения глобального
Python. Аналитические Ghidra / Unicorn / SDK-инструменты в runtime не добавлены.

```powershell
python -m pip install --no-deps --require-hashes --only-binary=:all: --target phone-exit/.tools/vampir-python-runtime -r phone-exit/bots/vampir-headless/requirements-runtime.txt
python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-gmc2-config.py --fetch --socks-port 17948
python -X utf8 phone-exit/bots/vampir-headless/run-nid-sdk-sign-in.py --email bot-test@vampir.top --timeout 100 --password-stdin --create-sdk-player --socks-port 17948
```

Последняя команда читает пароль из stdin. Настоящие пароли в текст команды,
аргументы, файлы или журналы не включать. Она выполняет один SignUp; для
обычного SignIn флаг `--create-sdk-player` убрать. Перед запуском нужен уже
подключённый локальный SOCKS Phone Exit. Эти команды не включают его сами.

## Связь компонентов и ограничения

`vampir_core.socks_route.SocksRoute(port)` допускает только 127.0.0.1 и порт
1024–65535. PySocks получает rdns=True; DNS назначения выполняет телефон.
Отказ SOCKS или TLS не включает прямую повторную попытку. Обычный HTTP
отклоняется до соединения. Системные / environment proxy игнорируются.
Redirect SDK и GMC2 по-прежнему запрещён.

WebView2 получает тот же порт через CreationProperties.AdditionalBrowserArguments:
`--proxy-server=socks5://127.0.0.1:17948 --disable-quic`. В аргументы процесса
попадает только фиксированный путь helper; запрос с параметрами передаётся
через stdin. Папка WebView2 отделена от прямого режима суффиксом socks-port.
Автоматизация формы остаётся однократной; CAPTCHA и подтверждения не обходятся.

Fetcher сохраняет выбранный порт в transport metadata снимка GMC2. Runner
проверяет SHA manifest / body, HTTP 200 и совпадение маршрута. Прямой режим
не принимает снимок SOCKS и наоборот; другой порт также отклоняется до окна.
В режиме SOCKS `geoIp.isoCountry` из проверенного ответа GMC2 задаёт явный
countryCode собственного клиента и для NID query, и для SDK body. Это не
утверждение о прочитанном активном native settings cache. В прямом режиме
сохраняется прежний выбор SDK country из provider joinedCountryCode.

Порт — идентификатор локального маршрута, а не криптографическая привязка
к телефону или гарантия неизменной географии. После переподключения / выбора
другого телефона заново получать GMC2. Автоматический владелец Phone Exit
и обновление снимка внутри bot runner ещё не реализованы.

## Реальные проверки

Отдельный временный клиент Phone Exit подключён к доступному личному HK-выходу.
Cloudflare trace по SOCKS подтвердил HK. Затем Python HTTPS через тот же SOCKS
получил GMC2 HTTP 200, 13 777 байт, geoIp.isoCountry=HK.
Неизменяемый снимок вне Git:
`F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/070408d4d6fff16f5b7fe4c95aaaa8f9fdbef4ac5f4d958f1475655b4d5c747a/manifest.json`.
SHA256 manifest совпадает с именем каталога. DECKEY / geoIp body не выводились.

Две попытки с этим маршрутом получили настоящий NID callback и дошли до
SDK SignUp. Обе отклонены HTTP 400 / 1602; диагностическая попытка подтвердила
`not allowed country for game`. При этом NID joinedCountryCode=UA, а SDK body
countryCode=HK. Различие установлено фактически. Причинная связь между
страной аккаунта и отказом пока не доказана; один HK IP проблему не устранил.
Запись SDK-игрока и игровая сессия не созданы / не подтверждены.

В официальном My Profile видны управление email, nickname, recovery email,
marketing и связанные сервисы. Видимого поля смены страны на этом экране нет.
Подмена страны аккаунта не выполнялась. Для проверки гипотезы предложены
готовый HK/JP-аккаунт или отдельная новая регистрация через HK. Пользователь
выбрал готовый аккаунт; ожидаются почта и вход в штатном окне. Новый ящик
и дополнительный Netmarble ID не создавались.

После проверки временный клиент остановлен командой владельца и завершился
с code 0. Системные маршруты не менялись. Наличие успешного HK HTTPS не
объявляется успешной регистрацией SDK или получением персонажа.

## Локальная проверка

31 целевой тест прошёл: четыре SOCKS, шесть runner, семь публичного GMC2,
четыре adapter, шесть SDK HTTP и четыре SignUp. WebView2 smoke также прошёл.
В тесте настоящий локальный SOCKS fixture принимает доменное имя unit.invalid,
затем TLS и HTTP: доверенный сертификат принимается, недоверенный отклоняется.
Проверены закрытие socket при ошибке, отсутствие глобального monkeypatch,
запрет HTTP без прямого DNS и соответствие одного маршрута NID / SDK.
Отдельный fixture на настоящем HK-снимке проверяет отклонение другого порта
и прямого режима. Это не нагрузочный или Android-тест.
