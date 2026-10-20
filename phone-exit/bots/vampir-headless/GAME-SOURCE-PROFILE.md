# Явный base-профиль и первая TCP-проверка лобби

20 октября 2026. Наш клиент получил явный профиль recovered-base из проверенного
основного Game.ini. AppVersion привязывается к двум подтверждённым полям пакетов.
Свежий публичный CDN config получен через HK; TCP-соединение с указанным в нём
лобби установилось. За три секунды чтения сервер ничего не прислал.
Игровые пакеты и учётные данные не отправлялись, Login не проверен.

## Выбор профиля и происхождение

Основной INI содержит AppVersion 1.12.14 / ConfigPrefix real / CdnConfig True,
patch INI — 0.1.1 / dev / False. Их native порядок применения ещё не установлен.
Профиль recovered-base — явный выбор конфигурации собственного клиента для
сетевой проверки. Он не объявляется снимком активного GConfig игры; поле
active_game_cache_verified остаётся false. Это продолжение ранее выбранного
[публичного base CDN-профиля](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md),
а не новый алгоритм выбора по внешнему виду строки версии.

`game-source-profile.py` требует `selected_profile='recovered-base'`.
Он проверяет текущие файлы установленной игры и неизменяемый снимок:

- EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
- Основной PAK SHA256: `c10228ece0e1252bdd3ccf99fd4936e52d7a144f96c634080947d24c429e525b`.
- Snapshot manifest SHA256: `393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db`.
- DefaultGame.ini SHA256: `7a50c4ccbdfddbf691ca4177156f4175618b9f650ac4dd40722fded013ffd792`.

Snapshot находится в `F:/PhoneExit Resources/Vampir/resource-config-snapshots/`.
Каждая NetworkSetting row сверяется с точным номером строки и key/value в INI.
Дубликат или изменённые source bytes отклоняются. Старое извлечение нельзя
молча перенести на обновившийся EXE / PAK. Runtime не извлекает PAK заново,
не загружает Ghidra / Oodle и не пытается восстановить весь Unreal startup.
Проверенное извлечение остаётся [отдельным инструментом](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

```powershell
python -X utf8 phone-exit/bots/vampir-headless/game-source-profile.py --profile recovered-base --check
```

## AppVersion в пакете

`vampir_core.login_context.bind_game_app_version(version, login, app_version=...)`
заполняет Version+0x10 и Login+0x40, то есть strings[0] / strings[3].
Source chain уже установлена: NetworkSetting/AppVersion → global 0x14b520d10
→ оба packet preparation paths. Источники:
[global loader](../resource-tools/vampir/HEADLESS-CDN-CONFIG.md),
[Version fields](../resource-tools/vampir/HEADLESS-CONNECTED-VERSION-PACKET.md),
[Login fields](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-FIELDS.md).

Binding сохраняет все остальные строки / integers / bytes и исходные immutable
templates. Пустая версия и несовпадающий уже заполненный контекст отклоняются.
`game-source-profile.bind_profile(...)` объединяет проверку выбранного профиля
с этой привязкой. Это AppVersion игрового профиля, не версия Netmarble SDK.
Серверное принятие версии пока не проверено.

## Свежий CDN через HK

`fetch-public-cdn-config.py --socks-port` теперь использует общий SocksRoute
с remote DNS / обычным TLS. Прямого fallback нет; origin / body / timeout /
redirect limits прежние. В transport metadata сохраняется выбранный порт.
Прямой режим сохраняет прежнее поведение. Offline snapshot check не принимает
SOCKS-параметр, так как соединение не открывает.

Временный Phone Exit через личный телефон подтвердил HK по Cloudflare trace.
CDN GET вернул HTTP 200 / 6000 байт; существующие decoder / selector выбрали
environment real, entry REAL, порт лобби 12000. Manifest:
`F:/PhoneExit Resources/Vampir/public-cdn-snapshots/4939dc4752684068106f52bc4954d3f8ebd43ff470fa43d1ae14e8f0d0a6736a/manifest.json`.
SHA256 manifest совпадает с именем каталога. Значения SDK / аккаунта не использовались.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-cdn-config.py --fetch --socks-port 17948
```

Снимок не удостоверяет текущую страну выхода после переподключения Phone Exit.
Порт — идентификатор выбранного локального маршрута, не криптографическая
привязка к телефону. Для нового соединения заново получать CDN и проверять выход.

## Ограниченная проверка лобби

`probe-lobby-connection.py` читает явно указанный manifest, проверяет его SHA,
body SHA, HTTP 200, source profile / URL и совпадение SOCKS-порта. Первый
вариант probe поддерживает только публичный IPv4 из результата CDN selector
и decimal port 1–65535. Loopback / private / IPv6 / malformed port отклоняются
до соединения. Адрес не перебирается и не составляется по догадке.

Через тот же SOCKS выполнен один TCP connect с timeout 10 секунд, затем
один recv до 65 536 байт с timeout 3 секунды. Получен read_timeout, 0 байт;
сокет закрыт. Любой путь после connect закрывает socket, send / sendall
не вызываются. Raw server bytes не сохраняются и не печатаются.
Это подтверждает TCP-доступность лобби, не совместимость frame / key /
Version / Login, не SDK-сессию и не список персонажей.

```powershell
python -X utf8 phone-exit/bots/vampir-headless/probe-lobby-connection.py --manifest "F:/PhoneExit Resources/Vampir/public-cdn-snapshots/4939dc4752684068106f52bc4954d3f8ebd43ff470fa43d1ae14e8f0d0a6736a/manifest.json" --socks-port 17948
```

Временный HK-клиент штатно остановлен после проверки, exit 0.
Маршруты и proxy-настройки Windows не менялись.

## Проверки и следующий шаг

Все 16 целевых тестов прошли: пять source profile / lobby probe, пять CDN,
шесть Login context. Проверены real snapshots / installed source hashes,
отказ изменённого INI / body, маршрут без direct fallback, запрещённые
назначения, bounded read / close без отправок и привязка AppVersion.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_source_probe.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_public_cdn.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_context.py
```

Далее — callback string Version, выбранный игровой server record и остальные
Login inputs / policy flags. После этого можно отправить контролируемый игровой
запрос через HK и перейти к списку персонажей. Native config precedence остаётся
отдельным неизвестным; выбор recovered-base его не закрывает.
