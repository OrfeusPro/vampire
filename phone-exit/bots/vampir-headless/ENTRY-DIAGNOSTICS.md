# Диагностика входа и параметры устройства

Для текущего SHA добавлен отдельный read-only Fetch:

```powershell
python -X utf8 phone-exit/bots/vampir-headless/run-account-sdk-fetch.py --account '<локальный UUID>' --profile '<полный SHA Fetch-профиля>'
```

SHA берётся из `sdk-fetch-runtime-current.json`. Это отдельная capability чтения;
команда не вызывает SignUp, Terms, SignIn или игру. Флаг `--capture-sdk-http`
явно включает ограниченную DPAPI-запись SDK HTTP. В первой проверке Silvercrow
SDK сообщил `not exist player channel`; следующий шаг — текущий первый
SDK-профиль. [Доказательства и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-FETCH-READ-ONLINE.md).

Шаблоны устройств уже реализованы в [панели аккаунтов](ACCOUNT-CONSOLE.md).
Колонка «Шаблон устройства» открывает его просмотр; редактирование включается
отдельно. Назначение выбирается в попапе аккаунта. Сохранение формы не выполняет вход.
Подробная таблица применений находится в [CONNECTION-PRESETS](CONNECTION-PRESETS.md).

Шаблон хранит аппаратные настройки, три постоянных ключа и общее имя регистрации
для максимум двух аккаунтов / выбранных персонажей. Маршрут остаётся у аккаунта.
Изменение общего шаблона затрагивает пару; во время работы оно заблокировано.
Назначение не подтверждает принятие нового устройства сервером или эмуляцию Android.

## Какие параметры доступны

| Группа | Поля настроек | Применение |
| --- | --- | --- |
| CPU | vendor, brand | Version и производное I_NMCPU |
| Windows | major, minor, build, product_type, suite_mask | osVersion / Version и производное I_DeviceOSVersion |
| Аппаратная metadata | I_DeviceModel, I_NMRAM, I_NMVGA | Metadata игрового входа |
| Другие metadata | I_TimeZone, I_LanguageCD | Metadata; язык NID и язык игрового Login настраиваются отдельно |
| Общая привязка | device_key, nm_device_key, nid_device_key | Три разных постоянных ключа устройства |
| Имя регистрации | device_name | Общее DESKTOP-имя пары; deviceName официальной формы |
| Маршрут | socks_port или прямой выход | Общий маршрут конфигурации, SDK и игры |

Пароли, код из письма, accessToken и launcherToken не входят в шаблон. Геолокация
выхода получается через выбранный маршрут, player ID и страна регистрации —
из ответов аккаунта. `deviceName` окна регистрации берётся из назначенного
шаблона; `I_DeviceModel` не заменяет это имя.

## Что наблюдали при настоящем SDK-входе

5 ноября 2026 года вторичный аккаунт прошёл NID → launcher/token → launcher/sign-in
на клиенте SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Использован текущий ПК и прямой маршрут. Custom-шаблон этим запуском не проверен.
[Доказательство и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-SDK-ENTRY-11322.md).

| Этап | Поля |
| --- | --- |
| Начальный NID URL по адаптеру | gameCode, buildCode, countryCode, language, os, nmDeviceKey, deviceKey, osVersion, clientId, nidV, webViewType, authType |
| launcher/token JSON | nmDeviceKey, deviceKey, countryCode, os, credential.channelAccessToken, credential.channelCode, credential.gameCode, credential.buildCode |
| launcher/sign-in JSON | nmDeviceKey, deviceKey, countryCode, os |
| Заголовки SDK | gameCode, buildCode; launcherToken только во втором запросе; Content-Type, Accept, Accept-Encoding, User-Agent |
| Ответ SDK | errorCode, errorMessage, accessToken; playerInfo.player и idpInfo |
| Данные player | playerId, gameCode, joinedCountryCode, joinedOs, gameRegion, status, playerStatus |
| Состояния playerStatus | restriction, withdraw, deviceSecure |

В наблюдавшемся ответе `restriction = ["workplace"]`,
`deviceSecure = ["device-registration"]`. Это полученные состояния сервера;
они не доказывают причину ограничения. Успешный SDK-вход не снимает их автоматически.
В этом диагностическом запуске окна регистрации устройства и защиты аккаунта
не проходились; игра и HP / MP не читались. Последующие результаты форм находятся
в [живом отчёте](../resource-tools/vampir/knowledge/evidence/auth/ACCOUNT-VERIFICATION-11322-LIVE.json).

Начальный каталог NID прошлой записи перечислял только непустые query-параметры;
`countryCode=` присутствует в формируемом URL, но не попал в тот каталог.
Новая диагностика сохраняет также имена пустых параметров.

## Запуск команды

```powershell
python -X utf8 phone-exit/bots/vampir-headless/run-account-entry-diagnostic.py --account '<локальный UUID аккаунта>' --profile '<полный SHA SDK Launcher профиля>'
```

Команда читает пароль из локального DPAPI-хранилища, выполняет одну попытку
и закрывает свои соединения. Не создаёт аккаунт, не входит в мир, не повторяет
неизвестный результат и не запускает наблюдатель обновлений.

`sdk-launcher:<SHA>` проверяет точный EXE и все 98 входов immutable профиля.
Его область — launcher SDK; создание профиля SDK, прямой SignIn и разрешения
игрового мира не предоставляются. Проверка и зависимости включены в существующий
`sdk-runtime-launcher-11316` с вариантом текущего SHA и `on_update`.

Приватный каталог `.local/verification-captures/<ID>/` содержит:

- `sdk-http.dpapi` — зашифрованные Windows DPAPI записи HTTP payloads SDK;
- `report.json` — результат, этапы, имена и типы полей без значений credentials.

Лимиты — 10 минут и 4 МиБ исходных payloads; ожидание формы NID ограничено максимум
300 секундами. Это запросы и ответы SDK на уровне HTTP-библиотеки, а не TLS
records, трафик официальной игры или все запросы встроенной страницы NID.
Для верификации используется отдельная команда и очередь панели.

Отдельный `capture-verification-navigation.mjs` наблюдает только URL / статус /
навигацию явно подключённого Chromium на loopback-портах 17951 / 17952.
Он не расшифровывает TLS и не записывает тела или заголовки; его приватный журнал
может содержать параметры URL. Автоматически к игре или после reconnect не подключается.

[Результат проверок и повторов кэша](../resource-tools/vampir/knowledge/evidence/auth/SDK-ENTRY-11322-VALIDATION.json) фиксирует 12 SDK / diagnostic случаев, два повтора без дочерних процессов и неизменность 59 frozen inputs.

## Официальные формы верификации

Для аккаунта без профиля игрового SDK доступен отдельный текущий first SDK пакет.
Он выполняет один Fetch, два строгих NO DATA и при необходимости один SignUp /
SignIn. Это не повторная регистрация Netmarble и не создание персонажа.
При существующем профиле SignUp не отправляется. Пароли берутся из локального DPAPI.

```powershell
$firstProfile = (Get-Content -Raw phone-exit/bots/resource-tools/vampir/knowledge/sdk-first-profile-current.json | ConvertFrom-Json).profile.sha256
python -X utf8 phone-exit/bots/vampir-headless/run-account-first-sdk.py --account '<локальный UUID аккаунта>' --profile $firstProfile --terms-country observed --terms-locale ru-RU --basic-terms-mode all
```

`observed` выбирает ISO-страну из свежего GMC2; язык и ветвь запроса указаны явно,
нативные defaults ими не объявляются. Доступные условия требуют просмотра и
останавливают автомат. Известные device/workplace states проходят через тот же
готовый адаптер форм; неизвестный результат завершает операцию. SDK-профиль
Silvercrow подтверждён онлайн. [Контракт, ограничения и результат](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-FIRST-SDK-PROFILE-CURRENT.md).

```powershell
python -X utf8 phone-exit/bots/vampir-headless/verify-account.py --account '<локальный UUID аккаунта>'
python -X utf8 phone-exit/bots/vampir-headless/verify-account.py --account '<локальный UUID аккаунта>' --manual-sign-in
```

Команда открывает формы по состоянию свежего SDK-входа. Сначала обрабатывается
регистрация устройства, затем защита аккаунта. Для каждого этапа выбирается код
из отдельного нового письма в пределах десяти минут. Успех требует положительного
HTTP-ответа и callback официальной формы. При незнакомом результате операция
завершается с кодом 2. Те же этапы доступны из таблицы аккаунтов.

После `login_failed` у NID запускается один ручной вход с новым GMC2 контекстом.
Флаг `--manual-sign-in` сразу выбирает ручной ввод. Форма проверяет адрес перед
отправкой, а callback принимается после совпадения адреса с выбранным аккаунтом.
Кнопка продолжения очереди сохраняет уже подтверждённые записи.

Точный список query и полей веб-запросов, источник `deviceName`, подтверждённый
SHA и результат живой проверки описаны в отдельном отчёте.
[Контракт форм верификации](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-ACCOUNT-VERIFICATION-11322.md).

Требования к общему входу будущего бота, проверкам после отключения и ручному
продолжению — в [BOT-ENTRY-FLOW](BOT-ENTRY-FLOW.md). В обычный игровой вход
общий адаптер форм встроен до лобби без повторной авторизации; отказ, неизвестное
состояние и истёкший контекст останавливают продолжение. Полный игровой вход
текущего SHA и восстановление после отключения этим не подтверждены.
