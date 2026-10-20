# Реальные проверки игрового Login

## Ревизия ClientVersion 258392: снова InvalidState

20 октября 2026 выполнена одна попытка с extra_number = 258392 из установленного
windows.manifestlist. Прежний аккаунт / Windows device profile, JP server ID 251;
новая SDK-сессия, страна HK. Лобби приняло `[2, 104, 4]`, все коды 0,
send 545 / recv 11 466, socket сохранялся во время игрового обмена.
Игра вернула Version 0 / Login 16, body 131, send 641 / recv 94 байта,
других ID нет. Персонажи не запрашивались; сокеты и JP-транспорт закрыты,
exit 0, stderr пуст. Изменение ревизии пока не устранило отказ.
[Связи ClientVersion, SHA и снимки](../resource-tools/vampir/HEADLESS-PATCH-CLIENT-VERSION.md).

## Login в лобби для JP 251 и сохранение соединения

20 октября 2026 выполнены две проверки исправленной цепочки: Version → список
серверов → lobby Login с выбранным ID 251. Во второй lobby socket оставался
открытым во время игрового обмена. Ответы лобби `[2, 104, 4]` приняты,
все result codes = 0, send 545 / recv 11 466, 55 групп / 98 записей.
Обе проверки получили игровой Version 0 / Login 16, InvalidState, body 131,
send 641 / recv 94 байта. Персонажи не запрашивались. Сокеты и JP-транспорт
закрыты, exit 0, stderr пуст. Изменённый порядок сам по себе отказ не устранил.
[Связи, исправление и снимки конфигураций](../resource-tools/vampir/HEADLESS-SELECTED-LOBBY-LOGIN.md).

## Повтор с новой SDK-сессией: снова InvalidState

20 октября 2026, по просьбе пользователя проверен один повторный вход.
JP-выход подтверждён country probe; аккаунт bot-hk-test@vampir.top,
Windows-профиль Netmarble, сервер 251 и параметры Login сохранены.
Получены новые NID / SDK credentials только в памяти; SDK вернул страну HK.
Лобби приняло Version / Login / список серверов: коды 0 / 0 / 0,
55 групп, 98 записей, send 545 / recv 11 466 байт.

Игровой сервер снова вернул Version 0 / Login 16, InvalidState;
body 131 байт, send 641 / recv 94, других packet ID нет.
Подсчёт байтов полный. Контекст windows-sdk-initial-reset,
extra_number = 0, адрес из SOCKS bound metadata неизвестен и передан пустым.
Повтор с новой SDK-сессией не устранил отказ. Это не доказывает причину ошибки
и не проверяет все варианты повторного входа настоящего клиента.

По сообщению пользователя персонажей на аккаунте нет; серверный список
персонажей ещё не получен. Пользователь разрешил создать первого персонажа
с любым доступным ником, классом и внешностью по умолчанию после успешного
входа и проверки протокола создания. В этой попытке запросов списка / создания
персонажа не было. Автоматические повторы не включались.
Игровые сокеты закрыты, JP-транспорт остановлен, exit 0, stderr пуст.

Свежие публичные manifest, вне Git:

- CDN: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/487d395397806705a001ae19712f3d96a06f8acf523455bb8a50793fe55441d4/manifest.json`,
  SHA256 `487d395397806705a001ae19712f3d96a06f8acf523455bb8a50793fe55441d4`, body 6000 байт.
- GMC2: `F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/3f109a829421701e93a06d1e05465481565783a032d63fadb575e188317fb8f6/manifest.json`,
  SHA256 `3f109a829421701e93a06d1e05465481565783a032d63fadb575e188317fb8f6`, HTTP 200, body 13 773 байта.

## После замены телефонов: код 16 / InvalidState

После сообщения пользователя о замене телефонов выбран доступный JP-выход,
country probe JP. Тот же bot-hk-test@vampir.top / server ID 251 получил
свежие SDK / lobby / ID 104, затем Version 0 / Login 16, body 131 байт,
send 641 / recv 94. Native mapper подтвердил InvalidState. Код 58 в этой
попытке не получен; причина изменения ещё не доказана. Windows-профиль
Netmarble и аккаунт сохранены. Персонажи не запрашивались, сокеты и JP-клиент
закрыты, exit 0, stderr пуст. Новая почта пока не создавалась.
[Снимки, расшифровка и границы](../resource-tools/vampir/HEADLESS-RESULT-ERROR-16.md).

## Version с неизвестным адресом исходящего SOCKS-соединения

Для того же JP server ID 251 поле Version+0x58 теперь пустое: Phone Exit
возвращает bound 0.0.0.0:0, а 127.0.0.1 относится к подключению к прокси.
Свежие SDK / lobby / ID 104 приняты, SDK HK допускается JP array50.
Получены Version 0 / Login 58, body 131 байт, send 641 / recv 94.
Отказ сохраняется; влияние правильного адреса и полная причина ещё неизвестны.
Персонажи не запрашивались. Сокеты и JP-клиент закрыты, exit 0, stderr пуст.
[Native-проверка, снимки и границы](../resource-tools/vampir/HEADLESS-CONNECTED-LOCAL-ADDRESS.md).

## Отдельная проверка страны без повторного игрового Login

После подтверждения native country predicate свежий SDK вернул HK.
Все JP server ID 251–270 допускают HK по array50; selector выбрал 251.
SDK / lobby вход и ID 104 приняты: 55 групп, 98 записей, body 11 338 байт,
send 545 / recv 11 466. Использован --server-list-only: игрового сокета,
Version / Login и запроса персонажей в этой проверке не было. Лобби закрыто,
JP-клиент завершён с exit 0, stderr пуст. Предыдущий BlockedIp не объясняется
несовпадением HK с проверенным country list.
[Снимки и границы](../resource-tools/vampir/HEADLESS-SERVER-COUNTRY-POLICY.md).

## Проверка состояния JP-серверов

Свежая попытка с native-фильтром record+0x35 получила 20 JP-записей ID 251–270.
У всех enums +0x34/+0x35/+0x60 равны 1/0/0; ни одна не имеет исключаемых
состояний 2/3. Array50 содержит по пять строк; содержимое не выводилось.
Остальные flags ещё не связаны с входом / созданием персонажа.
JP 251 снова получил Version 0 / Login 58, body 131 байт, send 650 / recv 94.
Найденное условие сброса выбранного сервера не объясняет этот отказ.
Сокеты и временный JP-клиент закрыты, exit 0, stderr пуст.
[Native-проверка, снимки и границы](../resource-tools/vampir/HEADLESS-SERVER-ENTRY-STATE.md).

## Проверка явного региона JP

Следующая свежая попытка использовала `--region JP`, а не прежний минимальный
ID общего списка. Связи региона подтверждены [native-проверкой и таблицами](../resource-tools/vampir/HEADLESS-SERVER-REGION-SELECTION.md).
Свежий ID 104 показал: старый server ID 101 имеет region code 1 / KR.
Новый selector выбрал **server ID 251 / group ID 251, JP / 4**.

SDK / lobby вход и список серверов приняты. На выбранном JP-сервере получены
VersionResult 0 и LoginResult 58 / BlockedIp, body 131 байт; send 650 / recv 94.
Контекст остался windows-sdk-initial-reset, extra_number 0. Выход подтверждён
как JP. Сокеты закрыты; временный JP-клиент остановлен с exit 0, stderr пуст.
Список персонажей ещё не отправлялся. Неправильный регион прежнего выбора
устранён, но причина оставшегося отказа не доказана.

Снимки: CDN `7b820d47c6cdd663834ea7bfcfe8bb4e45925cfa4945b158c0fa440dd52e032c`
(6000 байт), GMC2 `0637c3934c505e0a60074e8d3cfe9539e38fdf4a94347b665c372c6c335cc723`
(HTTP 200, 13 773 байта), каталоги `public-cdn-snapshots` / `public-gmc2-snapshots`
в `F:/PhoneExit Resources/Vampir`, файл manifest.json. Имена каталогов — SHA256 manifest.

Текущий пример запуска после подготовки свежего маршрута / снимков:

```powershell
python -X utf8 phone-exit/bots/vampir-headless/probe-selected-game-login.py `
  --email bot-hk-test@vampir.top --profile recovered-base `
  --manifest 'F:/PhoneExit Resources/Vampir/public-cdn-snapshots/7b820d47c6cdd663834ea7bfcfe8bb4e45925cfa4945b158c0fa440dd52e032c/manifest.json' `
  --socks-port 17948 --server-policy-byte 0 --region JP --selection lowest-valid-id `
  --context windows-sdk-initial-reset --extra-number 0 --password-stdin
```

Уточнение: [код 58 подтверждён как BlockedIp](../resource-tools/vampir/HEADLESS-RESULT-ERROR-58.md).
Ниже сохранён результат первой реальной попытки до этой расшифровки.

## Дополнительная проверка через JP

После расшифровки кода проверен другой маршрут. Первый выбранный JP-выход
не установил SOCKS, завершился с exit 1; запросов к игре через него не было.
Другой доступный JP-выход установил транспорт: внешний country probe вернул
JP, свежий GMC2 geoIp также указал JP. Адреса выходов не сохранялись.

На прежнем server ID 101 / group ID 1 с прежним начальным контекстом и
extra_number 0 снова пройдены свежие SDK / lobby вход и ID 104. Игровые
VersionResult 0 и **LoginResult 58 / BlockedIp**, body 131 байт; send 650 /
recv 94. Список персонажей не запрошен. Сокеты закрыты, временный JP-клиент
остановлен с exit 0, stderr пуст. Это не доказывает блокировку всех JP-сетей
и не устанавливает причину ограничения именно этих выходов.

Снимки этой попытки:

- CDN: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/60d42cdbcd2d7e1ae71ba238f2d50d8b22f38c9e575542303cef0f600c11d723/manifest.json`, 6000 байт.
- GMC2: `F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/a5a1b79d68d849cb6cbbe89aa842746b2a71dc543fb0610da027d84b9f248add/manifest.json`, HTTP 200, 13 773 байта.

В расшифрованном CDN включены NetmarbleS.UseRegion и UseNetmarbleJoinedCountry.
ContinueBillingCountryCodes содержит KR, JP, TW, HK, MO; поле о billing не
объявляется whitelist сетевого входа. Связь этих флагов с выбранным регионом
и полями игрового Login остаётся следующим источником для проверки.

20 октября 2026. Проверка выполнена без запуска игры через личный HK-транспорт.
Источник пакетов — код установленного клиента с EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Результат

На аккаунте bot-hk-test@vampir.top пройдена свежая цепочка:

1. SDK SignIn принят.
2. Лобби ответило на Version / Login / ServerListRead кодами 0.
   Полностью разобран ID 104: 55 групп, 98 серверных записей, тело 11 338 байт.
   Обмен с лобби — 545 байт отправлено, 11 466 получено.
3. Из свежего списка выбран server ID 101 / group ID 1 по явной локальной
   диагностической политике lowest-valid-id.
4. На одном игровом соединении отправлены Version и, после ответа с кодом 0,
   Login. **Получен полный LoginResult с кодом 58, тело 131 байт.**
   Игровой обмен — 650 байт отправлено, 94 получено; счётчики полные.

Вход отклонён. Название и причина кода 58 пока не установлены. Код из
несвязанного enum или соседняя строка данных не являются его расшифровкой.
Запрос персонажей не отправлялся; позиция и готовность игровой сессии
не подтверждены. Сокеты закрыты. Временный HK-клиент остановлен с exit 0,
его stderr пуст. Системные маршруты не менялись.

Предыдущая попытка остановилась на этапе NID с общим RuntimeError до игрового
соединения; HK-процесс завершился с exit 1. Причинная связь между этими
событиями не установлена. После добавления безопасных статусов окна и
диагностики транспорта HK переподключён, получены новые публичные снимки,
и следующая ограниченная попытка дошла до игрового LoginResult.
Автоматического повтора входа или перебора серверов нет.

## Контекст запроса

Использован [сборщик начального Windows SDK-контекста](../resource-tools/vampir/HEADLESS-LOGIN-INITIAL-CONTEXT.md):
`windows-sdk-initial-reset`, без NID UserInfo / manager68, byte настроек 7,
начальная строка wrapper пустая. Дополнительное uint32 +0x50 явно выбрано
равным 0 как локальная политика собственного клиента. Это не утверждение
о тексте исходного игрового контрола или его начальном значении.
ID сервера передаётся отдельно в +0xb0.

Две строки LobbyLoginResult, отдельный Netmarble ID, SDK accessToken и
наблюдённая привязка устройства принадлежат одной свежей попытке. Callback
`_consume_auth` передаёт их только в памяти после успешного ответа лобби.
Контейнер `AuthForGame` скрывает поля в repr. Ключи, пароли, токены и сырые
auth-ответы не записывались в файлы и Git.

## Runtime и границы

[probe-selected-game-login.py](probe-selected-game-login.py) проверяет источники,
выполняет SDK / lobby вход, выбирает endpoint из свежего ID 104 и собирает
оба игровых пакета. [exchange_game_login](../vampir-shared/vampir_core/game_login_probe.py)
использует существующие GameConnection / LoginFlow, общую очередь, sequence
и обработку смены ключа. Отдельного второго сокета между Version и Login нет.

LoginFlow сохраняет безопасные коды обоих ответов и размер последнего тела
после закрытия. Ненулевой результат закрывает соединение; ни decoder, ни probe
не выдумывают название ошибки. По 10 секунд отведено каждому игровому ответу;
общий предел — 20 секунд. Ограничены входные данные и неизвестные пакеты.
Список персонажей не запускается автоматически по code 0.

При исключении внутри pump текущий вызов может не вернуть счётчики байтов;
`byte_counts_complete=false` явно отмечает эту границу. В реальной попытке
с кодом 58 такого исключения не было. В ошибках NID наружу допускаются только
фиксированные browser_status / sign_in_step; прочие строки заменяются unknown.

## Снимки и воспроизведение

Для попытки с ответом 58 использованы свежие публичные snapshots:

- CDN: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/a99fa14b0d01326fa187d48fb66e366f181d46f0ba7418e2e68b319f12adc6e8/manifest.json`, 6000 байт.
- GMC2: `F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/296ec942c5ae27871ec2758893c4e4889d7cb00125e11a4db8a593c5eb76184e/manifest.json`, HTTP 200, 13 777 байт.

Имена каталогов — SHA256 manifest. Предыдущая попытка использовала CDN
`de4290a628e2f548d75e64bd4b9cae5eb32a7dd3e6b2bd19ff9237f00ec9a76b`
и GMC2 `3659971df64f275cbf8f64cd3be0b2df38510268703ff6c687429c6a2b2580cd`.
Поля Version описаны в [реальной проверке версии](LIVE-GAME-VERSION.md),
схема ответа — в [LoginResult reader](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).

Из корня проекта, пароль только через stdin; перед новой внешней попыткой
нужны действующий HK-транспорт и новые снимки:

```powershell
python -X utf8 phone-exit/bots/vampir-headless/probe-selected-game-login.py `
  --email bot-hk-test@vampir.top --profile recovered-base `
  --manifest 'F:/PhoneExit Resources/Vampir/public-cdn-snapshots/a99fa14b0d01326fa187d48fb66e366f181d46f0ba7418e2e68b319f12adc6e8/manifest.json' `
  --socks-port 17948 --server-policy-byte 0 --region KR --selection lowest-valid-id `
  --context windows-sdk-initial-reset --extra-number 0 --password-stdin
```

Прошли 35 проверок: 5 game login probe, 3 orchestration, 7 LoginFlow,
9 GameConnection, 5 lobby probe и 6 NID browser. Проверены один сокет /
sequence, оба кода при отказе, отсутствие Login при отказе Version, timeout
без повтора, повреждённый ответ, передача контекста в памяти и безопасные ошибки.

Далее — связать код 58 с обработчиком / данными клиента и проверить причину
отказа, затем получить успешный Login и перейти к списку / выбору персонажа.
