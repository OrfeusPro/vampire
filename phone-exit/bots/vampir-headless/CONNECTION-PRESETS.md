# Единый пресет подключения бота

Пресет объединяет устройство и сетевой маршрут. Он назначается аккаунту бота и
используется для выбранного сервера / персонажа этого аккаунта. Отдельных настроек
на каждый слот персонажа пока нет. Изменения формы применяются после сохранения,
работающий worker сначала нужно остановить. Настройки хранятся в console.sqlite3
и входят в [резервную копию](BACKUP.md); приватные значения не входят в Git.

## Выбор

- **По умолчанию:** текущие наблюдённые данные Windows ПК, прежняя привязка трёх
  ключей, прямой выход. Существующие записи автоматически не переводятся на custom.
- **Примеры:** desktop Intel, desktop AMD, laptop; каждый вместе с прямым выходом,
  Phone Exit SOCKS 127.0.0.1:1080 или локальным SOCKS 127.0.0.1:1081.
  Это образцы настроек, не наблюдённые устройства и не обещание совместимости.
- **Ручной профиль:** редактирование значений и сохранение нового именованного
  шаблона. Шаблон хранит аппаратные настройки и маршрут, без личных ключей.

При выборе custom-пресета ключи выбранного бота сохраняются. Если ключи ещё не
заданы, кнопка выбора готовит три независимых 128-битных случайных значения в форме.
Они фиксируются только при сохранении аккаунта. Отдельная кнопка создаёт новые
значения явно. При каждом входе они не меняются. Реестр наблюдённых ключей ПК
не переписывается; существующий confirmation-required gate сохраняется.
Новая identity не считается подтверждённой. После изменения устройства / маршрута
прежний sdk_created понижается до nid_verified, регистрация аккаунта не повторяется.

## Найденные поля и их применение

| Поля | Где применяются | Режим |
| --- | --- | --- |
| NID deviceKey | NID URL | Отдельный постоянный ключ |
| SDK deviceKey | SDK request, NID metadata | Отдельный постоянный ключ |
| nmDeviceKey | NID, SDK, лобби, game Version/Login | Отдельный постоянный ключ |
| Windows major/minor/build/product type/suite mask | NID osVersion, lobby Version, game Version | Наблюдение ПК или ручной WindowsVersion |
| CPU vendor / brand | game Version | Наблюдение ПК или ручной VersionCpuInput |
| I_DeviceOSVersion / I_NMCPU | Metadata лобби и тот же metadata в game Login | Автоматически из заданных Windows / CPU; иначе явные значения |
| I_DeviceModel / I_NMRAM / I_NMVGA | Та же metadata | Явные строки; единицы и принятие сервером не подтверждены |
| I_TimeZone / I_LanguageCD | Та же metadata | Явные строки; не меняют session clock и language byte игрового Login |
| I_ConnectIP / I_CountryCD | Свежая GMC2 geo через выбранный маршрут → metadata | Наблюдаемые данные, ручная подстановка запрещена |
| I_JoinedCountryCode | Свежие NID / SDK ответы | Страна аккаунта; может отличаться от страны выхода |
| SOCKS port | CDN config, NID browser, SDK HTTP, лобби и game TCP | Только loopback; прямой fallback отсутствует |
| Local / bound address | Version | Фактический адрес сокета / SOCKS bound endpoint, не поле для выдуманного IP |

При заданных CPU / Windows их metadata производятся из тех же значений, чтобы
избежать противоречия внутри одного запроса. Значения не записываются в progress
или redacted summary. Custom identity также разделяет WebView login-каталог по
digest ключей; исходные ключи не становятся частью имени каталога.

IP-адрес сервера определяется соединением. Несколько ботов с разными устройствами
могут использовать один SOCKS или прямой выход, как разные компьютеры за NAT.
Прокси нужно предварительно запустить отдельно. Поле порта не включает VPN и не
гарантирует страну. IMAP регистрации остаётся отдельным TLS-подключением к почте;
маршрут игрового HTTP не объявляется системным VPN.

## Границы полноты

Это настройка обнаруженных inputs Windows runtime, а не полная эмуляция устройства.
OS/platform codes, HTTP User-Agent и прочие browser headers остаются штатными для
Windows WebView. MAC, оператор, SIM, Android ID, Wi-Fi SSID не обнаружены как inputs
этого Windows-пути и не добавлены выдуманными полями. Marketing, ADID/IDFV/UDID,
часть metadata и активный SDK cache требуют дальнейшего исследования.
Версия игры, compiled tag, SDK source profile, токены, session sequence, временные
поля и ответы сервера формируются своими адаптерами; шаблон их не подменяет.

Живое принятие custom identity или аппаратных строк сервером не проверено.
Текущий source guard 1.13.16 не ослаблен. Новые поля metadata используют уже
найденные имена collector, но не доказывают перенос всего collector на новый SHA.
Поле «всё передаваемое» пока не закрыто: неизвестные inputs сохраняются как unknown.

## Проверки

Fixtures проверяют сохранность после перезапуска, разделение двух ботов при общем
маршруте, три разных ключа, неизменность исходной binding, confirmation gate,
согласованность system/metadata и запрет подменять geo/auth fields. Проверена
передача профиля worker → NID/SDK → лобби → game Version. Browser UI проверен на
изолированной базе: выбор пресета, генерация скрытых ключей, сохранение шаблона
и аккаунта, повторное открытие после reload. Игровые операции не запускались.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_bot_device_settings.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_sdk_runner.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_joined_country.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_selected_game_login.py
```
