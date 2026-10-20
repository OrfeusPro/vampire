# Страна регистрации SDK и список стран сервера

20 октября 2026. Продолжение [проверки состояния сервера](HEADLESS-SERVER-ENTRY-STATE.md).
Данные и код Windows-клиента; исходного C++ проекта нет.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Результат реальной проверки

Свежий SDK SignIn для bot-hk-test@vampir.top вернул joinedCountryCode **HK**.
Приняты вход в лобби и ID 104: 55 групп, 98 серверов, body 11 338 байт,
545 байт отправлено / 11 466 получено. Для JP-записей ID 251–270:

- array50 содержит по пять строк; проверка со свежим SDK country HK прошла
  для всех 20 записей, включая выбранный server ID 251 / group ID 251.
- Поле +0x35 равно 0; известные исключаемые состояния 2 и 3 отсутствуют.
- Остальные flags ещё не связаны с полным разрешением входа или созданием
  персонажа. Прохождение двух известных проверок не доказывает доступность всего сервера.

Таким образом, гипотеза о несовместимости HK с этим списком JP-стран
не подтвердилась. Причина предыдущего LoginResult 58 / BlockedIp остаётся
открытой. В этой проверке использован `--server-list-only`: игровой сокет,
Version и Login не создавались. Список персонажей ещё не получен.
Лобби закрыто; временный JP-транспорт завершён с exit 0 и пустым stderr.

Внешний country probe подтвердил JP. Страна выхода не подставлялась вместо
страны аккаунта. CDN / GMC2 получены через тот же loopback SOCKS 17948.
Снимки находятся в `F:/PhoneExit Resources/Vampir`:

- `public-cdn-snapshots/19a1ea69273ecd77e0ced489cf68e414b0e7fe9ffcdb0c284ef908417b386da0/manifest.json`, 6000 байт.
- `public-gmc2-snapshots/760eaac24f1b21d5ca9aec40a3729f681f2f6eae98a12f7d687300c189f5b663/manifest.json`, HTTP 200, 13 773 байта.

## Источник страны и проверка клиента

Существующий [разбор ответа SDK](HEADLESS-SDK-SIGN-IN-RESPONSE.md) уже подтвердил
constructor key auth+0x50 → joinedCountryCode и прохождение поля ответа
resultData.playerInfo.player.joinedCountryCode до setter 0x14454b8c0.
Теперь эта функция экспортирована в Ghidra и исполнена с bool=false,
как в response caller 0x1444cc9f5. Она передаёт строку на запись FString по
player+0x210 через 0x14143c260. Ветвь уведомления с bool=true не исполнялась.

Getter 0x1456048f0 получает SDK singleton через 0x1444aab90 и обращается к
player по singleton+0x110. Getter 0x1445242f0 копирует FString player+0x210.
Native predicate 0x145d3b1b0 вызывает эту цепочку и сравнивает строку с array50
выбранной серверной записи. Пустой массив принимает запись; отсутствующий
record отклоняется. Для непустого массива сначала сравниваются длины FString,
затем вызывается 0x1414596e0 с регистронезависимым ASCII-сравнением.
При выключенном SDK flag / отсутствующем manager или его player используется
fallback global 0x14b520d60. Его реальный initializer пока не связан.

В ServerList_Update этот predicate участвует в обработке рекомендованных ID.
Применение его как дополнительного фильтра нашего selector — явная локальная
политика. Это не восстановление всех проверок игрового сервера или UI.

[replay-server-country-policy.py](replay-server-country-policy.py) переиспользует
проверенный SDK response harness и выполняет на одних fixture objects:
auth constructor / response field slice → настоящий country setter → полный
predicate → настоящий record lookup и оба getter → настоящее сравнение.
Пятнадцать сценариев проверяют совпадение / отказ, совпадение второго элемента,
регистр, пустые строки / массив, отсутствие record, выключенный SDK flag,
отсутствие manager / player и fallback. Независимая модель проверяет результат.

JSON presence/object/string helpers, FString выделение / копирование, singleton
objects и fallback country — fixtures. Объект setter и объект getter намеренно
связаны в fixture; полное создание singleton / callback lifecycle не исполнено.
SDK response gates до field slice и полный ServerList_Update также не исполнялись.
Токены, страны и объекты этого replay синтетические; игра и сеть не запускаются.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/server-country-policy-replay.json`.
SHA256: `3cb13b832446f47fa26e44fa29a25f10e3ace98177a57a429e111bfd01800699`.
Отчёт содержит SHA переиспользованных response / device / lookup источников.
Индекс native-литералов расширен setter diagnostic; текущий SHA256
server-entry-index.json: `eb71020d69d3e24f75d011582031268ddbdda1a66e86960ef330f30c658054f2`.

Ghidra 12.1.4: 366 функций / 172 предупреждения.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-258411d5e987`.
Manifest SHA256: `bf223552c9512c07de9c0589346e9008b381327c297ff53f949c6cad243f5f9b`.
functions.json SHA256: `eef1fe17b98fda70d66ffefb18bb13ec994e2c6207b731fd8532c1cb4383a7be`.

## Runtime и границы

`game_server_allows_joined_country` проверяет array50 против отдельного
joined_country_code. Непустой массив требует явного двухбуквенного ASCII-кода;
неизвестное / пустое значение не заменяется страной выхода, почтой или кешем.
Регистр ASCII не влияет на результат. Native допускает совпадение пустых
строк; runtime намеренно не поддерживает такой country context.

`select_game_server_in_region` учитывает эту проверку после региона группы
и известных исключаемых состояний. Явный неподходящий ID отклоняется;
автоматический выбор продолжает поиск в том же регионе. Неизвестная страна
может допустить только запись с пустым array50. Endpoint-only selector и
прежняя Version-only команда без region сохраняют своё диагностическое назначение.

Login runner передаёт только свежую страну из того же SDK response, откуда
берёт остальные auth fields. Диагностика показывает двухбуквенный country code
и bool / null результата по каждой записи. Содержимое array50, host, тексты,
SDK tokens и идентификаторы пользователя не выводятся. `--server-list-only`
завершает работу после проверки цели, до CPU inputs и игрового сокета.

Пример после подготовки свежего маршрута и снимков:

```powershell
python -X utf8 phone-exit/bots/vampir-headless/probe-selected-game-login.py `
  --email bot-hk-test@vampir.top --profile recovered-base `
  --manifest 'F:/PhoneExit Resources/Vampir/public-cdn-snapshots/19a1ea69273ecd77e0ced489cf68e414b0e7fe9ffcdb0c284ef908417b386da0/manifest.json' `
  --socks-port 17948 --server-policy-byte 0 --region JP --selection lowest-valid-id `
  --context windows-sdk-initial-reset --extra-number 0 --server-list-only --password-stdin
```

Проверки: пять country policy, пять region/state, четыре Version selector,
три Login runner и три Ghidra — всего 20. Native replay воспроизводится
первым тестом; проверены остановка до игрового сокета и отсутствие auth / array50
текстов в диагностике. Далее — оставшийся контекст соединения / Login и причина
BlockedIp до успешного входа, списка / выбора персонажа и позиции.
