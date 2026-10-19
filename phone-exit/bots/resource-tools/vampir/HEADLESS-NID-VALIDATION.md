# NID OnResult: проверки и аргументы принятия токенов

19 октября 2026. Продолжение [result routing](HEADLESS-NID-RESULT.md).
Исполнен участок compiled OnResult от 0x1450ee94a до 0x1450ef437 и отдельный
FString copy constructor 0x141420cc0. 22 fixtures подтвердили caller gates и
раздельные аргументы access token / refresh token / ID / country.
Это ещё не исполненные setters, callback, persistence или игровая сессия.

## Источник и воспроизведение

[replay-nid-result-validation.py](replay-nid-result-validation.py) читает установленный EXE,
проверяя полный SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это данные/код собранного клиента, не исходный C++ проект.
Предыдущий static index и 14 initializer bindings переиспользованы.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/nid-result-validation-replay.json`, SHA256
`3d32143ca21985d0545a286469f71efc58ef1893543b842590ff3f2462a08333`.
Сохранены bytes/instructions/file offsets/SHA, полный OnResult и copy constructor,
отдельные static fragments/diagnostics settings methods, inputs/events/outcomes.

Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-result-validation.py`.
Unicorn 2.1.4 / Capstone 5.0.6 из локальных tools; instruction budget 4096.
Только synthetic поля, аккаунты и память запущенных процессов не читались.
Сетевых запросов не было.

## Что исполняется и что заменено

Выполняются настоящие инструкции caller slice, включая проверки длины,
условия/ветвления, обращения к map rows, подготовку аргументов и FString copy.
RBP/RSP и исходные регистры заданы по прологу функции: RBP=RSP+0x100,
R12=RSI=0, owner — fixture. Globals строк заполнены по проверенным bindings.
Service acquisition и query-to-map parser до entry slice обходятся явно.

Hash и map lookup — shims: lookup по известному descriptor возвращает fixture
index или -1. Allocation/memcpy — ограниченные shims. Integer parser — явная
пара (ok, parsed_value), channel mapper — явный byte return fixture.
Поэтому число 20 в fixtures не доказывает email enum, а строка "0"/"200" не
доказывает полный accepted numeric syntax. Вызовы settings и присваивание
country сохраняются captures. Тела setters, сохранение на диск и callbacks
не исполняются; stop находится перед 0x14453cdf0.

## Подтверждённые caller gates

| Условие fixture | Наблюдаемый исход |
|---|---|
| resultCode отсутствует | отдельная error branch до parser |
| resultCode присутствует, пуст | отдельная error branch до parser |
| parser ok=false или parsed_value != 0 | invalid result branch 0x1450ef57e |
| owner+0x150 имеет bits вне маски 0x5 | gate 0x1450ef571 до чтения accessToken |
| accessToken пуст | invalid result branch |
| refreshToken пуст, но ключ присутствует | принятие аргументов достигается |
| channelKey пуст | invalid result branch |
| mapper вернул 0 | invalid result branch |
| netmarbleId пуст | invalid result branch |
| joinedCountryCode пуст | invalid result branch |

Auth type fixtures 0/1/4/5 прошли gate, 2/6/255 остановились. Имена enum этих
значений здесь не определены. Весь диапазон uint32 не объявляется исполненным.

**Отсутствующее поле не эквивалентно пустому.** При map return=-1 для accessToken,
refreshToken, channelKey, netmarbleId или joinedCountryCode исполнение доходит
до чтения address 0x18 через нулевой row/descriptor. Replay сохраняет instruction,
size и unmapped_null_access; не отображает это как корректный отказ SDK.
Это наблюдение в данном fixture map contract, не проверенный crash живой игры:
реальный query parser, invariant полной map и верхние обработчики ещё неизвестны.
Наш будущий decoder должен проверять наличие полей до передачи дальше.
FString copy выполнен настоящими инструкциями, поэтому отсутствующий refreshToken
не был ошибочно заменён пустой строкой в shim. Web result действительно всегда
добавляет refreshToken, включая пустую строку при remember policy.

## Раздельные аргументы settings

| Call site → target | Подтверждение и аргумент |
|---|---|
| 0x1450ef3e6 → 0x14454a480 | diagnostic SetAccessTokenForNetmarbleId; accessToken |
| 0x1450ef406 → 0x141424870 | FString assignment receiver settings+0xb0; joinedCountryCode |
| 0x1450ef416 → 0x14454ba20 | diagnostic SetNetmarbleId; netmarbleId, R8b=1 |
| 0x1450ef423 → 0x14454a870 | diagnostic SetChannelTypeForNetmarbleId; mapper byte |
| 0x1450ef42f → 0x14454c470 | diagnostic SetSilentlySignInTokenForNetmarbleId; refreshToken |

Country assignment name выведено из захваченного source value и receiver;
не названо отдельным существующим C++ setter. Access/refresh не меняются местами.
Дополнительные web easyLoginToken/issueType в этой caller цепочке не читаются.

## Проверки и остаток

Четыре теста проверяют воспроизведение из pinned bytes, раздельные captures,
missing/empty outcomes, integer/channel/auth mode caller gates. Replay покрывает
валидацию и подготовку вызовов при заданных dependencies, не настоящий вход.
Далее: реальный numeric parser, channel mapper/enum, query parser/encoding,
settings adoption/persistence и вызов после 0x1450ef437 → callback → SDK/game session.
Общий runtime decoder пока не добавляется, пока эти зависимости не подтверждены.

Для следующей проверки PE import table уже уточнила вызовы parser 0x1415dea40:
0x1415dea6c → _wtoi, 0x1415dea7f → _finite, 0x1415deab2/0x1415deaea → iswspace.
Использован existing import_at из build-object-zero-init-code.py; compiled
parser и системный CRT пока не исполнялись. Исследовательская запись вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/nid-integer-parser-investigation.json`.
