# Первый SDK-игрок: отдельный SignUp и фактический отказ по стране

20 октября 2026. Netmarble ID создан, но SDK SignIn не нашёл канал игрока.
В отдельной диагностической попытке сервер вернул HTTP 400, errorCode 1203
и сообщение `not exist player channel`. Это наблюдение конкретного endpoint
и аккаунта, а не восстановленный полный каталог ошибок SDK.

## Источник и Ghidra

Источник — скомпилированный Windows клиент, не исходный C++ проект.
SHA256 EXE:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

`build-sdk-sign-up-index.py` использует уже проверенные PE / RIP helpers
из индекса авторизации. Найдены два diagnostic string и их LEA на границах
инструкций; оба селектора присутствуют. Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-up-index.json`, SHA256
`b7f40d41d1d21994d5a3a1f2cc0b44f717a7c75b9fa7da712787b34d26d6c4f7`.

| Функция | Адрес | Подтверждение |
| --- | --- | --- |
| FAuthImpl::SignUp | `0x1444ff5e0` | Исходный diagnostic и LEA, Ghidra |
| FAuthImpl::ExecSignUp | `0x1444e06a0` | Исходный diagnostic и LEA, Ghidra |
| Callback SignUp | `0x1444ce940` | Pointer invoke `0x1444d8620` — один прямой JMP на этот адрес; Ghidra |

Invoke не имеет собственного unwind range. Его не добавляли как выдуманную
обычную функцию: проверен bounded leaf JMP, экспортирован целевой root.
Callback получает response и вызывает ExecSignUp; полный dispatcher / delegates
в этом этапе не исполнялись.

Последний экспорт: 281 функция, 112 предупреждений,
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-149c912455b7`.
SHA256 manifest:
`41f0c2d36c83dbe37eb9e6ff23ecbed57785ce9cd9b1429c9b33b02508a9b14e`.
SHA256 functions.json:
`daf21987bbf8e31c6ccba7a87193f510ea24b1b438f703c31aaa3e6746095ac6`.
SHA256 SDK_SignUp.c:
`e3e73bc2cbb9b4d12625aec91de893f8da7b439d77b15a5b27310b53dc1f1793`.
SHA256 SDK_SignUpResponse.c:
`a19133b2fb536529b061c61cf6675f9784218a8c7a84906f8a7dba2fb44a678a`.

## Тело запроса и ограниченное исполнение

`replay-sdk-sign-up-body.py` переиспользует reviewed Replay из SignIn,
не заменяет готовые JSON / PE helpers. Четыре сценария исполняют участки:

- `0x1444ff84b..0x1444ff963`: четыре обязательных поля и сборка начальной map.
- `0x1444ffa86..0x1444ffb19`: отсутствие / наличие credential и GetObject.

Конечные адреса исключены. Исполняются существующие compiled key initializers;
settings / device getters, GetObject, JSON values / map, allocation / copy / free
остаются явными fixtures или captures. Профили UA / PC и KR / pc нужны только
для проверки переноса строк; fixture KR не является разрешением реальной страны.

Результат: обязательные `nmDeviceKey`, `deviceKey`, `countryCode`, `os`,
credential при переданном объекте. Поля playerId в запросе SignUp нет.
LEA и literal bytes подтверждают lookup `authUrl`, суффикс `v1/sign-up`
и тот же POST wrapper `0x14451c3f0`, что у SignIn. Endpoint lookup / append,
полная сериализация, HTTP и response в этих native-сценариях не исполняются.

Отчёт:
`F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-up-body-replay.json`, SHA256
`70a655ae248ca7969010678fa9be04e30b81802cfd3955328117a2a1107a5273`.
В нём сохранены фрагменты, инструкции, fixtures и ограничения.

## Ответ отличается от SignIn

Ghidra callback SignUp проверяет response / JSON / errorCode и HTTP 200–206,
проходит `resultData → playerInfo → player`, записывает player ID и другие
поля через те же ключи auth implementation, что разобраны для SignIn.
Отдельного извлечения SDK accessToken в этом callback не установлено.
Это статическая связь, не полностью исполненный response scenario.

Общий `parse_sdk_sign_up_response` требует canonical zero errorCode,
свежий непустой `resultData.playerInfo.player.playerId`, строгий UTF-8 / JSON
без дубликатов и лимит 65 536 байт. Это более строгая локальная политика.
Возвращается redacted `SdkSignUpData` с player_id, без access_token.
Успешная регистрация не объявляется входом или игровой сессией.

## Явный режим runtime и реальные результаты

`plan_nid_sdk_sign_up` строит проверенное тело без playerId и старых token headers.
`execute_sdk_sign_up` использует общий ограниченный HTTPS transport, но допускает
только отдельный ожидаемый `/v1/sign-up`. Обычный executor SignIn этот путь
отклоняет до сети; SignUp также не допускает путь SignIn. Redirect и повторы
не добавлены.

В `run-nid-sdk-sign-in.py` флаг `--create-sdk-player` явно выбирает SignUp
вместо SignIn. Ошибка входа никогда не включает создание автоматически.
После SignUp runner не выполняет SignIn или игровые действия сам.
Пароль задаётся через `--password-stdin`; пример с настоящим секретом
в документации не сохраняется.

Выполнены две реальные попытки SignUp после нового NID callback. Обе дали
HTTP 400 / errorCode 1602. Во второй ограниченная диагностика получила текст
`not allowed country for game`. Секретные значения запроса вырезались до
вывода сообщения; полное тело ответа и токены не сохранялись.
Создание SDK-игрока не подтверждено. Последующего SignIn не было.

Текущий runner выбирает SDK countryCode из provider joinedCountryCode —
ранее документированный явный профиль собственного клиента. Native getter
`0x144522160` читает service settings+0x3f0; источник записи этого поля
здесь ещё не установлен. Последний сохранённый GMC2 geoIp.isoCountry равен UA.
Совпадение с текущим runtime cache не доказано. Нельзя заменять страну на KR,
объявлять все страны запрещёнными или объяснять отказ одним IP без источника.

Далее — источник settings countryCode, фактический доступ установленной
версии игры из сети пользователя, затем SDK-регистрация и полноценный SignIn.

Пользователь уточнил: установленная версия напрямую на этом ПК не работает,
игра доступна в Японии и Гонконге; Global ожидается. Это уточнение пользователя,
не независимо проверенный список разрешённых стран. В личном каталоге Phone Exit
проверен HTTP 200 и найден доступный незанятый выход HK, также есть выходы JP.
Подключение и фактическая страна трафика через него ещё не проверены.
Не считать обнаружение телефона уже включённым VPN. Код Android выбирает
валидированную Wi-Fi/LTE с NOT_VPN; сторонний VPN на телефоне сам по себе
не является подтверждением страны его выходных сокетов.

## Воспроизведение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-sdk-sign-up-index.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-sign-up-body.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_sign_up.py
```

Четыре теста SignUp проверяют воспроизведение native body, соответствие plan,
отделение transport endpoints, один POST и строгий ответ без токена.
Отдельно прошли четыре runner, шесть HTTP и три проверки Ghidra.
