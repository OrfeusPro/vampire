# NID email: ответ, проверка профиля и передача результата SDK

19 октября 2026. Продолжение [email contract](HEADLESS-NID-EMAIL.md).
Почтовая ветка веб-кода передаёт accessToken через `nmidprovider/result`.
Её нельзя автоматически заменять отдельным authorization_code exchange.
Реального входа в аккаунт, HTTP с токенами и игровой сессии пока нет.

## Публичный JS: источник и проверка

[inspect-nid-auth-result.py](inspect-nid-auth-result.py) читает immutable snapshot
`F:/PhoneExit Resources/Vampir/auth-web-snapshots/63254de0c08cdcf7415500b1a975d39062166272d6ce674ea25fb58ef27bb01c/manifest.json`.
Manifest SHA256 равен имени каталога; auth.js SHA256:
`e9bee7cc5a71946c28a6e35f107c422f749d3b7b5fa8215ff291ec26b88cc868`.
Новых сетевых запросов в этом этапе нет.

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/nid-auth-result-evidence.json`, SHA256
`1025f7753465111cd232794070d8be3261d766f80085fc945dc95886c719280d`.
Сохраняются восемь выбранных functions с byte offsets, bytes и SHA256.
Из них выполняются query/result/route/projection/dispatch helpers; profile
gate/fetch/processing сохранены статически. Node v24.13.0, VM timeout 100 мс,
subprocess timeout 15 с; credentials/state/profile result/timers — fixtures.
Полное приложение, DOM, сеть, реальные policy checks и SDK не выполняются.

Наблюдаемая цепочка:

1. doSignInByEmail получает body от POST /api/signin/netmarble и вызывает B.
2. Для обычного authType ветка B вызывает F, затем W только при непустом профиле.
3. F вызывает getUserInfoFromSignIn: access_token передаётся в обработку профиля.
   Cie запрашивает /user/info с header accessToken, читает resultData, нормализует
   joinedCountryCode в uppercase. Это source contract, запрос не выполнялся.
4. Обработка профиля содержит redirect/context, await H(a) и USER_NOT_ALLOWED.
   Поэтому успешный POST сам по себе не доказывает завершение входа; identity,
   terms и другие проверки требуют отдельного разбора, их нельзя пропускать.
5. W сбрасывает временное состояние и вызывает doneSignInDeepLink.
6. doneSignInDeepLink → sendDeepLink → URLSearchParams → nm{gameCode}://nmidprovider/result.
   Доставка зависит от webViewType/isInGame: location, vuplex или launcher IPC.
   В replay заменена только конечная функция доставки, устройство не открывалось.

| Из credential/profile | Поле result query |
|---|---|
| status или 0 при falsy | resultCode |
| access_token или пустая строка | accessToken |
| easy_login_token или пустая строка | easyLoginToken |
| issue_type или пустая строка | issueType |
| user_key или пустая строка | netmarbleId |
| profile.joinedCountryCode или пустая строка | joinedCountryCode |
| refresh_token с remember policy | refreshToken |
| idpType=email | channelKey=mailUserKey |

Если canKeepSignedIn truthy, refreshToken передаётся только при rememberMe;
если canKeepSignedIn falsy, берётся имеющийся refresh_token без этого условия.
Четыре комбинации проверены actual JS helpers с synthetic status=0.
Query escaping проверен на access token fixture с пробелом, плюсом и амперсандом.
Это не native success и не настоящий токен. Восемь dispatch fixtures проверяют
signin/guestLinkIDP/gameLauncherLinkIDP/activate с пустым/непустым profile fixture.
Тела linking/policy handlers заменены captures; их результат не заявляется.

`signin` с callback onSignIn — другая команда: doIDPSingnInDeepLink.
Она не используется как доказательство схемы почтового result.

## Связь с собранным Windows клиентом

[build-headless-nid-result.py](build-headless-nid-result.py) проверяет полный EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это скомпилированный код клиента, не исходный C++ проект.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-nid-result.json`, SHA256
`5ede108dd8b882c13948085973ce84e4db37b236ca3477fa5b85e86c36a9f92f`.
Сохранены полные unwind fragments двух handlers и initializer fragments;
14 descriptor globals связаны с literals через проверенные инструкции
LEA RDX source → LEA RCX destination → CALL 0x141421150.
Конструктор строк и сами native handlers в этом этапе не исполнялись.

| Строка | Global descriptor | Initializer root VA |
|---|---|---|
| nmidprovider | 0x14b5644c8 | 0x1412382a0 |
| signin | 0x14b5644e8 | 0x141238510 |
| result | 0x14b564508 | 0x1412384b0 |
| resultCode | 0x14b5645a8 | 0x1412383c0 |
| accessToken | 0x14b5645b8 | 0x1412381b0 |
| refreshToken | 0x14b5645c8 | 0x141238570 |
| netmarbleId | 0x14b5645d8 | 0x141238330 |
| joinedCountryCode | 0x14b5645e8 | 0x141238300 |

OnDeepLink root 0x1450ed4f0 сравнивает command с global result:
load 0x1450ed832 → compare call 0x1450ed83e → branch 0x1450ed84e
на 0x1450ed923 → call 0x1450ed92b → OnResult 0x1450ee6b0.
Его точный diagnostic подтверждён в том же root. Для signin отдельный call
0x1450ed949 → OnSignIn 0x1450f08a0. Полная семантика URL parser и веток
валидации пока не исполнена; найденные поля не доказывают принятие токенов.

## Проверка и следующий шаг

Четыре теста: byte/SHA/reproduction, projection/query/refresh policy,
dispatch profile gates, compiled initializer/result route provenance.
Повтор: `python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_nid_result.py -v`.
Общий runtime decoder результата пока не добавлен: сначала проверить native
query parsing, resultCode validation, token adoption и SendSignInCallback.
Затем связать результат с SDK session и game Login. Активный provider/context
игры остаётся неизвестным; созданный тестовый почтовый ящик не означает,
что аккаунт Netmarble зарегистрирован или что игра уже авторизована.
