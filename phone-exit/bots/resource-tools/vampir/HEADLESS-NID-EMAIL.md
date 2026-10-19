# Почта/пароль: отдельные SDK-ветки и публичный NID web contract

19 октября 2026. Найдены отдельная legacy FEmailAuth и подготовка webview
Netmarble ID. По authWebViewUrl из [реального GMC2](HEADLESS-PUBLIC-GMC2.md)
получены публичные HTML/JS. Подтверждены JSON POST `/api/signin/netmarble`,
шифрование email/password и предварительное получение reCAPTCHA score token.
Общий offline plan реализован; login POST не выполнялся, ответа авторизации нет.

## Источники SDK: не смешивать провайдеров

[build-headless-email-auth.py](build-headless-email-auth.py) сохраняет 18 diagnostics
семейства FEmailAuth/Content/Credential и дополнительный NID CheckPossibleToOpen:
всего 19 symbols/20 verified LEA/18 roots, missing/rejected=0. EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Report `F:/PhoneExit Resources/Vampir/code-clues/headless-email-auth.json`, SHA256
`f5560ff80ea07281f8ee525a9cf79b46df58ee594e69979032431d52d0e48d44`.
Source code compiled/cooked, не настоящий исходный C++ проект.

| Ветка | Источник и граница |
|---|---|
| FEmailAuth constructor 1450cc260 | Поля access_token/refresh_token/user_key и client ID regex |
| FEmailAuthContent CheckPossibleToOpen 1450dcf30 | emailAuthViewUrl, emailauth/login?, /emailauth/manage?, serviceCode netmarble, clientId/countryCode и другие query names |
| FEmailAuth SignInSilently 1450f5850 | emailAuthTokenUrl, oauth/email/access_token?, grant_type/token; не переносится как NID authorization_code |
| FEmailAuthCredential GetObject 1450e5000 | channelAccessToken; полная семантика credential ещё не исполнена |
| FNetmarbleIDContent CheckPossibleToOpen 1450de4f0 | authWebViewUrl, clientId/gameCode/buildCode/device keys, authType signin/linkidp/withdraw/agreements |

Имена/поля сохранены source-bound, native branches здесь не исполнялись.
FEmailAuth использует client ID regex с underscore-группами; имена Netmarble ID
и EmailAuth endpoints не объявляются взаимозаменяемыми. Active provider selection
игры и полный runtime context ещё не доказаны. В извлечённых Game INI не найдено
прямого WindowsEmailClientId; это не доказывает отсутствие поздней настройки.
SDKType=Global и известный NetmarbleClientId сами по себе не выбирают эту ветку.

## Публичные HTML/JS и воспроизведение

[capture-netmarble-auth-web.py](capture-netmarble-auth-web.py) проверяет SDK
snapshot/body SHA, offline декодирует authWebViewUrl и разрешает только
`https://members.netmarble.com/auth` и один объявленный HTML module script
того же host `/assets/*.js`. Никаких придуманных путей API не запрашивается.
Обычный TLS/cert/hostname verify, без redirects/proxy/cookies, timeout 10 с,
read budget 30 с между read1, HTML ≤2 МиБ / JS ≤4 МиБ, identity encoding/length checks.
Текущая read операция может добавить до 10 с. Browser/полное JS приложение
не запускаются. Для явного нового capture:
`python -X utf8 phone-exit/bots/resource-tools/vampir/capture-netmarble-auth-web.py --fetch`.

В этом этапе: один первичный HTML GET, затем producer выполнил HTML+script GET,
итого 3 public GET, без login parameters/account cookies/POST. Immutable snapshot:
`F:/PhoneExit Resources/Vampir/auth-web-snapshots/63254de0c08cdcf7415500b1a975d39062166272d6ce674ea25fb58ef27bb01c/manifest.json`.
SHA256 manifest равен имени каталога; captured UTC `2026-10-19T11:15:00.173673+00:00`.

| Файл | Размер | SHA256 |
|---|---:|---|
| auth.html | 6184 | `b88068b44e2badfb6aeba3c0becc2df1b17a12e174bdf230a8be1a10f8fde1c1` |
| auth.js | 2068423 | `e9bee7cc5a71946c28a6e35f107c422f749d3b7b5fa8215ff291ec26b88cc868` |

Script URL взят из HTML, не угадан по имени hash. Body assets остаются вне Git.
Это bare /auth profile с default members context, не authenticated game webview.
Web assets/public RSA key могут обновляться отдельно от game EXE; сохранять
новый snapshot и перепроверять source anchors при их изменении.

## Проверенный web contract

[inspect-nid-auth-web.py](inspect-nid-auth-web.py) читает только сохранённые assets.
Report `F:/PhoneExit Resources/Vampir/code-clues/nid-auth-web-evidence.json`, SHA256
`e7d7de802b4ceb057324974fd89949108f5956f2f70cf08566d7f8d421117f1e`.
Byte offsets/SHA для каждого anchor/выбранного helper сохраняются; Unicode
character offsets не выдаются за byte offsets.

| Источник JS | Подтверждение |
|---|---|
| doSignInByEmail | email:z7(email), password:z7(password), deviceKey, expectedAction, reCaptchaScoreToken |
| z7 | U7.encrypt(value), Base64 RSA ciphertext |
| public page state → U7.setPublicKey | RSA_PUBLIC_KEY из HTML, текущий RSA modulus 1024 bit |
| expectedAction | members_signin |
| caller | getReCaptchaToken(members_signin) до doSignInByEmail |
| j8.post | относительный /signin/netmarble |
| request interceptor | relative path получает /api prefix → /api/signin/netmarble |
| interceptor headers | accessToken/clientId/gameCode/buildCode/playerId/nmDeviceKey/deviceKey/deviceIp/clientIp/osType→os/webViewType и Pragma no-cache |

Public page key SHA256
`9fac998d248506a715b5a583dd78b8737ecc48175057fc44d3c510bf3323afa6`.
Это публичный ключ web encryption, не SDK DECKEY и не nidEncryptKey.
AES/GMC2 OAEP не подставляются вместо наблюдаемого RSA PKCS1v1.5.

В Node v24.13.0 выполняются только reviewed padding helper, URL predicate и
request interceptor, извлечённые из pinned JS. RNG/BigInteger/state/loaders —
явные искусственные fixtures; полного приложения, DOM, сети, reCAPTCHA и
шифрования RSA JS library нет. Девять padding fixtures и три interceptor
fixtures воспроизводимы. Источник padding использует charCodeAt: BMP кодируется
1/2/3 bytes, surrogate pair — шестью bytes CESU-8, а не стандартными четырьмя UTF8.
Нулевой delimiter отделяет nonzero PKCS1 padding от encoded message.

Guard страницы сравнивает character count, поэтому multibyte-overflow fixture
может дать слишком короткий padding. Общий backend проверяет encoded-byte
предел k-11 до RSA. Это локальное исправление границы, не эмуляция ошибки JS.

## Общий offline request plan

`vampir_core.nid_email`: nid_js_string_bytes, encrypt_nid_field,
plan_nid_email_sign_in. Public RSA key/context/token передаются явно, значения
не trim/lowercase, surrogate pairs повторяют charCodeAt encoding. Plain NUL/
controls/unpaired surrogates отклоняются. Optional cryptography генерирует
PKCS1v1.5 padding безопасным RNG; поддержаны явные RSA 1024/2048/3072/4096 keys.
Дополнительный synthetic RSA roundtrip проверяет decrypted encoded bytes;
случайные ciphertext не объявляются побайтно равными.

Plan: HTTPS /auth origin → /api/signin/netmarble, JSON body и explicit headers,
frozen dataclass, repr скрывает URL/body/headers. Plaintext не хранится в плане.
Требует nonempty reCAPTCHA token, получаемый отдельно браузерным контекстом,
и explicit clientId/gameCode/buildCode. Остальные context values не приобретаются
и не наследуются от другого аккаунта. No HTTP/cookies/browser profile/credentials
storage. Origin/default browser headers и полный session lifecycle не моделируются.
Локальные пределы: 4096 chars plaintext до RSA byte guard, context/token ≤8192 ASCII
chars, headers ≤32768 bytes; unknown context keys, insecure URL и control chars
отклоняются без values в ошибках. Android crypto backend ещё не проверен.

Семь tests проверяют source snapshots/anchors/index, isolated JS replay,
CESU8/size edge, RSA synthetic roundtrip, actual interceptor→plan header mapping,
input/secret-safe errors/captcha required, URL scope/immutable capture outputs.
POST login, challenge/token acquisition, login response→authorization code и
native callback→token exchange ещё не выполнены. `network_ready=false`.
