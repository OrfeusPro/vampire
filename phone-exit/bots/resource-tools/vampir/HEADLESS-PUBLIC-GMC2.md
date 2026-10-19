# Реальный публичный GMC2 response и SDK constants

19 октября 2026. Один public HTTPS GET вернул status 200, errorCode 0 и 13788 байт.
DECKEY присутствует в HTTP response headers. Общий decoder получил 93 ordinary
и 1 secret constant, объединённая карта содержит 94 строки. Доступны authTokenUrl,
authAccountUrl, authUrl, emailAuthUrl, emailAuthTokenUrl, emailAuthViewUrl.
Ни один auth endpoint не вызывался; account login/session не выполнялись.

## Source profile и serviceCode

[build-headless-gmc2-public-profile.py](build-headless-gmc2-public-profile.py)
проверяет source EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`
и сохраняет source instructions/file offsets/bytes/SHA и literals.

| Поле | Подтверждённый источник профиля |
|---|---|
| serviceCode=netmarbles | ctor 1444bdb38/3f → manager+190; caller 1444f3f54 → R8; Request prologue 1444f534d сохраняет R8 в stack+60 |
| base=https://apis.netmarble.com/gc2 | production literal 1444bdb19; [mode2 selector](HEADLESS-SDK-CONFIG.md) |
| group=netmarbles-v5 | ctor 1444bdb5e/6f → manager+1c8 |
| version=5.2.11 | native getter 144524390 |
| build_code=0 → A | [compiled settings constructor default](HEADLESS-SDK-SETTINGS.md), actual late writes не исключены |
| market=nmp, game=thered | compiled game initializers 141258b10/141258ae0 |
| device_key | пустой явный public probe; identity не создана и не получена |
| playerId/accessToken | отсутствуют |

Production profile выбран по ранее [полученному public CDN Zone=real](HEADLESS-PUBLIC-CDN.md).
Это проверочный source-derived profile, не доказательство active installed
BuildCode или порядка Game cache. Все inputs явные, default 0 не подменён Zone 2.
ServiceCode теперь связан с constructor/caller, не угадан по имени game.

Profile report: `F:/PhoneExit Resources/Vampir/code-clues/headless-gmc2-public-profile.json`,
SHA256 `ed169b12eb7f0f0ccd0a83c93aa16f4e683212eb088bce82df27a0d712456abb`.
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-gmc2-public-profile.py`.

## Запрос и неизменяемый ответ

[fetch-public-gmc2-config.py](fetch-public-gmc2-config.py) использует общий
GMC2 URL/header plan. Разрешён один точный public URL, GET, empty nmDeviceKey;
Authorization/Cookie/accessToken/playerId отвергаются до I/O. Нет retries,
redirect follow, environment proxy, device identity или account acquisition.
TLS certificate/hostname verification обычная; timeout 10 с, между read 1
проверяется budget 30 с (текущая операция может добавить до 10 с), body ≤2 МиБ.
Content-Length/identity encoding и полнота тела проверяются. Это urllib transport,
не исполнение native HTTP object. User-Agent Research/1 и Accept-Encoding identity
явно зафиксированы как локальные overrides.

Для явного нового probe:
`python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-gmc2-config.py --fetch`.
Этот этап выполнил один GET; последующие проверки и tests — offline.

Snapshot: `F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/b18141355f468fda8e654da37927f9323bf59ee5018f1fd00b1326eed6aae1f1/manifest.json`.
SHA256 manifest равен имени каталога; рядом body.bin с SHA256
`7c5dba89d6aa76d4462b6101d0721b788c4ed17ce2960af08992299bb7d7b401`.
Время UTC `2026-10-19T10:59:17.069391+00:00`. Указатель
`F:/PhoneExit Resources/Vampir/code-clues/public-gmc2-recovery.json`.
Manifest хранит profile/tool SHA, request и выбранные response headers.
Исходный ответ включает DECKEY и geoIp metadata; сохраняется только вне Git,
ключ/metadata/значения constants не выводятся в console и не копируются в docs.
Это полученные SDK config data, не пользовательский account token/password.

## Что доказал разбор

Outer JSON: errorCode=0, resultData содержит encConstants/encSecretConstants/geoIp.
DECKEY 2396 ASCII chars — Base64 PKCS8 RSA private-key body 3072 bits. Тот же
логический UTF16 key используется для XOR encrypted string fields.
Normal field 4788 units больше раннего synthetic decoder budget; новый envelope
decoder использует [проверенный bounded raw XOR](HEADLESS-GMC2-XOR.md), без
двойного unescape, поскольку outer JSON уже снял escapes.

93 normal values оказались строками. Secret XOR даёт список из одного Base64
ciphertext 384 bytes. OAEP SHA256/MGF1 SHA256 существующего backend расшифровал
82 bytes; существующая secret-list сборка получила 1 строковое поле nidEncryptKey.
Значение не публикуется. Existing secret-overrides-normal map merge дал 94 entries.
Полная native callback/PEM parser acceptance и семантика virtual slot 28 по-прежнему
не исполнены. Наличие DECKEY именно в HTTP header наблюдалось в реальном ответе,
а не установлено по номеру native virtual slot.

Реальный PKCS8 body выявил ограничение прежнего backend: принудительный PEM
label RSA PRIVATE KEY принимает PKCS1, но не этот PKCS8 DER. sdk_secret.py теперь
читает canonical DER PKCS1 либо PKCS8 напрямую; тип RSA, размер 2048/3072/4096,
точная длина ciphertext, canonical Base64/DER и OAEP параметры проверяются.
Trailing DER и другие форматы отклоняются. Это локальная backend стратегия,
не утверждение о byte-for-byte native PEM parser. Предыдущие PKCS1 fixtures сохранены.

## Общий envelope decoder и offline воспроизведение

`vampir_core.gmc2_response.decode_gmc2_configuration(body, headers)` переиспользует
existing bounded JSON/XOR/RSA/list/map primitives. Требует один непустой DECKEY,
integer errorCode 0, resultData object и обе encrypted strings. Локальная политика
rejects duplicate/nonfinite/depth/Unicode/shape ошибок. В outer encrypted strings
NUL разрешён: реальный ciphertext содержит escaped NUL. Plaintext/CDN JSON
сохраняет прежний запрет NUL. Body≤2 МиБ, DECKEY ≤4096 ASCII chars, headers ≤256;
дальнейшие map/secret-list budgets прежние. Это local supported subset.

Возвращается отдельная frozen SdkConfiguration с read-only merged map; repr
не раскрывает constants и ключ не хранится в результате. Ошибки sanitised,
partial map не возвращается. Нет HTTP, session/auth readiness или account storage.

[decode-public-gmc2-config.py](decode-public-gmc2-config.py) повторяет всё offline:
`python -X utf8 phone-exit/bots/resource-tools/vampir/decode-public-gmc2-config.py`.
Report `F:/PhoneExit Resources/Vampir/code-clues/public-gmc2-decoded.json`, SHA256
`b4c1c50578bf734bf13900ad682a7865dea2ba288d4243549b4a40a8bfc6a09c`.
Только counts/auth field names/constant-map hash/runtime hashes, без plaintext values.
Семь новых tests: source/service binding, real snapshot/offline decode,
synthetic PKCS1/PKCS8/override, malformed envelopes, NUL policy, transport
TLS/identity/body limits, запрет credential headers и immutable snapshot.

Следом связать полученные endpoints с email/password/browser authorization
и обработкой token/expiry, затем SDK→game session. `network_ready=false`:
игровой вход, персонаж и фарм ещё не реализованы.
