# SDK sign-in: JSON, заголовки и локальный план запроса

19 октября 2026. Продолжение [NID credential33](HEADLESS-NID-CREDENTIAL.md).
Четыре native caller fixtures подтвердили JSON preparation; восемь fixtures
общего CreatePost подтвердили default headers, build selector и POST method.
Общий plan_nid_sdk_sign_in добавлен и привязан offline к authUrl из реального
public GMC2 snapshot. HTTP POST и SDK/game session не выполнялись.

## Источники и воспроизведение

[replay-sdk-sign-in-body.py](../../../replay-sdk-sign-in-body.py) проверяет EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это скомпилированный Windows клиент, не исходный C++ проект.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-body-replay.json`, SHA256
`8d4bb20917faeb90bdc25d2176388d99587f4c1d3ad2c4e3a22c5d391e5ec2d7`.
Сохранены caller/factory/getter/transport fragments, key/build initializers,
auth constructor leaf, literal bytes/file offsets/SHA, fixtures/body/header captures.

Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-sign-in-body.py`.
Unicorn 2.1.4/Capstone 5.0.6, budget 8192 instructions на slice/function.
Native execution: sign-in body slices 0x1444fba4d..0x1444fbb65 и
0x1444fbc88..0x1444fbdad; auth constructor leaf 0x1444bc380; compiled key/build
initializers; CreatePost slices 0x14451cccb..0x14451ce4c и 0x14451d0ca..0x14451d0f0;
BuildCode getter 0x14452b820. Выходы getter/device/settings, JSON values/map,
credential GetObject, allocation/copy/free/atexit и HTTP vtable — explicit fixtures/captures.
Full JSON writer, CreatePost connection/callback/response и игра не исполняются.

## JSON caller

FAuthImpl::SignIn root 0x1444fb800 получает body fields:

| Поле | Caller source |
|---|---|
| nmDeviceKey | FDeviceInfo::GetNMDeviceKey 0x1444e5ff0 |
| deviceKey | UNMServiceSettings::GetDeviceKey(bool) 0x144522820, flag true |
| countryCode | UNMServiceSettings::GetCountryCode 0x144522160 |
| os | FDeviceInfo::GetPlatform 0x1444e66b0 |
| playerId | первый FString аргумент SignIn, только если непуст |
| credential | virtual GetObject аргумента credential, если объект передан |

Первые четыре поля добавляются всегда. Их globals связаны с пятью точными
compiled key initializers (включая credential). Возвраты getters — явные
fixtures, реальные device identity/геолокация/профиль не приобретаются.
Email planner требует credential33 из предыдущего этапа; anonymous/null
credential branch наблюдается в replay, но не реализуется этим planner.

Optional key подтверждён цепочкой:

1. FServiceImpl constructor 0x144510fd0: LEA owner+0x150 на 0x14451111f →
   wrapper ctor 0x1444bc1d0 на 0x144511126.
2. Wrapper ctor вызывает leaf 0x1444bc380 на 0x1444bc21b.
3. Leaf пишет pointer UTF16 literal playerId в impl+0x30 на 0x1444bc3b5.
4. FServiceImpl::GetAuth 0x1445209e0 возвращает wrapper owner+0x150;
   SignIn wrapper 0x1444fb730 читает impl pointer и вызывает 0x1444fb800.
5. SignIn читает impl+0x30 на 0x1444fbc9e и использует его для непустого аргумента.

Constructor leaf исполнен. Factory/getter/wrapper chain сохранена статически,
не объявлена полностью исполненным startup. Отсутствие unwind у leaf учтено:
сохранён bounded decode до ret без calls/jumps, не отброшен как «нет функции».

## Endpoint и transport

SignIn использует SDK key authUrl и suffix v1/sign-in. Caller передаёт JSON
string wrapper 0x14451c3f0 на 0x1444fc171; тот создаёт пустую custom header map
и вызывает CreatePost 0x14451c600 на 0x14451c4d4. Эти связи статические.
Append semantics повторно используются из уже проверенного append_sdk_path;
endpoint не выбирается по похожему домену и не получается из game AppVersion.

| Header | Value / условие |
|---|---|
| Content-Type | application/json |
| Accept | application/json |
| gameCode | явное settings GameCode |
| buildCode | native BuildCode byte 1→B/2→C/elseA |
| accessToken | module account field+0x78, если FString непуст |
| authToken | тот же field+0x78 при том же gate |

Проверены build bytes 0/1/2/255 × empty/nonempty account field. Method captured
POST. Account return source — fixture, реальный SDK account/session не читался.
Нельзя автоматически подставлять provider access token в эти два headers.
Это отдельный token context; provider token расположен в nested credential.

## Переносимый request plan

`vampir_core.sdk_sign_in.plan_nid_sdk_sign_in` требует явные constants,
NidSdkCredential33, game_code, raw build_code byte, nm_device_key, device_key,
country_code и os_type. Optional player_id добавляется в body только непустым;
existing_sdk_token добавляет оба header и не наследуется из provider credential.
Нет identity acquisition, HTTP, storage, callback или SDK success state.

Local policy: printable ASCII ≤8192 chars/value, body/header totals ≤32768,
nonempty identity/game/platform/provider token, two-uppercase-letter country.
HTTPS authUrl без userinfo/query/fragment/backslash/invalid port. Это явно
строже native prefix check/непроверенных server limits. URL/path binding
переиспользует SDK helpers; JSON object семантически совпадает с captures,
побайтовая идентичность Unreal JSON writer не заявляется.
Frozen plan скрывает URL/body/headers в repr.

Offline binding использует неизменяемый public GMC2 snapshot
`b18141355f468fda8e654da37927f9323bf59ee5018f1fd00b1326eed6aae1f1`, с manifest/body
SHA verification и существующим decoder. Это constructor-default probe profile,
не подтверждённые active BuildCode/region/device values. Никакого auth HTTP нет.

Четыре теста проверяют native reproduction/factory key chain, common JSON
против captures, восемь header fixtures, real public config binding и local
policy/redaction. Далее callback response 0x1444d85f0: network/SDK result schema,
SDK access token/playerId/expiry, error handling и handoff к game Login.
Active auth attempt/provider selection и защищённое storage ещё не завершены.
