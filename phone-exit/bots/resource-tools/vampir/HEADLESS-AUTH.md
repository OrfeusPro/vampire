# Vampir — начало восстановления SDK авторизации

18 октября 2026. H04 частично: статические связи и offline token-request plans.
Общий [реестр](../../vampir/FUNCTION-INDEX.md), [задачи](../../vampir-headless/TASKS.md).
Полный вход по почте/паролю и игровая сессия **не реализованы**.

## Источник и воспроизведение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса VA, image base `0x140000000`; версия выпуска/Android parity неизвестны.
Использован только EXE: Saved/webcache, память процессов, launcher profile,
настоящие токены и аккаунты не читались. Внешних запросов не было.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-auth-index.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_auth.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-auth-index.json`,
SHA256 `42543d7c32c3fc1d4d00abde017ebe8f605a6175b5b6b05dd642bdeb7f1296e3`.
24 точных SDK diagnostic literals, 34 проверенных LEA, 24 unwind roots;
missing/rejected=0. Сохранены source/tool hashes, literals/file offsets/SHA,
полные fragments/instructions, 143 referenced constants, request helper code,
512 native executions escaping primitives. Эти уровни подтверждения различаются.

## Два разных обмена

Исходные UTitleUI roots остаются `ProcessNetmarbleSDK=0x14641ee20` и
`OnSuccessNetmarbleSDKAuth=0x14641d560`. Первый проверяет объект manager+0x38, затем вызывает wrapper
`0x145609b00`; второй также проверяет manager+0x38. Точная семантика этого
объекта/ready state и переход к packet Login ещё полностью не прослежены.

SDK diagnostic→root связи включают:

| Назначение из diagnostic | Root VA | Граница подтверждения |
|---|---|---|
| FAuthImpl::SignIn | 0x1444fb800 | authUrl и v1/sign-in, не вход по email/password напрямую |
| FAuthImpl::SignInByLauncher | 0x1444fd270 | authUrl и launcher/sign-in |
| FAuthImpl::GetTokenByLauncher | 0x1444e8130 | authUrl и launcher/token |
| FAuthImpl::RefreshToken | 0x1444f4050 | authUrl/v1/refresh-token, проверки exp/Need a Signin |
| FChannelManagerImpl::CreateLauncherCredential | 0x1444dd8a0 | candidate launcher credential route; chc key |
| FChannelManagerImpl::IsRunningOnLauncher | 0x1444eb1c0 | diagnostic: AuthType is not nmlauncher / missing parameters |
| FNetmarbleIDProvider::GetAccessTokenByAuthorizationCode | 0x1450e2640 | token form ниже |
| FNetmarbleIDProvider::GetAccessTokenByRefreshToken | 0x1450e2f50 | token form ниже |
| FNetmarbleIDProvider::GetUserDetail | 0x1450e6e30 | authAccountUrl/v2/user/details, Authorization/Bearer |
| FNetmarbleIDProvider::IdpSignIn | 0x1450e7cb0 | authAccountUrl/v2/idp, tokenId/sign-in |
| FNetmarbleIDProvider::GetIdpToken | 0x1450e44e0 | authAccountUrl/v2/idp, idToken/gameCode/buildCode/token |
| FNetmarbleIDProvider::InternalSignIn | 0x1450e9960 | authAccountUrl check; полный URL ещё не собран |
| FNetmarbleIDContent::OnSignIn | 0x1450f08a0 | query/deeplink parsing, полная схема ещё unknown |
| FNetmarbleIDContent::OnFinishSignIn | 0x1450edd20 | query validation, callbacks ещё не исполнены |

Ещё ShowWebview/standalone/launcher/credential/callback roots находятся в JSON.
Наличие diagnostic не означает, что весь одноимённый метод исполнен или что
конкретная ветка выбрана текущим аккаунтом. Auth codes, refresh tokens, IDP tokens,
SDK session и game Login не объявляются взаимозаменяемыми.

## Подтверждённая форма token request

Две функции используют config key **authTokenUrl**, относительный путь
**v2/access-token** и header **Content-Type: application/x-www-form-urlencoded**.
Базовый адрес не установлен: не подставлять домен по сходству с другими SDK URL.

| Grant | Поля формы |
|---|---|
| authorization_code | grant_type=authorization_code, client_id, device_key, code |
| refresh_token | grant_type=refresh_token, client_id, device_key, refresh_token |

Кодовый caller заполняет пары на `0x1450e2c12..0x1450e2ccc`; endpoint suffix
загружен на `0x1450e2af5`, content type на `0x1450e2d17`. Запрос передаётся
`0x14451c570` на `0x1450e2d80`; refresh caller делает это на `0x1450e36e1`.
Wrapper вызывает `0x14451c600`, связанный точным diagnostic
FNetworkManagerImpl::CreatePost и строкой POST (`0x14451d0ca`).
Общий helper передаёт запрос дальше через HTTP object; сетевое исполнение не проверено.

Form builder `0x144586a30` использует шаблон `{0}={1}` и separator `&`.
Value escaping проходит через `0x141c13850`: `%`, byte whitelist и hex helper.
Native whitelist `0x141c06750` и uppercase hex `0x1415ad670` исполнены для
каждого byte0..255 (512 вызовов). Без escaping остаются только ASCII
`-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~`.
Space становится `%20`, плюс `%2B`, слэш `%2F`; generic quote_plus здесь не
копирует наблюдаемую форму. Полный Unreal string/map/HTTP builder не replayed;
Unicode UTF16→UTF8 и supplementary characters отдельно не подтверждены.

## Переносимый offline план

`vampir-shared/vampir_core/auth_request.py` содержит `plan_authorization_code`
и `plan_refresh_token`. Результат TokenRequestPlan хранит endpoint key,
relative path, POST/content type и bytes body. Repr скрывает body, ошибки не
включают значения полей. Runtime не читает Saved, не запускает launcher/игру,
не получает пароль/токен и не отправляет HTTP.

Локальные ограничения: непустые printable ASCII values до4096 chars на поле,
body до32768 bytes. Unicode и control chars отклоняются явно до отдельной
проверки. Это budgets/границы поддержанного subset, не лимиты сервера.
HTTP field order задан по caller pairs; byte-for-byte identity всего native
map serializer не заявляется. Пять тестов проверяют provenance, LEA/call targets,
native byte primitives, раздельные grants, special chars/редактирование repr/лимиты.

## Следующие зависимости

1. Источник актуальных authTokenUrl/authAccountUrl/authUrl и clientId/game/build
   config, выбор production/region; сохранять SHA/источник, не hardcode кандидаты.
2. Реальный интерактивный вход по почте/паролю→authorization code, возврат браузера,
   challenge/ошибки; ручное подтверждение там, где требует провайдер.
3. Разбор token responses/expiry и переход Netmarble ID→SDK session→PktLobbyLogin/
   PktLogin. Нельзя отправить code/refresh token как игровой пароль по догадке.
4. Endpoint/port selection, TCP connect/session setup и live canary после полного
   offline contract. Credentials/токены получать явно, не извлекать из чужих профилей.

Эти пробелы сохраняют H04 частичным. `network_ready=false`; standalone вход,
персонаж, бой и 10–20 аккаунтов этим этапом не реализованы.
