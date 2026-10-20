# RequestGMC2: аргументы GET и условия заголовков

Продолжение: [serviceCode source и public success response](HEADLESS-PUBLIC-GMC2.md).
serviceCode=netmarbles подтверждён ctor manager+190/caller R8/Request stack+60;
public probe без identity/account данных принят, real constants декодированы.

19 октября 2026. Исполнен native участок `1444f5560..1444f57b1`: URL,
шесть постоянных headers, optional eTag/session fields и метод GET захвачены
через synthetic HTTP object/vtable. 16 fixtures проверяют четыре BuildCode
значения и оба состояния eTag/accessToken. HTTP transport не исполнялся.

## Источник и воспроизведение

[build-headless-gmc2-headers.py](../../../build-headless-gmc2-headers.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-gmc2-headers.py`.
EXE SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Источники и зависимости те же, что в [GMC2 URL replay](HEADLESS-GMC2-URL.md).
Нет процесса игры, account files, реальных playerId/accessToken/device key
или сетевых запросов. Все значения fixture явно искусственные.

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-gmc2-headers.json`,
SHA256 `f0a6cd4d9528b5dfd40aa6b058d3e503f0757c2b70bffa8f3f9f1b6d87aaa152`.
Содержит source bytes/file offsets/fragment SHA, constructor/Request/getter
fragments, входы и полные captures. Имя поля не заменяет proof его источника.

## Поля запроса

Имена headers создаются native constructor prefix `1444bd970..1444bda2e`;
FString constructors — shims. Prefix до этих границ целиком исполнен.
Request virtual slot+68 получает URL, +b0 — пары header-name/value,
+60 — FString GET. HTTP object и эти virtual methods — capture fixtures,
реальная wire serialization, casing/default headers и отправка не проверены.

| Header | Native источник | Условие |
|---|---|---|
| Content-Type | literal application/json, call `1444f559b` | Всегда в slice |
| Accept | literal application/json, call `1444f55d8` | Всегда |
| serviceCode | переданный FString pointer stack+60, call `1444f55f9` | Всегда |
| gameCode | SDK settings+38, call `1444f563a` | Всегда |
| buildCode | settings+48 → native build getter 14452b820, call `1444f5684` | Всегда |
| nmDeviceKey | helper 1444e5ff0, diagnostic FDeviceInfo::GetNMDeviceKey, call `1444f56b7` | Всегда |
| eTag | переданный FString R12, call `1444f56e1` | FString count+8 >1 на `1444f56c7` |
| playerId | helper 144524d80, diagnostic UNMServiceSettings::GetPlayerId, call `1444f5754` | AccessToken FString count>1 |
| accessToken | account object+78, call `1444f5775` | Count account+80 >1 на `1444f5708` |

ServiceCode — явный вход; не подменён GameCode или guessed constant.
BuildCode labels подтверждены [отдельным native getter](../auth/HEADLESS-SDK-BOOTSTRAP-VALUES.md).
Пустые eTag/token fixtures представлены allocated empty FString с count 1;
их ветки пропускаются. PlayerId без accessToken не добавляется.
При непустом token helper может вернуть пустой playerId: slice сам не требует
его непустоты. Содержимое device/player helpers здесь return fixtures,
не восстановленный алгоритм создания device identity или SDK login.

## Исполнение и переносимый план

Native constructor prefix, header/method preparation branches и полный BuildCode
getter/его initializers исполнены. FString/heap/copy/free/singletons/device/
player getters и HTTP vtable methods — явные bounded shims/captures.
Остановка до request/callback/response lifecycle; создание HTTP object, auth
lookup, token expiry и реальная сессия не выполнялись.

Общий `vampir-shared/vampir_core/gmc2_request.py` предоставляет frozen
Gmc2RequestPlan и plan_gmc2_get_request. Все обязательные inputs явные,
optional strings по умолчанию пусты, порядок headers совпал с captures.
URL/headers скрыты из repr, исключения не включают значения. Нет глобальных
credentials, чтения профиля, генерации устройства или передачи по сети.
Empty explicit required values сохраняются, readiness из этого не выводится.

Локальная политика строже native slice: HTTPS URL с hostname, без userinfo/
fragment/пробелов и invalid ports; printable ASCII fields максимум 4096 chars,
header name/value sum максимум 32768 bytes. Это локальные budgets, не серверные
лимиты и не полная проверка доверия endpoint. Body/default wire headers вне
этого плана. Headers — immutable tuple, без наследования другого аккаунта.

Четыре теста проверяют source/offsets, повторяют 16 captures и общий plan,
проверяют отсутствие секретов в repr/errors, input policy/immutability,
и воспроизводимость report. `active_values_verified=false`, `network_ready=false`.
Далее response/schema/encConstants/encSecretConstants/DECKEY → auth endpoints;
source serviceCode, active settings и device identity также требуют завершения.
