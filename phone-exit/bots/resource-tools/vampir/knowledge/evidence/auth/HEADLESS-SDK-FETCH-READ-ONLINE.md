# Silvercrow: отсутствует запись канала игрового SDK

6 ноября 2026 года, клиент SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Проверка выполнена командами без ручного входа пользователя, через назначенный
общий шаблон устройства и прямое соединение. Пароли прочитаны из локального DPAPI.

## Что вернул сервер

После первоначального отказа верификации выполнена одна попытка существующей
SDK-диагностики с ограниченной записью HTTP под Windows DPAPI:

- NID прошёл; `launcher/token` вернул `errorCode=0`, `errorMessage=success`.
- `launcher/sign-in` вернул HTTP 400, `errorCode=1203`,
  `errorMessage=not exist player channel` и
  `errorCause=This player's channel data is not exist`.

Затем выполнен ровно один отдельный `v1/fetch-player` с новым NID credential.
Он вернул HTTP 400 / 1203 с теми же сообщениями. Fetch не дал ни player summary,
ни access token, ни готового игрового соединения. Входы остальных семи аккаунтов,
SDK SignUp, Terms и создание персонажей не запускались.

Это установленный серверный отказ из-за отсутствия записи канала игрока в SDK
для выбранного аккаунта / gameCode / credential. Он не является полученным
запросом регистрации устройства или проверки почты. Корневая причина отсутствия
привязки ещё не доказана: нельзя по этому тексту автоматически создать профиль,
подменить gameCode / identity или утверждать, что аккаунт Netmarble отсутствует.
NID и launcher token были приняты.

Приватные каталоги `.local/verification-captures/bfc2b8878c97442db1be02ad90f018cc/`
и `70e210d2bef544bcba3ad8be31de9ea5/` содержат зашифрованные application payloads
и отчёты с безопасным inventory. Это HTTP адаптера, не запись официальной игры
или TLS records. Токены, ключи, body с credentials и идентификаторы не опубликованы.

## Отдельный Fetch-only пакет

[Текущий source contract](HEADLESS-SDK-FETCH-CURRENT-CONTRACT.md) проверяет целые
request / response, окна аргументов, точные строки и callback; initializer
подтверждён как 39-байтовый fragment. Общие SDK / Launcher доказательства
переиспользованы в их прежних границах. Native JSON / provider callbacks целиком
не исполнялись, локальный ответ ограничен строгим `SdkFetchSummary`.

`build-sdk-fetch-profile.py` собирает неизменяемый профиль только для
`v1/fetch-player`. Он включает прежние 98 SDK inputs и точные Fetch / runtime /
browser helpers. Загрузчик проверяет каждый вход и установленный EXE. Отдельный
ContextVar владеет одним обменом; ошибка транспорта также расходует попытку.
Ни SDK Launcher guard, ни world admission не расширены. Повторный Fetch в том же
scope, устаревший контекст, чужой маршрут / SHA и вложенный scope отклоняются.

`run-account-sdk-fetch.py` читает сохранённый аккаунт, открывает один NID,
делает один Fetch и закрывает соединение. `--capture-sdk-http` явно включает
ограниченный приватный захват. Пароль не передаётся в argv; открытых токенов в
stdout нет. Реальная попытка использовала первоначальный профиль `e354dc7e…`.
После усиления pinning browser helpers назначен новый профиль через
`sdk-fetch-runtime-current.json`; живой запрос ради этой технической правки
не повторялся.

## Обновление и дальнейший шаг

Новые `sdk-fetch-current-contract` и `sdk-fetch-read-runtime` имеют `on_update`.
Capability `sdk-profile-read` отделён от мира. Их guard заново проверяет сохранённые
inputs даже при попадании в кэш и прикрепляет их к квитанции; selector читается
из JSON. Tooling проверяет одноразовость, истечение контекста, неизменность
Launcher guard и потерю прикреплённых proofs. Новый SHA без source contract
остаётся блокером, а не получает старое разрешение.

Следующий функциональный пакет — штатный первый SDK-профиль: текущие Fetch gate,
Terms / явное принятие при наличии условий, SignUp и SignIn. Прежняя цепочка
[подтверждена для старого SHA](HEADLESS-FIRST-SDK-LIVE-AND-NID-HINTS.md), но не
допущена для этого EXE. После её переноса нужно повторить Silvercrow, обработать
фактические проверки и продолжить сервер / персонажа / Viper / мир. Текущий
Fetch-only пакет не предоставляет эти операции.

[Машинные квитанции проверок и живой результат](SDK-FETCH-CURRENT-VALIDATION.json).
