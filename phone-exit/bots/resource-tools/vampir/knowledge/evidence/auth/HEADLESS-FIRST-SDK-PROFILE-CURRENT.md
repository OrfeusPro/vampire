# Первый SDK-профиль Silvercrow: текущий контракт и живой вход

6 ноября 2026. Полный SHA256 клиента:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Продолжение [Fetch / отсутствующей записи канала](HEADLESS-SDK-FETCH-READ-ONLINE.md)
и [готовых 126 native continuation случаев](HEADLESS-FIRST-SDK-CONTINUATION-CURRENT.md).

## Результат сервера

Командой выполнена подготовка `silvercrow@vampir.top` через назначенный общий
шаблон устройства и прямой маршрут. Пароли прочитаны из локального DPAPI;
токены и реальные SDK ID в публичный отчёт не записаны.

Первый запуск остановился на NID `login_failed` до любого SDK-запроса. Отдельная
NID-диагностика затем приняла те же данные; SDK она не вызывала. Причина первого
отказа не установлена. После изменившегося ответа NID одна новая полная попытка
прошла последовательность:

```text
NID → Fetch 1203 → BasicTerms NO DATA → IndividualTerms NO DATA
→ SDK SignUp → SDK SignIn
```

SignUp вернул player ID; SignIn вернул тот же ID и непустой access token.
Известный `playerStatus` не запросил дополнительных форм: `verification_status`
равен `verified`, список выполненных проверок пуст. Регистрация устройства и
снятие защиты в этой попытке не выполнялись. В панели сохранён `sdk_created` и
подтверждение текущего fingerprint.

Это создание **профиля игрового SDK**, а не игрового персонажа. CharacterList,
Create, выбор персонажа и вход в мир не отправлялись. Остальные семь аккаунтов
не запускались. Прежний отказ SignIn 1203 на Silvercrow преодолён штатной
подготовкой первого SDK-профиля.

Живая попытка использовала профиль
`3d5065cdde24a49389a5c53a9644386e53ff271027680ca56b98a0f9f99df5b8`.
Её приватный журнал — `.local/first-sdk-attempts/c58f21f941154740822420eae2021a27/report.json`;
SDK application payloads сохранены ограниченно под Windows DPAPI, не как TLS records.
После улучшения диагностики отказа NID и закрепления всех загружаемых browser
helpers назначен новый профиль через `sdk-first-profile-current.json`.
Ради этих локальных правок авторизация повторно не выполнялась.

## Source contracts

Общий экспорт 30 roots использован повторно. Дополнительно получен только
direct SignIn response `0x1444d2ba0`: `run-3653ffde95d7/details.json`, SHA256
`9f35728d87b7d1f51dfb14fdf119493ca3f1f70485d5706f26034977caa813de`.
Других JVM / повторных экспортов этого пакета не требовалось.

- `inspect-first-sdk-auth-current.py` проверяет целые SignUp / SignIn requests
  и responses, окна аргументов, callback E9, общий POST и текущие ключи Launcher.
  Семь owner keys проверены в полном линейном leaf длиной 403 bytes;
  `accessToken` — в явном 39-byte initializer fragment. Это статический контракт
  строгого локального plan/parser subset, без исполнения HTTP/JSON engine.
- `inspect-first-sdk-terms-current.py` добавляет 56 native NO DATA/error случаев
  с настоящими result constructor, dispatcher и queued thunk. Ещё два
  последовательных NO DATA ответа в одном эмуляторе исполняют настоящий Basic
  callback, создание delegates и Individual continuation до captured
  Netmarble channel 33 / step 13. Готовая отдельная матрица 126 не повторяется.
- HTTP body / JSON primitives, strings, allocation, service и scheduling имеют
  явные fixtures. Content-bearing Terms/UI, согласие, destruction/lifetime races
  и полный SDK engine не объявляются исполненными. State 2 означает NO DATA,
  а не пользовательское согласие. Доступные условия останавливают автомат.

## Runtime и обновление

`build-sdk-first-profile.py` собирает отдельный неизменяемый пакет с 159 inputs:
Fetch и базовый SDK, три source contracts, потребители и девять browser helpers.
Loader проверяет каждый вход, установленный EXE и собственный код. Старые
Launcher / Fetch / world guards не расширены. Один scope владеет одной
последовательностью, включая неизвестный исход SignUp; вложенный запуск запрещён.
Перед каждым сетевым этапом повторно проверяются SHA клиента, возраст GMC2,
аккаунт / selector / маршрут; caller проверяет fingerprint устройства.

Команда использует kernel lease аккаунта и атомарный журнал фиксированных этапов.
При известных device/workplace states она передаёт тот же SDK-контекст готовому
`continue_verification`, без второй авторизации. Терминальные формы сохраняют
серверный срок десять минут; после них команда не продолжает в лобби.
Неизвестный статус / ошибка / изменение назначения останавливают операцию.

Checks `first-sdk-auth-current`, `first-sdk-terms-current` и
`sdk-first-profile-runtime` связаны с contract `sdk-first-profile`, `on_update`
и штатным dispatch/cache guard. Auth, Terms и runtime имеют отдельные JSON
selectors: изменение CLI не меняет ключ кэша неизменного Terms proof.
Даже при cache hit guard проверяет все retained inputs и добавляет их в receipt.
Native Terms tooling читает готовый source-bound report после проверки SHA;
неизменная матрица не запускается ради упаковки повторно.

Контексты этого bounded пакета привязаны к текущему SHA. Новая версия требует
своего переноса / source contracts / пакета; неизвестный layout даёт блокер.
Общий игровой admission этим пакетом не назначается. Следующий этап — текущий
server/character/world candidate и Viper CDO / Create, затем первый полный вход
Silvercrow перед остальными семью.

[Проверки, source pointers и безопасные признаки живого результата](FIRST-SDK-PROFILE-VALIDATION.json).
