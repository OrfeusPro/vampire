# Контракт Fetch и отдельная операция чтения SDK-профиля

23 октября 2026. SHA256 EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [Fetch первого входа](HEADLESS-RELEASE-FIRST-GAME-FETCH.md).
Контракт запросов разобран статически; native writer этих HTTP body не исполнялся.

## Endpoint и тело

`1444e8890` содержит diagnostic `FAuthImpl::Fetch`, `authUrl` lookup и суффикс
UTF-16 `v1/fetch-player` в `149531300`. После credential virtual `+8` собирается
JSON с двумя парами: `credential` и `scope`. Значение `scope` — строка `channel`
из literal `1495312f0`. Имя ключа `scope` установлено текущим initializer
`1411b0710`: global `14b564d90`, literal `14952d320`.
Сборка / сериализация объекта передаётся wrapper `144523b00`, как в прежнем
контракте SDK POST. Поля устройства в это body не добавляются.

```json
{"credential":{"channelCode":33,"channelAccessToken":"<fresh NID credential>"},"scope":"channel"}
```

`1444e9b00` содержит отдельный diagnostic `FAuthImpl::FetchByLauncher`, суффикс
`launcher/fetch-player` в `1495330e0` и custom header `launcherToken` из
credential `+58`. Его HTTP wrapper — **другой**, `144522040`; метод и полный
контракт этого wrapper пока не проверены. Этот путь в runtime не реализован
и не подменяется обычным POST Fetch.

Callback pointers `1444dfbe0` / `1444dfbf0` — E9 в `1444ca990` / `1444cb400`.
Оба корня выгружены целиком. В обычном Fetch прослежены errorCode conversion,
HTTP 200–206, optional `resultData` и вложенное чтение по owner keys.
Серверный ненулевой код передаётся в result constructor `144517fd0`, затем
dispatcher `1444e5900`. Полная семантика error object / dispatcher и всех
owner keys не объявляется исполненной native-проверкой.
Ответ Fetch не используется как `SdkSignInData`: он не даёт боту права считать
готовыми SDK access token, player ID, лобби или игровую сессию.

## Runtime

[sdk_fetch.py](../../../../../vampir-shared/vampir_core/sdk_fetch.py) строит отдельный
план `v1/fetch-player`. Общие заголовки gameCode / buildCode и строгая проверка
HTTPS берутся из существующего SDK auth context. Устройство / страна должны
быть переданы явно для проверки контекста runner; в body Fetch они не попадают.
Сохранённый SDK token не подставляется, provider token скрыт из repr плана.

`execute_sdk_fetch` использует существующий ограниченный HTTP transport:
проверка TLS и точного ожидаемого endpoint, один POST, без redirect / retries.
Парсер требует canonical zero errorCode и объект resultData. Это более узкая
локальная политика, чем optional native resultData. Вложенные identity / idpInfo
отбрасываются; возвращается только `SdkFetchSummary`, не SDK-сессия.

В [runner](../../../../../vampir-headless/run-nid-sdk-sign-in.py) добавлен явный
`--fetch-player`. Он допускается только с NID flow и несовместим с
`--create-sdk-player`. После Fetch runner останавливается. SignIn, окно terms,
SDK SignUp и создание игрового персонажа не запускаются. Панель и её обычные
кнопки продолжают прежний вход; массовая операция Fetch не добавлена.

```powershell
python -X utf8 phone-exit/bots/vampir-headless/run-nid-sdk-sign-in.py --email '<почта>' --profile recovered-release --fetch-player --password-stdin
```

Пароль передаётся вызывающим процессом через stdin; в команду и Git не включается.
Без `--password-stdin` остаётся ручное окно NID. CLI выводит только безопасные
признаки результата либо HTTP / SDK code; server text / токены не печатает.

Четыре новых теста проверили точное разделение body / headers, отсутствие identity
в summary, отказ неоднозначного JSON, единственный POST на HTTP 400 / 1203,
остановку до SignIn / SignUp и несовместимые режимы. Дополнительно прошли
6 HTTP, 7 launcher и 7 NID runner regression tests. Проверки используют mocks,
не выполняют авторизацию. Check `release-sdk-fetch` включён в общий workflow.

## Живое наблюдение

Перед проверкой не было процессов игры и account worker. Пароли прочитаны
в памяти через DPAPI из прежней приватной БД в read-only соединении.
Источник — recovered-release; прямое соединение, без Phone Exit / VPN.

- `nightraven@vampir.top`: NID прошёл до `sdk_fetch_player`; единственный
  `v1/fetch-player` вернул HTTP 400 / SDK 1203. Попытка закончилась.
- `bot-test@vampir.top`: контроль остановился с `NidBrowserStatusError`
  **до Fetch**. Это не успешный контроль SDK-профиля основного аккаунта.

В этом эксперименте подтверждён код 1203 на конкретном Fetch endpoint нового
аккаунта. Сообщение ошибки и полные response body не сохранялись. Причина
1203 и точная construction native error ещё не проверены; предыдущий synthetic
gate не превращается автоматически в доказанную причину этого live ответа.
Реальные terms, SDK-профили и персонажи не изменялись. Повторов после отказа нет.

## Продолжение условий

`14561ace0` вызывает `GetTermsOfService`, затем wrapper `1445ac900` →
implementation `1445ac980` с явно переданными аргументами и callback.
Adapter `145608200` (`0fb612e9f8ccffff`) ведёт в `145604f00`.
Последний журналирует step 7; при raw state 2 вызывает сохранённый owner
delegate `+a8` / count `+b0`, при state 3 — delegate `+b8` / count `+c0`.
Это статически установленная передача управления, не весь lifecycle согласия.

Предыдущий basic-terms callback создаёт эти delegates с vtables `14990d430`
и `14990d498`; source bytes slot `+60` указывают на `14560b130` и `14560aff0`.
Их смысл ещё не присвоен. Продолжить с этих targets и `1445ac980`, подтвердить
enum состояния и путь перед SDK SignUp. Не включать SignUp по одному `1203`.

## Воспроизводимость

Ghidra-пути относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-1b2b935daa62/details.json`, Fetch запросы / terms continuation | `fc36502fde60719b09bcbaef04f5fdb21ae45e078f6f50a906c76815896d957b` |
| `details/run-3380a52fff6d/details.json`, scope initializer / ответы / продолжение | `7b0307a30a6cc0b33c1149c956e12a0c822fa8f54a6b4299fbd07c429ad518aa` |

Полные exports, callbacks и указатели используются повторно. Native тела
Fetch / HTTP / Terms здесь не исполнялись; тесты runtime не выдаются за native replay.
Источник, ограничения и следующая проверка закреплены через prepare / finish.
