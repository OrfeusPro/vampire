# Живой контроль создания: остановка на SDK и исправление wrapper

23 октября 2026. Проверка выполнялась напрямую, без Phone Exit / VPN.
Worker использовал `recovered-release` и проверку источника EXE
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [worker и журнала](HEADLESS-CREATE-WORKER-JOURNAL.md).

## Что реально произошло

Перед запуском не было активных account worker или процесса игры. Панель
запущена на `127.0.0.1:17949` с прежней приватной `console.sqlite3`.
HTTP отдал новую кнопку создания, API — поле `creation_attempts`; это проверка
доступности страницы / API, не визуальная проверка браузера.
Пароли использовались из хранилища, не передавались в process arguments.

Для `nightraven@vampir.top`, EU / Aria 1 / server ID 381, запущена отдельная
operation create. Вход Netmarble прошёл, получен launcher token, но последующий
SDK launcher sign-in вернул HTTP 400 / code 1203. До игрового TCP, Login,
списка персонажей и Create ID 103 эта попытка **не дошла**.

Затем выполнена контрольная operation characters для основного `bot-test`
на EU / Prelude 2. Она прошла SDK и дошла до выбранного лобби, но игровой
контекст не был получен. Панель показала остановку `selected_lobby_login`.
Числовой код этого отказа в прежнем сообщении панели отсутствовал, поэтому
причина здесь не уточняется. Результат не подтверждает работоспособность
игрового входа в этот момент, но опровергает общий отказ SDK для обоих аккаунтов.

После паузы и исправления wrapper выполнена ещё одна попытка create того же
нового аккаунта. Она снова остановилась на SDK HTTP 400 / 1203 до игры.
В конце проверены API панели: **0 активных jobs, 0 записей creation_attempts**.
Постановка Create в очередь не происходила, персонаж ботом не создан.
Другие 23 новых аккаунта не запускались.

SDK 1203 не интерпретируется как доказательство отсутствия регистрации,
неверного пароля, IP-блока, отсутствия персонажа или необходимости SignUp.
Повторная регистрация и автоматический fallback SDK SignUp не выполнялись.
Различие между аккаунтами установлено по этапу, причина остаётся неизвестной.

## Исправленная ошибка интеграции

Во время проверки пути обнаружено: внешний `run` принимал creation_factory,
но не передавал его через `_run` и `_after_lobby`. Последняя функция ссылалась
на имя без локального параметра. Поэтому при достижении игрового этапа callback
не мог корректно попасть в exchange. Ранние отказы SDK / лобби не являются
доказательством срабатывания этой ошибки в живой попытке.

Теперь callback передаётся через все три границы. Два новых теста проверяют:

- `run → _run → selected lobby callback → _after_lobby`, тот же объект factory;
- `_after_lobby → exchange_game_login`, тот же объект factory и закрытие socket.

Auth / lobby / socket dependencies этих тестов — fixtures / mocks.
Они не заменяют живую проверку Create. Четыре journal/worker теста и 20 тестов
account console также прошли. В worker добавлен вывод **только числового**
`lobby.login_result_code`, если он доступен; response bodies, токены и серверные
тексты в сообщение не копируются.

## Следующий шаг

Проверять различие NID → launcher token → SDK sign-in для нового и основного
аккаунтов по уже имеющимся источникам. Не повторять массово входы, не создавать
другие SDK-профили по одному коду 1203. Если появится новый обоснованный путь
авторизации, проверить его отдельно; Create разрешён только после принятого
пустого списка. Native payload / JSON / handler пока не требуют повторного анализа.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_wrapper.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_journal.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_account_console.py
```

Check `release-creation-wrapper` привязан к текущим исходникам и SHA.
[Wrapper](../../../../../vampir-headless/probe-selected-game-login.py),
[worker](../../../../../vampir-headless/account-worker.py).
Приватные credentials, DB и auth captures в evidence / Git не добавлялись.
