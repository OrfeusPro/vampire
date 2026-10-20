# Начальный контекст игрового Login для Windows

20 октября 2026. Продолжение [полей настроек](HEADLESS-LOGIN-POLICY-INPUTS.md).
Источник — код установленного клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Связи и native-проверка

`Network_PeersConstruct` 0x1467a79e0 уже присутствовал в экспорте. В ветви
создания игрового wrapper он вызывает base constructor 0x144aaa530, затем
по 0x1467a7ae7 / 0x1467a7aee обнуляет 16 байт FString descriptor +0x100.
Значение переносится в Login string +0x88 существующей подготовкой пакета.
Начальная строка пустая. Это не доказывает отсутствие её последующих записей
во всех ветвях повторного входа.

У объекта настроек из constructor 0x145556120 vtable равен 0x1498a9618.
**Его slot +8 указывает на 0x14556a750.** Эта функция пишет byte object+0x18 = 7.
Связь с объектом установлена через actual constructor / vtable slot,
а не по соседству адресов. При вызове этого метода перед подготовкой Login
поле +0x124 равно 7. Сам constructor, как показано ранее, этот байт не задаёт.
Порядок вызова метода во всех вариантах запуска настоящей игры не установлен;
собственный клиент выбирает этот начальный контекст явно.

Уточнение 21 октября: в [успешной официальной записи](HEADLESS-LIVE-TCP-CAPTURE.md)
поле +0x124 равно 1, а metadata +0xd8 непустая. Описанный здесь reset-контекст
не воспроизводит состояние этого входа; значение 7 нельзя считать универсальным.

[replay-login-initial-context.py](../../../replay-login-initial-context.py) исполняет:

1. Участок 0x1467a7ab4 → 0x1467a7b27 с настоящим base constructor wrapper.
   Объект заранее заполнен 0 / 127 / 255; исходный caller задаёт R15 = 0.
2. Constructor объекта настроек, затем его метод через фактический vtable slot.
3. Подготовку Login с существующими actual getters / constructor пакета.

Три сценария сохранили пустую начальную строку, byte 7 и две отдельные строки
лобби. Копирование последних моделируется ранее доказанными FString hooks;
свежий сетевой ответ этим replay не загружается. Системный base helper,
строковые primitives, SDK state и request handoff остаются ограниченными
fixtures. Не исполнены полная TLS / allocation ветвь конструктора peers,
полный запуск игры, socket и серверный Login.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/login-initial-context-replay.json`.
SHA256: `f61c5ef1caf004650f5676775b755c188c030b5eb90268f82c2b9c54a78f9f1d`.

## Сборщик runtime

`vampir_core.login_context.prepare_initial_windows_game_login` принимает
подготовленный Windows Version, наблюдённую привязку устройства, свежие SDK
данные, отдельный Netmarble ID и успешный LobbyLoginResult. Caller отвечает
за принадлежность этих данных одной попытке / аккаунту и источник endpoint.

Нужно явно выбрать `context='windows-sdk-initial-reset'`, передать выбранный
server ID и **extra_number** для uint32 Login+0x50. Этот дополнительный номер
не подменяется ID сервера. На момент этого replay источник строки ещё не был
установлен. Позднее подтверждена цепочка от `ClientVersion` в manifestlist:
[источник ревизии и runtime parser](../updates/HEADLESS-PATCH-CLIENT-VERSION.md).
Значение по-прежнему передаётся явно; числового default в runner нет.

Ветка сохраняет начальную пустую строку wrapper, metadata без NID UserInfo
и отсутствие manager+0x68. Режим 0 соответствует проверенному constructor;
SDK-поля Netmarble ID / accessToken связываются существующим binder. Byte
настроек равен 7 после явного выбора описанного контекста. Остальные нулевые
поля происходят из constructor пакета; AppVersion, compiled tag и raw DWORDs
согласованы с подготовленным Windows Version. Две строки из лобби остаются
раздельными. Required device confirmation запрещает подготовку новой попытки.

Сборщик не отправляет пакеты, не выбирает сервер и не создаёт идентификаторы.
Он не заявляет воспроизведение всех SDK backend / игровых состояний.

## Поиск, экспорт и проверки

[build-login-context-candidates.py](../../../build-login-context-candidates.py) использует
готовые PE / direct-call helpers: 89 проверенных calls; конструктор peers
найден как caller base constructor. Дополнительный поиск byte +0x18 в явном
адресном окне дал кандидатов, после чего они проверялись в Ghidra. Адресное
окно не объявлено границей класса; три недекодированных roots сохранены.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/login-context-candidates.json`.
SHA256: `5497282a3d50b6ef04b0a77d3a5fd248da92311eb10aa0bf379c1a12c7b2f54d`.
Кандидаты UseA / UseB сами по себе не доказывают принадлежность объекту настроек.

Ghidra 12.1.4: 352 функции / 159 предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-ea2fd0b5f55d`.
Manifest SHA256: `6194ea51472396987c1a1d5babf20c7bda6ee20c1905686f70875d2cb4885c47`.
functions.json SHA256: `3c5806ad2ea150ccf9717720cf572e5acc2e50b0920f7a3fbdd47c85737d70d8`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-login-context-candidates.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-initial-context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_initial_game_login.py
```

Прошли две новые проверки, шесть прежних login context, четыре policy inputs
и три проверки Ghidra — всего 15. Новых сетевых попыток нет. Следующий шаг —
сохранить SDK / lobby context только в памяти и выполнить Version → Login
на одном игровом соединении, затем запросить список персонажей.
