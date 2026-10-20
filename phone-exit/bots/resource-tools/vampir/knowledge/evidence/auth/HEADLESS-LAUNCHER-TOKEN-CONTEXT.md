# Launcher-токен: заголовок, ответы и отдельный номер канала

20 октября 2026. Продолжение [launcher-контекста](HEADLESS-LAUNCHER-AUTH-CONTEXT.md).
Имя заголовка теперь установлено: `launcherToken`. Также подтверждено, что
`channelCode = 200` и внутренний номер канала SDK берутся из разных полей.
Это пока не доказательство причины игрового `InvalidState` или фактического
выбора launcher-ветви официальным клиентом в прежней живой проверке.

## Источник и воспроизведение

Собранный EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Перед исследованием адреса проверены через реестр. Callback pointers
`0x1444d8510` и `0x1444d8600` — пятибайтовые JMP, а не unwind roots.
В Ghidra добавлены их actual targets и initializer ключа.

Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-a32e792f4d73`.
415 функций, 190 предупреждений. Manifest SHA256
`9a72c6c3977f0719eabe1e6f9970193a11fc3a7bdf19ed6ec5359301130ccca7`,
functions.json SHA256
`552e1d9011710a0ec0b48d95ece8d4d3488e6bfda566f4f0a8016a8f340d501d`.

[replay-launcher-token-context.py](../../../replay-launcher-token-context.py)
сохраняет `F:/PhoneExit Resources/Vampir/code-clues/launcher-token-context-replay.json`.
SHA256: `e4c0731f6ea2e16dccf94d708ab335628efd2f23de3cddd5e0957705dc09711b`.
Отчёт содержит source-bound инструкции, callsites, callback thunk bytes,
SHA инструментов и псевдокода, результаты 13 native fixtures.
Оба launcher replay закреплены за своими immutable Ghidra export:
добавление посторонних функций в следующий экспорт не меняет их доказательства.
Псевдокод сверяется с SHA в provenance.

## Токен передаётся в отдельном заголовке

Initializer `0x1411b0460` по `0x1411b0472` вызывает FString constructor
`0x141421150` с destination `0x14b4f0a70` и UTF-16 literal `0x1494d4178`.
Фактический текст — `launcherToken`. Затем выполняется регистрация cleanup;
она захватывается fixture, а не регистрируется в настоящем процессе.

Native slice `0x1444fd4c0..0x1444fd4f7` читает этот global как ключ и строку
credential+0x58 как значение, передаёт одну пару в map constructor
`0x143bf76c0`. У `SignInByLauncher` эта map передаётся отдельно от JSON body
в `0x14451c570`; назначение аргументов общего HTTP wrapper установлено
[обычным SDK sign-in](HEADLESS-SDK-SIGN-IN.md).

Три fixtures исполняют initializer и slice вместе: пустой токен, обычная
синтетическая строка и строка `a.+/=_-`. Capture сохраняет значение без изменения.
FString constructor и map constructor — явные fixtures; исполняются настоящий
выбор literal, подготовка указателей и handoff. Это не проверка HTTP transport,
допустимости пустого токена сервером или правил сетевой библиотеки.

## Ответ launcher/token отличается от ответа sign-in

| Callback pointer → actual root | Подтверждённый путь по Ghidra и инструкциям |
| --- | --- |
| `0x1444d8510` → `0x1444c5910` | Общие network / JSON / errorCode gates; диапазон HTTP 200–206; `resultData` читается строковым getter `0x1444768c0`, передаётся в result constructor `0x144510060`, затем dispatcher `0x1444dec50` |
| `0x1444d8600` → `0x1444cce90` | `resultData` читается объектом; accessToken → module+0x78; playerInfo.player → ID / country / region / status; затем SetSignIn и dispatcher `0x1444dff20` |

Иными словами, строковый `resultData` ответа launcher/token нельзя подавать
в существующий parser полного SDK sign-in, ожидающий вложенные объекты.
Точный consumer строки за `0x1444dec50` ещё не проверен. Имена методов сами
по себе не доказывают обязательную последовательность двух HTTP-вызовов.

В launcher sign-in статически прослежены уже известные setters:
player ID `0x14454bc50`, country `0x14454b8c0`, SetSignIn `0x14454c3d0`.
Структура player совпадает с ранее разобранной
[обычной SDK response](HEADLESS-SDK-SIGN-IN-RESPONSE.md).
Полные JSON gates, traversal и delegates нового callback не исполнялись;
локальный SetSignIn не считается доказательством свежего токена или server success.

## Канал ответа берётся из credential+0x68

Участок `0x1444cd8e0..0x1444cd8f4`:

1. Читает pointer credential из closure+0x20.
2. Если pointer ненулевой, читает byte credential+0x68.
3. Записывает его в module+0x88.
4. Если credential отсутствует, прежний module+0x88 сохраняется.

Десять native fixtures: credential есть / отсутствует, byte +0x68 равен
0 / 20 / 33 / 200 / 255, прежний module channel равен 7.
Credential+0x50 во всех случаях отдельно равен 200 и на результат slice не влияет.
Запись и null gate исполняются настоящими инструкциями. Closure / credential /
module заданы искусственно; разбор `chc` в реальном токене не проверялся.

Это уточняет предыдущий вывод: нельзя автоматически объявлять 200 каналом
активного SDK player. Ранее constructor связывал byte +0x68 с полем `chc`
token container; его происхождение и допустимые значения ещё нужно проследить.

## Следующий участок и ограничения

Готовый direct-call scanner нашёл четыре подтверждённых callsites:
два к GetTokenByLauncher в root `0x1444e5560` и два к SignInByLauncher в root
`0x1444fc5f0`. Фрагменты сохранены в отчёте. Это кандидаты для дальнейшего
Ghidra-разбора, а не доказанная роль маршрутизатора. Поиск не охватывает все
виртуальные вызовы и tail jumps.

Следом — эти два caller, consumer результата `0x1444dec50` и источник `chc`.
Реальный путь официального запуска nmlauncher / netmarble остаётся неизвестным;
NMAUTH_TYPE не читается из игры и не предполагается по названию лаунчера.
Нет новых HTTP-запросов, изменения runtime, чтения реальных токенов или памяти
игры. Успешный Game Login и список персонажей по-прежнему не получены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-launcher-token-context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_launcher_token_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --build
```
