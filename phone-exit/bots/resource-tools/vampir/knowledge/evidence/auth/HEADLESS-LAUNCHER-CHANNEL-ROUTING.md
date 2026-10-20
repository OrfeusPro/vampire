# ChannelManager: выбор SignIn и отдельное получение launcher-токена

20 октября 2026. Продолжение [токена и двух ответов](HEADLESS-LAUNCHER-TOKEN-CONTEXT.md).
Разобраны найденные caller roots. Это публичные для SDK операции
`FChannelManagerImpl::SignIn` и `FChannelManagerImpl::GetLauncherToken`.
Вторая может использовать уже сохранённый NID credential канала 33.
Это даёт основание подготовить отдельный запрос launcher/token с таким
credential; обязательность launcher-входа для игрового сервера не установлена.

## Источник и проверка

EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса сначала проверены через реестр. Ghidra экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-b8564958f914`.
418 функций, 190 предупреждений. Manifest SHA256
`f3105456b5f12aac8ac6011b2892612e441607a655aba71f5a5950a21cd321ae`,
functions.json SHA256
`f3a78a3b426bd0c459cc7d6aeaa8f8df680c999c171991e51a71ed20daf12139`.

[replay-launcher-channel-routing.py](../../../replay-launcher-channel-routing.py) →
`F:/PhoneExit Resources/Vampir/code-clues/launcher-channel-routing-replay.json`.
SHA256: `7f7a061d723c51e308e6e60f1eb700cd8c9bbb980a815d0fda99b131c3fe3fc6`.
Отчёт закреплён за immutable export; содержит полные source-bound fragments,
diagnostic literals, SHA псевдокода и инструментов, результаты 26 native fixtures.

Точные diagnostic strings устанавливают роли, а не только аналитические имена:

| Root | Diagnostic literal | SHA256 literal |
| --- | --- | --- |
| `0x1444fc5f0` | `FChannelManagerImpl::SignIn` в `0x1494db400` | `0f646cf01b9897c70cf0b62811b55592a266f1b052e16b28432410660e61768d` |
| `0x1444e5560` | `FChannelManagerImpl::GetLauncherToken` в `0x1494db7f0` | `1efc9d2d5e3e3f98ce5d6e1519ba1b98083f543507b20b72fa1cfa691cd66ed2` |
| `0x1444dec50` | `FAuthImpl::ExecGetTokenResult` в `0x1494d9c00` | `63f926ec3a6ceddfc5b29e5defa380066b748fdf3392bb930a435126ebe7d811` |

## SignIn выбирает backend по каналу

Входной channel — byte второго аргумента. Callback сохраняется binder
`0x1444ba4f0` по manager+0x80 на `0x1444fc6dd`. Затем требуется ненулевой
service context. Карта credential manager имеет записи по 0x20 байт;
ключ — byte записи, credential shared pair — запись+8/+0x10.
Lookup исполняется настоящими инструкциями, а не fixture функции поиска.

| Проверенные условия | Handoff / остановка |
| --- | --- |
| Нет service context | Остановка до создания error object |
| Канал 200, credential найден | `SignInByLauncher`, вызовы `0x1444fc9cc` / `0x1444fc9ff` |
| Канал 200, credential отсутствует | `CreateLauncherCredential` на `0x1444fc858`; его выполнение здесь остановлено |
| Канал 20 / 33 / 255, credential найден, прежний канал 33 | Обычный SignIn wrapper `0x1444fb730`, пустой player ID и исходный credential |
| Канал 20 / 33 / 255, credential отсутствует, прежний канал 33 | Остановка до создания error object |

Число 255 — граничный synthetic fixture, а не установленный допустимый
серверный enum. Native маршрутизация сама по себе не доказывает принятие backend.
Все captures проверяют, что handoff сохранил тот же credential pointer и auth
context. HTTP-методы и ошибки за этими границами не исполнялись.

## Особая ветвь с прежним каналом 100

При requested channel 33 код дополнительно получает прежний внутренний
SDK channel через `0x1444bb4b0` / `0x144521af0`. При значении 100 проверяет
уже известный support helper `0x144517ef0`, затем сохранённый player ID.

Восемь fixtures проверяют requested channel 33 / 100, support false / true
и пустой / непустой player ID при прежнем канале 100. Только support=true
и непустой ID доходят до обычного SignIn с этим ID и **нулевым credential**.
Остальные останавливаются до error allocation. Поэтому формула «все каналы,
кроме 200, всегда передают свой credential» неверна.

Предыдущий channel, support и сохранённый ID заданы fixtures; их фактическое
состояние официального запуска не считывалось. Это не доказательство, что
конкретный аккаунт использовал гостевую ветвь или что она объясняет Login 16.

## GetLauncherToken — отдельная операция с существующим credential

`0x1444e5560` сохраняет callback по manager+0xe0, проверяет service и ищет
credential **переданного канала**. Не создаёт отсутствующий launcher credential.
При успешном lookup получает Auth и передаёт найденную shared pair в
`FAuthImpl::GetTokenByLauncher`, `0x1444e8130`, через callsites
`0x1444e591f` / `0x1444e595b`.

Девять fixtures: raw channels 20 / 33 / 200 / 255 × наличие credential,
затем отдельное отсутствие service. При наличии service и credential все
четыре канала доходят до GetTokenByLauncher с тем же объектом. Остальные
останавливаются перед error allocation. Полный HTTP body ранее разобран:
GetObject credential дополняется gameCode / buildCode внутри JSON credential;
внешний объект содержит четыре поля устройства.

Для NID credential 33 его GetObject уже проверен в
[прежнем replay](HEADLESS-NID-CREDENTIAL.md). Следовательно, код поддерживает
путь NID credential → отдельный запрос launcher/token. Он не требует
подменять NID channelCode на 200. Реальный ответ этого нового запроса пока
не получен; строка `resultData` не считается доказанной SDK-сессией.

## Результат возвращается через сохранённый callback

`FAuthImpl::ExecGetTokenResult`, `0x1444dec50`, статически:

- копирует callback из auth+0x188 и очищает прежнюю привязку / count +0x190;
- переносит исходную result shared pair в closure;
- передаёт задачу в уже известный scheduler `0x141404350`, selector 1,
  thunk `0x1444d80f0`.

Это та же схема отложенной доставки, что у разобранного
[обычного SDK result dispatcher](HEADLESS-SDK-RESULT-DISPATCH.md), но другой slot.
Новый dispatcher здесь не исполнялся. Адрес прикладного bound consumer остаётся
неизвестным; callbacks в native caller fixtures намеренно пустые.
Автоматическая последовательность GetLauncherToken → SignInByLauncher
этими функциями не доказана. Расширять replay scheduler без нового вопроса
о данных авторизации не требуется.

## Границы и следующий шаг

Исполняются entry, channel gates, native map lookup и handoff до backend.
Service acquisition, SDK channel / support / player getters, GetAuth, callback
binding/copy — явные fixtures. Карта содержит один объект без control block.
Не исполняются полный SDK lifecycle, ветви с непустыми callbacks, backend HTTP,
создание credential, error objects и cleanup после handoff.

Далее — подготовить явные планы launcher/token для NID credential 33 и
launcher/sign-in с отдельным launcherToken, строгий parser строкового resultData
и проверку передачи контекста. Затем отдельный сетевой эксперимент через JP.
Не выдавать этот эксперимент за доказанный штатный порядок официального запуска;
не включать автоматический fallback и не повторять старый игровой Login без
изменившегося контекста. Runtime пока не менялся, реальная сессия и персонажи
по-прежнему не получены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-launcher-channel-routing.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_launcher_channel_routing.py
python -X utf8 phone-exit/bots/resource-tools/vampir/function-registry.py --build
```
