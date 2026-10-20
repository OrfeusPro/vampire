# Реальный launcher-вход: SDK принят, Game Login возвращает BlockedIp

20 октября 2026. Продолжение [маршрутизации SDK](HEADLESS-LAUNCHER-CHANNEL-ROUTING.md).
Реализована цепочка NID credential 33 → launcher/token → launcher/sign-in →
список серверов → выбранное лобби → Game Version / Login. Через два разных
JP-телефона и HK получен Game Login 58 / BlockedIp. Персонажи не запрашивались.

## Изменения runtime

[sdk_launcher_auth.py](../../../../../vampir-shared/vampir_core/sdk_launcher_auth.py)
содержит два плана запроса и отдельный parser строкового resultData.
Проверка устройства / default headers вынесена в общий helper
[sdk_sign_in.py](../../../../../vampir-shared/vampir_core/sdk_sign_in.py);
прежний NID plan сохраняет прежнюю схему тела и заголовков.
В [sdk_sign_in_http.py](../../../../../vampir-shared/vampir_core/sdk_sign_in_http.py)
новые endpoint используют существующий bounded HTTPS transport: проверка
сертификата, запрет redirect, лимиты ответа и отсутствие retry.

Runners `run-nid-sdk-sign-in.py`, `probe-lobby-sdk-login.py`,
`probe-selected-game-login.py` принимают `--auth-flow launcher`.
Default остаётся `nid`; fallback между способами входа отсутствует.
Сочетание launcher flow с созданием SDK player запрещено до открытия NID.

Запрос launcher/token сохраняет NID channelCode 33 / channelAccessToken;
внутрь credential добавляются gameCode / buildCode. Ответ требует явного
errorCode 0 / "0" и непустой строки resultData. Object resultData, bool / float
вместо кода, duplicate keys, NaN, неверный UTF-8 и строки вне ASCII-профиля
отклоняются. Лимиты: ответ до 65 536 байт, токен до 8192 символов.
Это строгая локальная политика; подпись / expiry / claims не проверяются.

В launcher/sign-in передаются четыре поля устройства и отдельный заголовок
launcherToken. NID-токен не подставляется в этот заголовок. Ответ разбирается
существующим SDK parser: нужны свежие accessToken и player ID. Только последний
SDK-результат передаётся в лобби и Game Login. Токены / bodies / headers скрыты
из repr. Оба запроса сохраняют один device profile и явно выбранный SOCKS route.

## Реальные проверки

Аккаунт bot-hk-test@vampir.top, прежний наблюдённый Windows device profile.
Пароль передавался через stdin, без аргумента процесса или файла с паролем.
Phone Exit SOCKS на 127.0.0.1:17948 использовал личные сохранённые телефоны и
прямой WebRTC. ОС / firewall / маршруты не менялись.

Первый JP-телефон не установил прямую связь; после приведения helper к рабочему
EXE транспорта и IPv4 STUN отказ повторился, авторизации через него не было.
Два других JP-телефона и HK подключились. HTTPS trace для каждого подтвердил
loc=JP / HK; IP не сохранялся. Телефоны различались, уникальность внешних IP
не измерялась. Третий JP проверен по отдельной просьбе пользователя.

| Выход | SDK / лобби | Game Version / Login | Сохранение результата |
| --- | --- | --- | --- |
| JP, первый подключившийся телефон | Launcher token и sign-in приняты; лобби 0 | 0 / 58 BlockedIp | Наблюдённый вывод runner; отдельного summary файла нет |
| HK | То же | 0 / 58 BlockedIp | Summary SHA ниже |
| Другой JP | То же | 0 / 58 BlockedIp | Summary SHA ниже |

Во всех трёх игровых попытках: ID 256 / группа 253 / регион JP,
контекст windows-sdk-initial-reset, ClientVersion 258392 из установленного
windows.manifestlist, SDK joined country HK.
Лобби: 55 групп / 98 серверов; Version / ServerList / Login codes = 0;
545 байт отправлено, 11 466 получено. Лобби оставалось открытым при Game Login.
Игра: Version code 0, Login code 58, тело 131 байт; 641 байт отправлено,
94 получено, счётчики полные, иных packet IDs нет. CharacterList не отправлен,
game_session_ready=false. Exit 0 означает завершённый probe, а не игровую сессию.

## Snapshots и итоги без секретов

Все пути ниже относительно `F:/PhoneExit Resources/Vampir/`.

| Попытка | CDN manifest SHA256 | GMC2 manifest SHA256 |
| --- | --- | --- |
| JP, первый подключившийся | `be25eca9bc63003c27fffc4372c6d9b74256ad63b066b9acb7beb98827ad12f5` | `42569d39d322947ff6d5fb8c84b27264a5d1b4b6752bb6872d05561746602ecb` |
| HK | `5a147570574dbc80c6f35e955c53182ebb57d990711e871cfd657330b029b9b4` | `2062ae78d81d066f67ebe137e6ca1e211c14c6f80e7e6d704a8103dc950b9780` |
| Другой JP | `c63140a7fccf5dd76e4c7353720cb16389f6a0566d472eb7b608e7ba6b4b5fdb` | `f398e5fe2e1688bb2dad20f2a82753b51ce3fca8b5a1103e1fdb1071675e8e8f` |

Пути: `public-cdn-snapshots/<SHA>/manifest.json` и
`public-gmc2-snapshots/<SHA>/manifest.json`. CDN body 6000 байт во всех случаях;
GMC2 HTTP 200, body соответственно 13 773 / 13 776 / 13 772 байта.

HK summary: `code-clues/live-launcher-login-hk-summary.json`,
2026-10-20 20:33:29 UTC, SHA256
`469cc68b09fa868939885b4e5ee51a0cd5a7adedfd5bcc85b715cec3aaef2fa8b`.
Другой JP summary: `code-clues/live-launcher-login-jp-summary.json`,
2026-10-20 20:35:46 UTC, SHA256
`d7a246bc10249c3db01e05072707a3efb12c14947f99ffb0799f860fe70e6471b`.
Summary содержит только коды / счётчики / состояние / SHA public snapshots,
без credentials и тел ответов. Raw output этих двух попыток не сохранялся.
После тестов сокеты и SOCKS закрыты, helper завершился с кодом 0;
проверено отсутствие listener на 17948.

## Выводы и следующий шаг

Реальные launcher/token и launcher/sign-in приняты — новое подтверждение
серверного контракта. Game Login по-прежнему отклонён.
[Код 58 связан с BlockedIp](../network/HEADLESS-RESULT-ERROR-58.md);
страна в HTTPS trace не доказывает принятие игровым сервером.
Причина ограничения, проверенный сервером адрес и условия допуска не установлены.
Смену кода нельзя приписывать только launcher flow: относительно прежнего
Login 16 изменились также телефон / выход и свежая сессия.
Штатный auth route официального запуска тоже не измерен.

Не повторять эти же попытки без нового условия. Полезный сравнительный тест —
официальный клиент на том же явно выбранном выходе с проверкой достигнутого
экрана, затем сравнение оставшегося контекста. До этого нельзя объявлять ни IP,
ни устройство, ни metadata доказанной причиной всех прежних отказов.

## Проверки

Схемы запросов сверены с готовыми native body / header captures.
Проверены раздельность трёх токенов, endpoint / parser, отказ без fallback,
секреты в repr / ошибках и передача режима до игрового probe.
Смежные проверки прежних NID SignIn / SignUp и лобби также проходят.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_launcher_auth.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_sign_in_http.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_sign_up.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_sign_in.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_sdk_runner.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_selected_game_login.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_probe.py
```

Для live probe к существующей source-bound команде добавляется
`--auth-flow launcher`; нужны свежие snapshots того же SOCKS route.
Пароль — только stdin. Команда не создаёт персонажа.
