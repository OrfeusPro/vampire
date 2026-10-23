# Первый SDK-вход подтверждён; безопасные подсказки NID

23 октября 2026. Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [отдельного первого SDK-входа](HEADLESS-RELEASE-FIRST-SDK-LOGIN.md).

## Живой результат

Подготовленный аккаунт `nightraven@vampir.top`, прямое соединение без VPN,
current source profile; явные параметры условий UA / en-US / all.
Пароль прочитан через DPAPI из локальной SQLite в read-only соединении,
не передавался в аргументах процесса и не печатался. Тела авторизации и токены
не сохранялись. До запуска не было процесса игры или account worker.

Одна попытка после добавления безопасной диагностики прошла всю цепочку:

```text
NID callback
sdk_fetch_player
sdk_basic_terms
sdk_individual_terms
sdk_first_profile
sdk_sign_in
accepted=true, player_id_present=true, sdk_token_present=true
```

Порядок подтверждён progress callbacks самого runtime. Ветка условий запускается
только после Fetch HTTP 400 / canonical errorCode 1203. Оба parser приняли
NO DATA, затем SDK SignUp вернул player ID, а SignIn — тот же player ID и токен.
Не повторялась регистрация Netmarble. Локальная запись аккаунта переведена
в `sdk_created` только после этого подтверждения.

Это первый успешный SDK-профиль нового аккаунта, а не игровой персонаж или вход
в мир. Значения player ID и токена остаются приватными; в отчёте только признаки.

## Проверка создания на Aria 1

Для сохранённого назначения EU / Aria 1 / server ID 381 / Carnage запущен
обычный account worker `create`. Первый worker остановился на NID HTTP 400.
После передачи новых diagnostic fields через worker выполнена одна отдельная
повторная попытка: NID и launcher token / SignIn прошли, затем лобби и выбор
цели. На этапе `selected_lobby_login` сервер вернул **10036**.

Игровой Login, CharacterList и ID 103 не отправлялись. В приватном
`creation_attempts` для этого аккаунта **0 записей**. Ник и назначение не менялись.
Оба worker завершились, фонового повтора нет.

Свежий каталог сохранил Aria 1 / ID 381 / group 357 / excluded false.
Последний признак означает только отсутствие известных исключённых состояний
record `+35` 2 / 3; он **не подтверждает доступность входа**.
Исторический mapper на прежнем SHA называл 10036 IsInspect / Under maintenance:
[разбор лобби](../network/HEADLESS-LOGIN-LANGUAGE.md#расшифровка-10036-isinspect--технические-работы).
Для текущего EXE этот mapper новым replay не проверялся; масштаб и причина
нынешнего отказа не установлены. Назначать другой сервер автоматически нельзя.

## Безопасная диагностика NID

[nid-http-diagnostics.cs](../../../../../vampir-headless/windows/nid-http-diagnostics.cs)
теперь возвращает дополнительно только фиксированные `Hint` / `Shape`.
Ни одно серверное строковое значение не возвращается. Из bounded JSON до 16 КиБ
рассматриваются только известные поля code / message / error и один nested error.
Email, password, accessToken и неизвестные поля не используются для классификации.

Поддержаны подсказки: invalid_credentials, account_not_found, rate_limited,
captcha_required, device_confirmation, region_restricted, session_invalid.
Это эвристические признаки текста ответа, **не доказанная причина отказа**.
Если совпало несколько разных категорий, возвращается unknown.
Неизвестные языки / схемы не угадываются. Формат ответа классифицируется отдельно,
например nonnumeric_code или message_only; raw code string наружу не попадает.

Поля проходят allowlist в Python adapter и selected-game probe. Account worker
показывает фиксированную русскую подсказку с формулировкой «ответ содержит признак».
Они не разрешают вход, повтор, смену пароля, обход капчи или принятие условий.
Старые numeric / size / UTF-8 диагностики сохранены. Поведение заполнения формы
и native setter / input events не изменялось.

Новый успешный вход не доказывает, что диагностика исправила предыдущий отказ:
она только наблюдает ответ. Причина нестабильных NID HTTP 400 остаётся открытой.

## Проверки и следующий шаг

Прошли 3 diagnostic tests (C# компилируется и исполняется в PowerShell),
9 browser adapter, 11 selected-game, 20 account console, 12 first SDK и
9 NID runner tests: **64 теста**, без живой авторизации внутри тестов.
Тестовые строки проверяют все hints, неизвестную / неоднозначную причину,
игнорирование identity-полей и отсутствие raw text в выводе.
Также прошёл `nid-browser.py --smoke`: synthetic callback captured,
external navigation / popup блокируются, response code проверен, игра не запущена.
Check `release-nid-http-hints` запускает три diagnostic tests; остальные наборы
проверены отдельно.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_diagnostics.py
python -X utf8 phone-exit/bots/vampir-headless/nid-browser.py --smoke
```

Далее проверить текущий mapper / условия выбранного лобби для 10036 и отличие
от глобального каталога. После принятого входа — свежий список, создание Carnage
только при принятом пустом списке, затем назначение по ключу и вход в мир.
Повторный SDK SignUp на этом аккаунте не нужен: профиль уже создан.
