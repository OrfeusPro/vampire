# Runtime: Version → Login через владельца сокета

20 октября 2026. `LoginFlow` связывает проверенные Version / Login codecs
с общей очередью; `GameConnection.start_login()` подключает этот поток
к владельцу сокета. Поля обоих исходящих пакетов передаются явно.
SDK sign-in, получение токенов, реальных device keys и адреса сервера
этим кодом ещё не выполняются.

## Поведение

`start_login(version, login, now=..., timeout=..., max_payload_size=...)`
проверяет полный Login payload до первой отправки и ставит Version / ID1
в очередь. Повторный start и запуск после начала выбора персонажа запрещены.
При отказе очереди новый bootstrap не устанавливается, sequence не меняется.
Далее:

```text
version_pending → ID2, code 0 → Login / ID3 → login_pending
login_pending   → ID4, code 0 → login_response
```

ID2 разбирается целиком: `<IIBII`, 17 байт, bool нормализуется. Поля после
result code сохраняют имена по native offsets, их назначение не угадывается.
Требование точных 17 байт — локальная политика: native reader допускает
остаток после тела. ID4 разбирается существующим полным LoginResult decoder.

`login_response` означает только получение тела с code 0. Native handler
имеет дополнительные ветви, в том числе ранний выход по signed-полю и
peer flag; здесь они не объявляются пройденными. Нет автоматического
перехода в список персонажей, готовый мир или подтверждённую сессию.
`enter_character_list()` после start_login требует login_response,
но также требует явного вызова от внешнего подтверждённого lifecycle.
Code 0 сам по себе не является таким событием.

Если start_login не используется, прежний явный API списка остаётся
доступен для владельца уже подготовленного контекста и локальных тестов.
Это не автоматический обход авторизации и не готовый runner аккаунта.
ID2 / ID4 без зарегистрированного LoginFlow поступают внешнему on_packet.

## Ключ, время и ошибки

Обе отправки используют текущий sequence и ключ общей очереди. ID11
между Version и Login обрабатывается владельцем до ID2: ack упаковывается
старым ключом, Login — новым. Сам flow не создаёт ключей.

На каждый ожидаемый ответ назначается отдельный timeout с момента постановки
запроса в очередь. Часы монотонные и передаются владельцем. При timeout,
неподдержанном ненулевом коде, повреждённом теле или отказе постановки Login
соединение закрывается без автоматического повтора. Список и очереди очищаются.
Ненулевые коды сохраняются числом без выдуманных названий ошибок или challenge.
Нужны отдельные штатные обработчики подтверждения устройства и других исходов.

Подготовленный Login хранится до принятия VersionResult, затем ссылка
удаляется. При ошибке / закрытии удаляются payload и разобранный ответ.
Это управление временем жизни ссылок, а не гарантированное стирание памяти
Python. Поля авторизации не выводятся в repr и сообщения ошибок flow.

## Источники и проверка

Source SHA256 собранного клиента:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

- [ID2 reader, gate и переход в Login](../resource-tools/vampir/HEADLESS-VERSION-RESULT-HANDLER.md).
- [Version writer / кадр](../resource-tools/vampir/HEADLESS-VERSION-SEND-PATH.md).
- [Login writer / кадр](../resource-tools/vampir/HEADLESS-LOGIN-SEND-PATH.md).
- [LoginResult reader](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).
- [Условия native LoginResult handler](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-HANDLER.md).

`phone-exit/bots/fixtures/vampir-login-flow.json` содержит 14 Version и
29 Login кадров из существующих native replay-отчётов, а также минимальное
полное тело LoginResult. SHA исходных отчётов сохранены рядом. Данные
синтетические; fixture не содержит учётных данных аккаунта. Тесты runtime
не требуют EXE, Ghidra, Capstone или Unicorn.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_flow.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_connection.py
python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_send*.py'
```

Пройден 31 тест: семь новых, девять владельца соединения и 15 отправки.
Сверены все 43 native-кадра, точный размер / bool ID2, дубликаты, timeout,
ненулевой результат, повреждённое тело, отказ очереди и удаление данных.
Socketpair-тест проводит ID1 → смена ключа / ack → ID2 → ID3 → ID4,
затем отдельно разрешённый ID101. Сервер синтетический; настоящая сессия
и политика устройства не проверены.

Далее — заполнение Version / Login из реального SDK / device context,
установление фактического события входа в выбор персонажа и первый
контролируемый вход. Адреса, токены и идентификаторы не подставлять по догадке.
