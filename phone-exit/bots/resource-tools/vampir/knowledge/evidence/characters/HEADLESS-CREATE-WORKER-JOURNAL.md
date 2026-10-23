# Worker создания и постоянный журнал попытки

23 октября 2026. Codecs относятся к EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [сессионного lifecycle](HEADLESS-CREATE-SESSION-FLOW.md).

## Доступный путь

В панели добавлена отдельная кнопка «Создать Carnage, если персонажей нет».
Она запускает worker operation `create` с сохранёнными настройками аккаунта.
Сохранённый класс должен быть Gunner / Carnage, сервер выбран, назначенного
персонажа быть не должно. Другие классы не подменяются автоматически.
Обычные «Запустить» / чтение списка не включают Create.

Worker проходит обычный выбранный вход Netmarble → SDK → лобби → игровой Login
и список. Передача `creation_factory` в exchange позволяет подготовить payload
**после принятого пустого списка того же соединения**. При существующем персонаже
или отказе Login factory не вызывается. Повторная регистрация не запускается.

Factory сохраняет принятый пустой список, получает сохранённый / случайный ник
по существующей политике, строит явный Carnage/F candidate и атомарно записывает
`pending` в SQLite **до возвращения payload в очередь**. Ошибка записи запрещает
отправку. Никакие пароли, токены или bodies в журнал не записываются.

## Журнал и восстановление

Таблица `creation_attempts` добавляется без замены прежней БД, credentials,
настроек или списков. Каждая попытка имеет UUID, account / region / server,
nickname, source SHA, состояние и время. Code сохраняется после ответа,
серверные key / name — только при подтверждённом `created`.

`BEGIN IMMEDIATE` сериализует конкурирующие попытки: две попытки одного аккаунта
и сервера не могут одновременно получить новый pending. Настройки перечитываются
в транзакции, включая enabled / target / class / nickname / assignment.
Предыдущая попытка блокирует новый Create до отдельной сверки списка.

После исключения worker переводит pending в unknown. Завершающая очистка не
перезаписывает уже полученный terminal outcome. При принудительном завершении
worker panel watcher также переводит оставшийся pending в unknown. Даже при
аварийном завершении всей панели сохранённый pending блокирует новую попытку.
Ни один pending / unknown не приводит к автоматическому повтору Create.

Только отдельная операция «Войти и прочитать персонажей» может сверить журнал.
Новый принятый список должен иметь observation time позже последнего состояния
попытки. Непустой список даёт `existing_verified`, пустой — `empty_verified`.
Это не запускает Create: для нового решения требуется следующий явный `create`.
Изменение часов назад может запретить сверку как недостаточно свежую; оно не
разрешает повтор без проверки. Код занятого ника всё ещё неизвестен, ник по
произвольному отказу не меняется.

После created key/name видны в журнале и имя может показываться в таблице.
Индекс слота не угадывается. На следующем принятом списке точное уникальное
совпадение сохранённого server key назначает его индекс / key только если
текущий target прежний и пользователь ещё не назначил персонажа.
Ошибочный response record не используется как identity созданного персонажа.

## Проверки и границы

Четыре теста journal / worker проверяют:

- сохранение pending после повторного открытия БД и запрет нового Create;
- отказ для старого списка, отдельную fresh empty сверку и новую явную попытку;
- created key/name, неизменность успеха после cleanup и назначение по свежему key;
- два конкурирующих begin: ровно один pending и один отказ;
- порядок worker callback: БД уже содержит pending до возврата payload;
- success / rejection / исключение после подготовки и existing character без factory.

Все auth / CDN / игровые вызовы worker в этих тестах — mocks, БД временная,
fixture vault не читает реальные пароли. Семь local socket flow тестов проверяют
factory только на accepted empty list; 40 exchange, 20 account-console и один
account-table тест также прошли. Python compilation и `node --check` прошли.
UI в живом браузере и реальный сервер игры в этом этапе не проверялись.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_journal.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_creation_flow.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_account_console.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_account_table.py
node --check phone-exit/bots/vampir-headless/console/console.js
```

Check `release-creation-journal` связан с исходниками и текущим SHA.
[Журнал](../../../../../vampir-shared/vampir_core/creation_journal.py),
[worker](../../../../../vampir-headless/account-worker.py),
[панель](../../../../../vampir-headless/account-manager.py).
Следом — перезапустить панель с сохранением её БД после проверки активных worker,
затем одна разрешённая живая попытка на пустом EU-аккаунте, новое чтение списка
и вход по подтверждённому ключу. Не запускать сразу все 24 создания.
