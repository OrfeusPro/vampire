# Login в лобби после выбора игрового сервера

20 октября 2026. Исправлен порядок операций диагностического игрового runner.
Ранее он получал успешный LobbyLoginResult при server ID = 0, затем список
серверов и переходил к игровому подключению. Ответ лобби после передачи
выбранного server ID не запрашивался.

## Связи в коде клиента

Источник — установленный Windows EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`, экспорт
`export-c7552efd2125/run-7f47677751ba`, 372 функции / 175 предупреждений.
Manifest SHA256: `312b9622dd1cb27301cbbc745e0e6d635e968f7624ff12f96ffc83f74ee17c70`.

1. `BeginGameImpl`, `0x146425730`, выбирает запись сервера. Перед концом функции
   вызывает setter `0x144aab510` с выбранным ID и сохраняет endpoint отдельными
   setters. Эти участки уже проверены в
   [выборе серверной записи](HEADLESS-BEGIN-GAME-SERVER-TARGET.md).
2. По `0x146425af3` вызывается slot `+0x38` lobby wrapper. Таблица
   `0x149d84d78` связывает его с `Lobby_LoginPrepare`, `0x1467a9360`.
3. Эта подготовка получает game wrapper через `0x144aaa9d0`, читает выбранный
   ID getter `0x144aaaa10`, сохраняет его в lobby wrapper `+0x60` и переносит
   в PktLobbyLogin DWORD `+0x68`. В runtime это `integers[2]`.
   [Native-подготовка пакета](HEADLESS-LOBBY-LOGIN-PREPARATION.md) уже проверяет
   этот перенос для отдельных server ID.
4. `LobbyLoginResult_Handler`, `0x14677ec50`, переносит две строки успешного
   ответа в game wrapper и вызывает игровое подключение из обработчика.
   [Windows-ветвь](HEADLESS-LOBBY-WINDOWS-CONTINUATION.md) проверена отдельно.

Поэтому ответ от Login с server ID = 0 нельзя считать воспроизведённым
ответом выбранного игрового сервера. Время жизни lobby socket также должно
покрывать переход к игровому подключению. Это клиентские связи, не доказательство
того, что сервер отклонял прежние попытки именно по этим причинам.

## Изменения runtime

Игровой runner теперь выполняет на одном lobby socket:

`Version (1) → VersionResult (2) → список (103) → список (104) → выбор записи → Login (3) → LoginResult (4)`.

Sequence исходящих кадров: 0 / 1 / 2. Фильтры региона, состояния и SDK-страны
применяются до Login. Выбранный ненулевой server ID подставляется в пакет;
успешный ответ и SDK context передаются игровому обмену только в памяти.
Игровой обмен выполняется внутри callback до закрытия lobby socket.
Оба сокета закрываются и при отказе, и при исключении.

До открытия игрового сокета runner проверяет совпадение выбранной записи,
server ID успешного lobby Login и наличие открытого lobby context.
Старый отдельный диагностический login / list probe и режим --server-list-only
сохранены; они не являются новой цепочкой игрового подключения.

Пустой аккаунт и создание первого персонажа относятся к последующим этапам.
Здесь запросов персонажей нет. Kind = 0 и extra_number = 0 по-прежнему явно
выбраны диагностическим клиентом; их фактический начальный контекст не доказан.

## Проверки

19 целевых unittest-проверок прошли. Socket scenarios проверяют настоящий
обмен кадров, дробление ответа списка, ID / sequence и выбранный server ID.
Проверены отказ списка, server ID = 0, отказ Login и исключение consumer;
consumer успешной сессии вызывается до закрытия сокета. Отдельные проверки
запрещают игровой socket при несовпадающем ID, ошибке лобби или закрытом context.
Прежние native preparation и country-policy проверки также прошли.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_probe.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_selected_game_login.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_preparation.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_server_country_policy.py
```

## Реальный результат

Проведены две ограниченные попытки на том же HK-аккаунте / JP server ID 251:
первая — с выбранным ID и закрытием лобби перед игрой; вторая — с сохранением
открытого lobby socket во время игрового обмена. В обеих лобби приняло порядок
ответов `[2, 104, 4]`, Login server ID 251, все result codes = 0.
Лобби: 55 групп / 98 записей, send 545 / recv 11 466 байт.

В обеих попытках игровой Version принят, Login снова вернул 16 / InvalidState;
body 131 байт, send 641 / recv 94, других packet ID нет, подсчёт байтов полный.
Следовательно, эти исправления пока не устранили отказ. Список персонажей
не запрашивался. Оба обмена завершены, JP-транспорт остановлен, exit 0, stderr пуст.
Игра не запускалась, новая почта и новые ключи устройства не создавались.

Свежие публичные конфигурации, вне Git:

- CDN manifest SHA256 `22bb1b5e565a59b83d44dbbb6c268e06838cd4ac0b5f61c33f3b90ec06315f8b`, body 6000 байт;
- GMC2 manifest SHA256 `9c9f9616811e9f14dcd995fd6f67c360c602414258d79a21a1f992281fc835dd`, HTTP 200, body 13 773 байта.

Расположение: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/<SHA>/manifest.json`
и `public-gmc2-snapshots/<SHA>/manifest.json` соответственно.
Далее — оставшиеся входные поля и SDK / session context до успешного игрового Login.
