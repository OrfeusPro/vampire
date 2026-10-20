# После замены телефонов: игровой LoginResult 16 / InvalidState

20 октября 2026. Продолжение [проверки контекста соединения](HEADLESS-CONNECTED-LOCAL-ADDRESS.md).
Источник — код и данные установленного клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Реальное изменение результата

После сообщения пользователя о замене телефонов заново прочитан личный
каталог: доступны три JP-выхода и один HK, а также UA / FR / SG / NL.
Выбран доступный JP-выход. Свежий внешний country probe подтвердил JP.
Идентификаторы телефонов и IP не сохранялись; точная смена внешнего IP
или серверная причина изменения результата этим не установлены.

Прежний аккаунт bot-hk-test@vampir.top и JP server ID 251 / group ID 251
сохранены. Наблюдённые ключи Windows-профиля Netmarble не заменялись;
новая почта / аккаунт не создавались. Свежие SDK SignIn, lobby Version /
Login и ID 104 приняты. SDK country HK проходит проверку JP array50.
ID 104: 55 групп, 98 серверных записей, body 11 338 байт; send 545 / recv 11 466.

На игровом сокете получены **VersionResult 0 и LoginResult 16**. Тело Login
131 байт, обмен 641 / 94 байта, other packet IDs пусты, byte counts полные.
Контекст — windows-sdk-initial-reset, extra_number 0, адрес исходящего
SOCKS-соединения неизвестен и передан пустым, как в предыдущей проверке.
Прежний код 58 / BlockedIp в этой попытке не получен. Это существенное
изменение ответа, но не доказательство причины или успешного входа.
Список персонажей не отправлялся. Сокеты закрыты, временный JP-клиент
завершён с exit 0, stderr пуст.

Снимки в `F:/PhoneExit Resources/Vampir`:

- `public-cdn-snapshots/80e84c4cb87d9e5e6e9a8f9161450f08b65440947ba52f64ac76bd395297f828/manifest.json`, 6000 байт.
- `public-gmc2-snapshots/d8e3c9250a6fb37b56d2c645357fb282b38cdb2fe044dd281140072ec0c1516f/manifest.json`, HTTP 200, 13 773 байта.

## Подтверждённое значение кода 16

Настоящий mapper 0x1458091b0 от входа до возврата преобразует 16 в ключ
**InvalidState**, ASCII-литерал 0x1498ffc20, file offset 160 426 016.
SHA256 bytes литерала с NUL:
`ae57f46db8636d50fd3d84a0eb0746edf5c106d345c364cabb65ca3d6a07c6a2`.
Адрес связан с исполненными инструкциями / jump tables, а не с номером строки.

Существующая английская таблица ProjectRED-Windows-6106.csv содержит этот
ключ в строке данных 91, текст «Invalid state». SHA256 таблицы:
`0139351e6a9c56a86903c24f55d3d90933167661e60994e203b34c34e97110c3`.
Это не уточняет, какое состояние аккаунта, SDK, игровой сессии или клиента
отклонено. Нельзя называть код блокировкой устройства или аккаунта.

[replay-result-error-16.py](../../../replay-result-error-16.py) переиспользует прежний
ограниченный mapper replay и исполняет полные вызовы для 0 / 16 / 58:
Success / InvalidState / BlockedIp. FString constructor остаётся fixture;
выполняется native mapper, не серверный код или вывод popup. Сохранены
достигнутые инструкции, source ranges, literal bytes и localization provenance.
Исходный отчёт семи кодов для BlockedIp сохранён без перезаписи.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/result-error-16-replay.json`.
SHA256: `8df799371fdf5bb2a532f42155a2830625edc91cfd25da2617394d7fd5a31cab`.
Ghidra-источник: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-258411d5e987`.
Функции ResultError_Text, Result_Gate, VersionResult_Handler и LoginResult_Handler
уже экспортированы; повторного экспорта не требовалось.

## Runtime и дальнейшая проверка

Runtime теперь сообщает InvalidState по-русски: «Недопустимое состояние при входе».
Автоматических повторов, смены профиля устройства, создания аккаунтов или
запроса персонажей на отказе нет. Три mapper / label tests, семь socket probe
и три Login runner tests прошли — 13 проверок. Проверка через socketpair
подтверждает Version → Login, закрытие после 16 и отсутствие запроса персонажей.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-result-error-16.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_result_error_text.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_login_probe.py
```

Далее — полный SDK / player state и контекст игрового Login до успешного входа,
списка / выбора персонажа и позиции. Повторный разбор VersionResult_Handler
подтвердил прямой вызов Login_Prepare после Result_Gate; сам по себе новый
код 16 не доказывает, что порядок этих двух запросов неверен. Разрешение
пользователя создать отдельную тестовую почту и аккаунт сохраняется для
контрольной проверки, если она потребуется.
