# Franz 2: связь имени с ID и отдельная попытка входа

20 октября 2026. Продолжение [проверки официального клиента](HEADLESS-OFFICIAL-CLIENT-JP.md).
Пользователь сообщил, что персонаж не создан, затем закрыл игру. Новая проверка
бота началась до сообщения о закрытии и завершилась после него; точный момент
закрытия относительно SDK-входа отдельно не измерялся.

## Таблицы и свежий список серверов

Существующие извлечения дают следующие строки `Real_JP`:

| Таблица | Id | Name |
| --- | --- | --- |
| ProjectRED-Windows-6107.csv | 251 | Monty1 JP |
| ProjectRED-Windows-6107.csv | 256 | Franz2 TC |
| ProjectRED-Windows-6108.csv | 253 | Franz |
| pakchunk1-Windows-516.csv | 251 | Monty1 |
| pakchunk1-Windows-516.csv | 256 | Franz2 |
| pakchunk1-Windows-517.csv | 253 | Franz |

Таблицы серверов имеют колонку ServerGroupType, таблицы групп — Type.
Совпадение числа в таблице групп и в таблице серверов не означает один объект.
В свежем ответе ID 104 запись сервера 256 содержит group ID 253 / region 4.
Это согласуется с показанным в клиенте `Franz - Franz 2`; старый выбор 251
по минимальному ID соответствовал другой строке — Monty1.
UI lookup локализации в работающем процессе не исполнялся, строки имени
из свежего сетевого ответа не выводились и не сохранялись.

[build-server-name-evidence.py](../../../build-server-name-evidence.py) читает только
существующие CSV и extraction indexes, проверяет SHA каждой таблицы и
единственность строк. Отчёт сохраняет SHA индексов, номера записей, смещения,
размеры и происхождение PAK из индексов. Нового извлечения PAK не было.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/server-name-evidence.json`,
SHA256 `03472fd8f48f4455c2e2638a21c471f0d51296d13141ecb1272e5c7eb28ee7d2`.
SHA CSV соответственно порядку таблиц выше, без повторов:

- 6107: `3a387427e02814e4318a4f076a8a3ecd2ad885c3c8a8698a32e04217f92d359a`;
- 6108: `453900ea40b505185fb8f37bfb27f9b5b1c597f2f0ce656aa3317f24e60deb5e`;
- 516: `25a59f795e68d121ed020aecca06f6e9627f0c4eed384a829f5f7cf3ae0ae348`;
- 517: `5df9b2e997f7588106bc26ddda39c148b149b43589a420eb1198da550c65010f`.

## Реальный вход бота на ID 256

HTTPS-проверка существующего Phone Exit SOCKS 1080 снова вернула JP.
Использованы свежие публичные snapshots:

- CDN: `public-cdn-snapshots/16d40e44070129c198e8c186f2c3c4ae6c5a4edc281a53df584469cae168efb0/manifest.json`;
- GMC2: `public-gmc2-snapshots/b73d7a223360935479d26ed15750da8fe8f58e17cefd5a3ac42cf8baed8b91ab/manifest.json`.

Корень обоих путей — `F:/PhoneExit Resources/Vampir`; имена каталогов равны
SHA256 manifest. GMC2 вернул HTTP 200, 13 773 байта; CDN — 6000 байт.
Пароль передан через stdin; credentials и тела ответов не сохранялись.

Результат `probe-selected-game-login.py` для аккаунта bot-hk-test@vampir.top:

- SDK принят, joined country HK.
- Лобби: пакеты 2 / 104 / 4, все три кода 0; 55 групп и 98 серверов.
  Выбор ID 256 передан в lobby Login, лобби оставалось открытым при игровом входе.
- Выбран server ID 256 / group ID 253 / region JP. Native state gate не исключает
  запись, проверка страны HK пройдена. Это не доказательство всех условий входа.
- Установленный ClientVersion прочитан из windows.manifestlist: 258392.
  Контекст `windows-sdk-initial-reset`, source profile `recovered-base`.
- Game Version: 0. Game Login: 16 / InvalidState, тело 131 байт.
  Отправлен 641 байт, получено 94; другие packet IDs отсутствуют,
  счётчики полные. Соединения закрыты, запрос персонажей не отправлялся.

Другой сервер не устранил отказ. Это не доказывает, что контекст лаунчера,
metadata, устройство или защитный компонент являются причиной InvalidState.
Следующая проверка — источник SDK / launcher context по имеющимся экспортам.
Создание персонажа и позиция остаются открытыми.

## Воспроизведение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-server-name-evidence.py
```

Для сетевого runner использовать существующую команду из
[описания выбранного lobby Login](HEADLESS-SELECTED-LOBBY-LOGIN.md), изменив
явный `--server-id` на 256, порт на действующий SOCKS и public manifest на
свежий. Ревизию читать через `--patch-manifestlist`; пароль — только stdin.
Повтор без изменения условий автоматически не запускается. Runtime не менялся.
