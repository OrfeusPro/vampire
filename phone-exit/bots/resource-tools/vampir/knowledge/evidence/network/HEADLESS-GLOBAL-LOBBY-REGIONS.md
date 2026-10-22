# Региональное лобби в текущем клиенте

22 октября 2026. Источник EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [прямой проверки и каталога без Prelude](HEADLESS-GLOBAL-DIRECT.md).
Пользователь уточнил: Global запущен в прежнем клиенте на ПК, выбран EU,
сервер Prelude 2; для аккаунта бота нужен новый персонаж.

## Источники адреса

В свежей CDN-конфигурации REAL есть `lobbyAddress`, `lobbyAddressNA`,
`lobbyAddressEU`, `lobbyAddressSG`. Все четыре точных UTF-16 литерала текущего
EXE имеют проверенные LEA references из `0x14565f760` / SetServerList.
Прежняя portable-модель читала только обычный адрес, поэтому сама доступность
Global не меняла выбранное ботом лобби.

| Ключ CDN | Literal VA | Поле config |
| --- | --- | --- |
| lobbyAddress | 0x14990f390 | +0xd0 |
| lobbyAddressNA | 0x14990f3c0 | +0xe0 |
| lobbyAddressEU | 0x14990f3e0 | +0xf0 |
| lobbyAddressSG | 0x14990f400 | +0x100 |

В этой сборке `lobbyPort` читается в +0x110. Старый layout с портом +0xe0
относится к историческому EXE и для этих полей неприменим.
В публичном CDN региональные адреса — DNS-имена. Endpoint validator теперь
использует ту же проверку публичного IPv4 / ограниченного DNS-имени, что
и игровой target; фактические DNS-ответы проверяет выбранный транспорт.

## Native selector

Целая функция `0x14563a8f0` при включённом guard `0x14b59502c` выбирает:

- параметр 5 → config+0x100 / SG;
- параметр 6 → config+0xe0 / NA;
- параметр 7 → config+0xf0 / EU;
- остальные значения → config+0xd0 / обычный адрес.

Пустая региональная FString не заменяет обычный адрес. При непустом выбранном
адресе и отличии от global FString `0x14b595040` вызывается assignment
`0x141441e40`, результат true. Выключенный guard, пустой итоговый адрес или
совпадение с прежним значением дают false без замены.

Direct caller `0x145614420` перед вызовом setter получает config через
`0x14563efe0` и читает выбранное число из singleton+0xa8 через `0x14556c640`.
Это проверенное окно инструкций; полный UI-путь выбора региона не исполнен.
`0x146460920` отдельно копирует переданный endpoint в globals и вызывает
методы peer; это не доказательство, что именно он выбирает региональный адрес.

## Проверка и границы

[replay-release-regional-lobby.py](../../../replay-release-regional-lobby.py)
исполнил целую `0x14563a8f0` в 540 комбинациях: параметры 0–8 / 255,
отсутствующая / пустая / непустая региональная и обычная строка, прежняя строка
и guard 0 / 1. Сравнение, ветвления, fallback и return исполняются native.
Config / прежние globals заданы fixtures; assignment — ограниченное копирование
descriptor без настоящего allocator. Source config проверен на неизменность.
Сеть, SDK и создание персонажа этой проверкой не выполняются.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-regional-lobby-replay/a315c86908d78c232d610fa1978c63b59dd21647cfa3a3fdbc95166e3e7032cd/manifest.json`.
SHA256 совпадает с именем каталога.

Материалы Ghidra в comparison
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

- `details/run-325d384c349d/details.json`, SHA256 `6e506a4cb7df54969a3ef2f9cbc0103c9ed60e763030d46717dcf6899a6e71a4` — SetServerList.
- `details/run-93dc853f4d98/details.json`, SHA256 `7b6da77bc68b3633340a1935a37e6447ff40468d1169ca26acadcf86f5b58da0` — selector и endpoint consumer.

В portable API `select_cdn_server(..., lobby_region='EU')` задаёт явный выбор.
Login runner связывает EU / NA / SG с тем же лобби, а фильтр игровых серверов
использует числа 7 / 6 / 5. Это локальные имена, соответствующие CDN-ключам
и native selector; не переименование прежних KR / ASIA / TW / JP.
Принадлежность конкретного server ID проверяется по свежему ответу ID 104.
До получения Prelude 2 создание персонажа и игровой вход не объявлены рабочими.
