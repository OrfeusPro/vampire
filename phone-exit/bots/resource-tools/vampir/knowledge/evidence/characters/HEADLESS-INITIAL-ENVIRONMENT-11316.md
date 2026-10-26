# Начальный SightEnter: NPC, другие игроки и адаптер

EXE 1.13.16, SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
ID 301 подключён к частичной модели отдельного владельца сессии.
Это продолжение [whole wire / lifecycle проверки](HEADLESS-SIGHT-ENTER-WHOLE-11316.md)
и [create / leave модели](HEADLESS-OBSERVED-ENVIRONMENT-11316.md).
Нового игрового входа здесь не выполнялось.

## Проверенная статическая цепочка

`inspect-sight-bindings-11316.py` сверяет полный SHA immutable PE, границы
инструкций / unwind roots, точные bytes, vtable slots, E8 targets и UTF16 literals.
Используются Capstone 5.0.6 и существующая bounded регистрационная выгрузка;
весь большой owner повторно не экспортируется.

- Constructor `1456c0300` вызван из `1467b605d`; регистрация `1467b6070`
  передаёт packet в RDX и handler в R8. Handler table `149dc6120+10`
  указывает на `14679c530`. Packet vtable `149922490+20` содержит reader
  `1456c5390`, slot +28 — getter `1456cf150`, возвращающий ID 301.
- Handler `14679c530` вызывает `14679e940` для CharacterOther и `14679e2f0`
  для NPC. NPC array: packet+20 / count+28 / stride 240; initializer
  `145d74330` совпадает с ID 324. NPC+8 — key, +10 — raw NPC ID,
  +18 — XYZ, +58 / +60 — HP / MaxHP; предыдущие field anchors проверяются повторно.
- CharacterOther array: packet+10 / count+18 / stride 230. Ветка сравнивает
  record+8 с own model+8 и пропускает собственный key. Initializer `145d745f0`
  переносит key+8, FString+20, XYZ+88 в поля model+8, +128, +20 соответственно.
- Record+c8 передаётся `145d8b8d0`: row+8 — EStat ID, row+10 — uint64 bits.
  Только stat 134 преобразуется делением на 100; level 3, HP 4 / MaxHP 5,
  MP 9 / MaxMP 10 передаются в `1455f10f0` напрямую. Имена типов установлены
  [ранее](HEADLESS-STAT-NOTIFY-11316.md), не угаданы по значениям.
- Factory `14567eb50` использует typed lookup `145513740`, generic key lookup
  `145512800` и IsA class getter `1454d0d90`. Getter передаёт в `1416ab8d0`
  строки `/Script/NnFramework` и `NnCharacterPC` из `149844010` / `1498b0a42`.
  Это основание для вида `player`; другие массивы не объявляются NPC / игроками.

Новые Ghidra exports находятся под полным SHA в `ghidra/request-exports/`:
`run-eda0e7f52b0c`, `run-195b5450082e`, `run-af1726c11f17`,
`run-9d2599a77a1b`, `run-1783b09fca41`; stat helper — `run-2b394d32f0ca`.
Каждый имеет полный export / provenance. Проверочный отчёт вне Git:
`code-clues/sight-bindings-11316/883c6d3899bf9b09d0be0c16e8f93c70e91e5ca484eee5e50fa623f3899713b9/manifest.json`.
Полный handler / UObject / listener native путь не исполнялся; source fields
не доказывают текущие координаты после коррекции движком.

## Изолированная модель и отображение

`ObservedEnvironment` разбирает полный ID 301 до изменения subset, с общим
collection budget 4096. Все изменения выполняются под lock владельца сессии.
NPC / player с одинаковым числовым key не сливаются; публичный key — decimal
string без потери uint64. Собственный player исключается только при явном
валидном key; при неизвестном key player rows пропускаются с отдельным счётчиком.

Имя игрока ограничено 32 Unicode codepoints, сокращение помечено. Level / HP /
MP публикуются только в безопасном диапазоне целых JavaScript; недопустимые bits
и нечисловые XYZ становятся неизвестными. Повторный stat использует последнюю
запись. Начальные stats / позиции имеют `stats_current=false` /
`position_current=false`, источник `sight_enter_notify`. Собственные vitals
не изменяются от этих записей.

Лимит общий: 512 NPC / игроков. API отдаёт две страницы по 256; существующие
ключи обновляются и при заполнении лимита. Пустой SightEnter не очищает прежние
наблюдения и не объявляет полный census. Leave удаляет actor key; triples
QuestVisibleActor не превращаются в дополнительные keys. Мир / close / decode
error очищают subset. До явного world ID события пропускаются; live owner
передаёт его только после finish_response. Порядок начального ID 301 относительно
world finish ещё нужно проверить на настоящем потоке. Ground / gadget / projectile / tether пока представлены
только числами записей последнего пакета, без выдуманной классификации.

Основной прототип использует прежний адаптер, общие HP/MP и кнопку «Окружение».
Таблица показывает тип / key, имя / код NPC, уровень, HP/MP и XYZ при получении.
Неизвестные поля — «—». Проекция на карту и названия монстров не добавлены.

## Воспроизведение и границы

```powershell
$env:PYTHONPATH='phone-exit/bots/vampir-shared;phone-exit/bots'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_initial_environment.py -v
node phone-exit/bots/vampir/ui-prototype/prototype-live-model.test.cjs
```

Пять offline tests проверяют static bindings, mixed upserts / own filtering,
unknown key, unsafe stats / nonfinite XYZ / name limits, atomic malformed frame,
leave / world / close, 50 synthetic owners и обе настоящие HTTP-страницы с 512
игроками и большим own stats payload. Это не реальные одновременные аккаунты.
Два ранних прогона максимального HTTP payload через urllib получили WinError
10054; причина не установлена. Отдельный случай и полный набор также проходили.
Проверка HTTP использует прямой HTTPConnection с явным timeout 3 секунды,
bounded read 262145 bytes и сверкой Content-Length; повторов запроса внутри
теста нет. Длительная стабильность HTTP-нагрузки требует отдельной проверки.

Браузер проверен через loopback API с `mode=fixture`, без игрового соединения:
два NPC (включая uint64 max key), игрок уровня 6, HP 875/1000, MP 210/500;
own key отфильтрован, собственные HP 2700/2700 и MP 2000/2000 сохранены.
После отключения fixture API открытая таблица очищена до «Текущие данные
окружения недоступны». Скриншот вне Git:
`F:/PhoneExit Resources/Vampir/ui-prototype-checks/initial-environment-pc-npc.png`.
Snapshot `e7344f7b8c0c227b762a85bfbf51cd610d4c26cd8b67524084a2f623b55aee99`
прошёл byte/provenance verifier: 1970 resources, 1507 textures. Это локальная
проверка данных / layout, не доказательство геометрии текущего игрового экрана.

Остаются настоящий поток окружения через Phone Exit, live multi-account,
current stats / movement и actor state, имена NPC, проекция / действия карты,
квесты и следование. Следующий шаг: проверить готовность выхода и сессии,
затем получить начальный SightEnter с реального сервера без слепых повторов входа.
