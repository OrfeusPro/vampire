# Проверка состояния сервера перед входом

20 октября 2026. Продолжение [выбора региона](HEADLESS-SERVER-REGION-SELECTION.md).
Источник — данные и код клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Страна HK и регион JP

Подтверждённая таблица JoinedCountry разрешает аккаунтам HK регионы TW, ASIA
и JP. Поэтому страна регистрации HK сама по себе не доказывает причину отказа
на JP. Таблица не заменяет актуальную серверную политику и не доказывает,
что весь country context нашего игрового Login уже совпадает с клиентом.
Адрес почты не используется как признак региона в реализованном selector.

## Сброс выбора в native-коде

В ServerList_Update 0x145d4afe0 после lookup выбранного сервера:

- 0x145d4bcd7 загружает byte по record+0x35.
- 0x145d4bcdb вычитает 2 из младшего байта; 0x145d4bcde сравнивает его с 1.
- 0x145d4bce1 делает unsigned JBE на 0x145d4bd83 только для значений 2 и 3.
- 0x145d4bd83 записывает нулевой QWORD по master+0x308: сбрасывает оба DWORD
  выбранного сервера. Остальные значения идут к передаче выбранного endpoint.

[replay-server-record-state.py](../../../replay-server-record-state.py) исполнил эти
инструкции для всех 256 значений входного байта и проверил как переход, так и
два итоговых ID. Lookup и полный Update не исполнялись; объекты — fixtures.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/server-record-state-replay.json`.
SHA256: `15e379952404d0c8f26b99646dbb30b4ba91a356a6be9a9321a081c0e09802a2`.

Runtime теперь исключает состояния 2 и 3 при выборе внутри явного региона.
Явный ID с таким состоянием отклоняется; автоматический выбор продолжает
поиск в том же регионе. Это консервативное применение native-условия сброса,
а не доказательство доступности входа для всех остальных значений.
Старый endpoint-only selector сохраняет назначение проверки адреса и порта.

## Что ещё нельзя называть «открыт» или «закрыт»

Имена значений record+0x35 пока не установлены. Нельзя подменять ими общий
доступ к серверу, заполненность, техработы или запрет создания персонажа.
В извлечённой английской таблице ProjectRED-Windows-6099.csv есть разные ключи:
SERVERLIST_STATE_00 / 01 / 02 / 03 и TITLE_SERVER_CREATE_LIMITE_NOTICE.
SHA256 таблицы: `433812fd793da5fff5197a8441b3c0831cd30e31002cd1fcc0004628099a4fe7`.
Их связь с конкретным wire-полем и числом ещё не доказана. Виджет
WBP_ServerSelectMyCharacterT содержит ImageNormal, ImageBusy, ImageFull,
ImageMaintenance, WidgetSwitcherState и ButtonAccess; имена не доказывают
условие клика или актуальную видимость.

Отдельный predicate 0x145d3b1b0 сравнивает строки record+0x50 с текстом,
полученным через SDK getter 0x1456048f0, либо с fallback global 0x14b520d60.
Пустой массив принимает запись, отсутствующая запись отклоняется.
Getter 0x1456048f0 вызывает 0x1445242f0, который копирует FString из
SDK player settings+0x210. В этой функции проверен точный ASCII-литерал
по 0x1494e2150: `class FString __cdecl UNMPlayer::GetJoinedCountryCode(void) const`.
Это связь с кодом страны регистрации, а не со списком отдельных аккаунтов.
Сравнение использует регистронезависимый ASCII-путь 0x1414596e0 после проверки
длины FString. Последующее [дополнение о country policy](HEADLESS-SERVER-COUNTRY-POLICY.md)
подтвердило запись settings+0x210 ответом SDK и полный predicate. Его реальный
fallback country ещё не связан; runtime использует только свежую SDK-страну.
Строки array50 не выводятся в диагностику, сохраняется количество элементов
и результат сравнения с SDK country.

[build-server-entry-index.py](../../../build-server-entry-index.py) связывает точные
диагностические литералы с native roots 0x146429c90 / 0x14642a1e0 и обработчиком
LoginResult. Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/server-entry-index.json`.
После расширения setter diagnostic текущий SHA256:
`eb71020d69d3e24f75d011582031268ddbdda1a66e86960ef330f30c658054f2`.
Эти точки и caller 0x146417800 проверены в Ghidra; пользовательский доступ
не выводится только из их аналитических имён.

## Реальная проверка

Свежая цепочка через подтверждённый JP-выход на bot-hk-test@vampir.top снова
получила SDK / lobby вход и ID 104: 55 групп, 98 записей, body 11 338 байт.
В JP находятся ID 251–270. У всех enums +0x34/+0x35/+0x60 равны 1/0/0,
array50 содержит пять строк. Состояния 2 и 3 среди этих JP-записей отсутствуют.
Остальные flags различаются; их семантика не назначена по этим различиям.

Выбран JP server ID 251 / group ID 251. VersionResult 0, LoginResult 58 /
BlockedIp, body 131 байт, обмен 650 / 94 байта. Полученный отказ не объясняется
найденным условием сброса состояния 2/3. Полная доступность сервера этим ещё
не доказана. Список персонажей не отправлялся. Сокеты закрыты, временный
JP-клиент остановлен с exit 0, stderr пуст.

Снимки в `F:/PhoneExit Resources/Vampir`:

- CDN: `public-cdn-snapshots/a54f3c242c026a9434afb27f3bc3adf7c7c24d92c6942e5c615b25cfd2121ada/manifest.json`, 6000 байт.
- GMC2: `public-gmc2-snapshots/9d125b10a23eb44770a0b3efe3dde3ab176b19311ca68ece51a5c7c79f3176c9/manifest.json`, HTTP 200, 13 773 байта.

Диагностика Login runner выводит только ID, числовые enums, bool flags,
количество array50 и результат известного native-условия. Host, тексты,
содержимое array50 и auth context в этот вывод не включаются.

Ghidra 12.1.4: 365 функций / 172 предупреждения. Экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-218f99c0b140`.
Manifest SHA256: `3533fc70b0d68147135d155b7793cbe0c68b26c744d0b124e1fdf40fded9781a`.
functions.json SHA256: `319ed9dd35469eff030befd0b06fcb3378fe8396014cd1929d649d36e1abf476`.

Команды из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-server-entry-index.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-server-record-state.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_server_region_target.py
```

Проверка: пять region/state tests, три Login runner, три endpoint, четыре
Version selector и три Ghidra. Далее — запись joined country в SDK settings, полный
predicate и проверка соответствия HK содержимому JP array50 до успешного
Login и списка персонажей.
