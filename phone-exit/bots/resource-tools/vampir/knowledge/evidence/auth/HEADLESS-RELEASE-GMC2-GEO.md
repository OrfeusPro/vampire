# GMC2 response: путь clientIp к common data

21 октября 2026. Current EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [обновления common data](HEADLESS-RELEASE-COMMON-DATA.md).
Это статический разбор сохранённых Ghidra instructions / pseudocode, не новый
native replay и не живая авторизация.

## Проверенная цепочка

Общий индекс нашёл `geoIp` в `0x1444c5080`. Это уже исполненный ранее GMC2
constructor, а не новый parser. Его повторное исследование не потребовалось.
В готовом `RefreshSDKConstants`, `0x1444faff0`, найден callback `0x1444dfc70`.
Три отсутствовавшие функции получены через prepare / collect, по явным адресам:

| Функция | Наблюдение |
| --- | --- |
| 0x1444dfc70 | Переносит два слова descriptor третьего аргумента во временный объект, обнуляет исходный descriptor и вызывает 0x1444d0370 |
| 0x1444d0370 | Проверяет результат / JSON и вызывает 0x1444f9980 с manager и разобранным JSON; далее обрабатывает constants / сохранение |
| 0x1444f9980 | Использует manager key descriptors, переносит строку в settings+0x38 и передаёт geoLocation следующему helper |

В constructor manager+0xc0 связан с literal `0x149537980` / `geoIp`,
manager+0xd0 — `0x149537988` / `clientIp`, manager+0xe0 — `0x149537998` /
`geoLocation`, manager+0xf0 — `0x1495379a8` / `isoCountry`.
Тексты заново сверены по immutable EXE; это публичные имена полей, не их значения.

В `0x1444f9980` два вызова `0x14447dd80` подготавливают вложенный JSON context;
второму передаётся manager+0xc0. Затем:

- `0x1444f9a09`: вызов `0x14447dfd0` с key manager+0xd0 / `clientIp`;
- `0x1444f9a0e`: destination `settings+0x38`, далее фактические move stores
  pointer / count / capacity и обнуление временного descriptor;
- `0x1444f9a60`: тот же string helper с key manager+0xe0 / `geoLocation`;
- `0x1444f9a6e`: передача settings, результата и raw flag 0 в `0x144552430`.

При доступном service settings берётся через `0x1444b23c0`, поле holder+0x110.
Это тот же источник, который использует проверенная UpdateGmc2: settings+0x38
→ P+0x108 / P+0x118 → D+0xe0 / D+0xf0 → I_ConnectIP / I_NMMobileIP.
Связь последнего участка и его fixtures описаны в предыдущем разборе.

## Что пока не доказано

Generic JSON helpers `0x14447dd80` / `0x14447dfd0` здесь не исполнялись native.
Полный callback, JSON acceptance, ошибки / отсутствие полей и изменение cache
также не проверялись исполнением. Обозначения nested context / string helper
описывают их использование в данном Ghidra пути, не новое доказательство всего parser.

Изначально роль geoLocation helper оставалась неизвестной. Продолжение ниже
установило запись страны в `0x144552430`; запись города им не подтверждена.
Нельзя заменить этот путь чтением только `geoIp.isoCountry`, joined country
аккаунта или произвольным значением региона.

Для проверки формы сохранённого публичного GMC2 body сверены manifest / body SHA.
В `resultData.geoIp` есть строковые clientIp / geoLocation / isoCountry / isoCity /
cityName / countryName. Выведены только имена и типы, без IP и geo-значений.
Это наблюдение схемы одного ответа, не доказательство активного native cache.

Runtime metadata не изменена; ни старый IP из capture, ни сохранённые geo-данные
не передавались в новый Login. Причина InvalidState остаётся неизвестной.

## GeoLocation — источник CountryCode

Отдельная выгрузка `0x144552430` содержит diagnostic literal
`void __cdecl UNMServiceSettings::SetCountryCode(const class FString,bool)`
по `0x14953c7a0`. Весь текущий метод разобран; destination assignment —
settings+0x3f0. GMC2 caller передаёт в него строку `geoLocation` с flag 0.

Метод сравнивает вход со строкой `A1`, literal `0x148a1742c`. Если строки равны
и прежний FString count settings+0x3f8 > 1, значение сохраняется. Во всех других
случаях вызывается assignment в settings+0x3f0, даже для равной обычной строки
или пустого входа. Это не универсальное правило «A1 всегда пропускается»:
при пустом прежнем поле native setter сохраняет A1.

[replay-release-country-setter.py](../../../replay-release-country-setter.py)
исполнил **целый setter с notify=0**, как в GMC2 caller, при выключенной diagnostic
logging. 14 синтетических случаев включают прежние count 0 / 1 / >1, A1,
одинаковые / разные страны, пустые и Unicode строки, a1 и A1x. Проверены выбор
ветви, source descriptor, cleanup входа и отсутствие записей вне +0x3f0…+0x400,
включая соседний city descriptor. Три regression tests прошли.

FString compare / assignment / cleanup — fixtures. Реальный allocator / free
backend, notify=1, generic JSON helpers, HTTP acceptance, whole callback и
полный collector этим replay не исполняются. Случаи содержат только синтетические
строки, без реальных geo-значений / IP / credentials.

Вместе с прежним UpdateGmc2 подтверждён путь:
geoLocation → settings+0x3f0 → P+0x128 → D+0x100 → I_CountryCD.
Город этим методом не записывается. В используемом base metadata encoder I_City
не выбирается; расширять исследование города без нужного consumer не следует.
Следом — contracts нужных JSON helpers и подключение свежего GMC2 context
к runtime с явной проверкой источника / маршрута / свежести. Текущий runner
по-прежнему передаёт subset с I_TID; новых живых попыток здесь не было.

## JSON helpers: границы извлечения полей

Дополнительные явные экспорты текущего SHA прослежены по псевдокоду и
инструкциям. Это статический результат; native parser / map lookup не исполнялись.

- `0x14447dd80` сохраняет выходной адрес RDX, передаёт неизменённый ключ R8
  в общий lookup `0x14447e460`, затем вызывает `0x144472bf0` для вложенного
  контекста. `0x14447dfd0` использует тот же lookup и конверсию `0x14447e050`.
  Обе обёртки возвращают выходной адрес и освобождают временный shared reference.
- Lookup требует ненулевой value с type 6 и успешный virtual method +0x80.
  Затем формирует key view с длиной max(FString count − 1, 0) и вызывает
  `0x1415f3770`. Сам map lookup и поведение отсутствующего ключа не проверены.
- Конструктор контекста `0x144472bf0` сначала обнуляет выходное состояние;
  значение принимает только при ненулевом pointer и type 6.
- `0x14447e050` при null или типе вне 2 / 3 / 4 возвращает нулевой FString
  descriptor. Для type 2 вызывает `0x1415ea440`; type 3 использует virtual +0x58
  либо numeric fallback, type 4 выбирает literal по результату bool accessor.
  Следовательно, native converter нельзя описывать как строго string-only.
- Строковая ветвь `0x1415ea440` обнуляет выходной descriptor, передаёт его virtual
  method +0x58 и возвращает тот же адрес. При false создаётся и освобождается
  отдельная временная строка; замены выходного descriptor в этой ветви не видно.
  Конкретная реализация virtual method и backend FString ещё не проверены.

Для runtime следующая граница — строгая локальная политика приёма наблюдаемой
object / string схемы `resultData.geoIp`, а не копия всего native parser.
Неподдержанные типы отклонять до авторизации; не угадывать numeric formatting.
Проверять SHA профиля / body, маршрут и возраст ответа. `geoLocation` передавать
по доказанному правилу A1, `clientIp` — только из свежего ответа выбранного выхода.
Полный callback / cache lifecycle и обязательность metadata для Login остаются
неизвестными. В этой проверке runtime и сеть не запускались.

## Свежий GMC2 context в runtime

Для `recovered-release` `run-nid-sdk-sign-in.py` теперь получает публичный GMC2
непосредственно перед входом через выбранный SOCKS / HTTPS. Request и NID profile
должны принадлежать одному закреплённому SHA источника и профиля. Константы SDK,
clientIp, geoLocation и isoCountry извлекаются из одного ответа в памяти;
сохранённый `public-gmc2-recovery.json` в этой ветви не читается.

Транспорт вынесен в лёгкий `vampir_core/gmc2_http.py` и используется также CLI
исследования. Сохраняются TLS validation, запрет redirects / credentials,
лимиты тела и времени, remote DNS через выбранный SOCKS. Исследовательские
инструменты и Ghidra runtime не импортируются.

`gmc2_context.py` принимает наблюдаемую схему объектов и непустых строк;
неподдержанные типы, дубли ключей, опасные для metadata строки и не публичный
IPv4 отклоняются локально. Это более строгая политика, чем native conversions.
SHA тела считается по полученным байтам. Поля и account context исключены из repr;
runtime не сохраняет body / geo / credentials на диск.

`probe-lobby-sdk-login.py` передаёт тот же `SdkInputs` в SDK, без повторной загрузки
и смешивания контекстов. До открытия окна, после окна и перед metadata проверяются
аккаунт, профиль, исходный SHA, SOCKS-порт и возраст по monotonic clock.
Локальный предел — 300 секунд с начала fetch, а не восстановленный SDK timeout.
Фоновая смена телефона за тем же портом отдельно не обнаруживается: маршрут должен
оставаться неизменным в течение попытки; после его замены нужен новый контекст.

Для текущего source SHA частичная metadata дополнена I_ConnectIP из clientIp
и I_CountryCD из geoLocation. IsoCountry используется отдельно в прежнем SDK
countryCode; joined country не заменяет geoLocation. Собственное состояние страны
бота в начале запуска пустое: A1 в этом случае записывается. Helper сохраняет
непустое прежнее значение для последующих обновлений A1; cache игры не читается.

Локально прошли 34 теста: 11 новых geo / runtime, 5 lobby, 6 NID runner,
5 release profile и 7 public GMC2. HTTP / browser / auth в новых runtime tests —
fixtures; реальная сессия и причина InvalidState ими не установлены.
Исторические тесты прежнего профиля используют сохранённый EXE с проверкой
полного SHA вместо обновлённого установленного файла. Production guards сохранены.
Три новых offline checks зарегистрированы в research-checks.json.

Задание: `F:/PhoneExit Resources/Vampir/knowledge/requests/14410cfec54b4369d1c5a976444e5348f7d39353252e208fc7fdcf8e4e5f9d01/manifest.json`.
Следом — одна живая проверка текущей metadata через стабильный JP-маршрут.

## Живая JP-проверка: Login и список приняты

21 октября 2026 после подключения свежего GMC2 выполнена проверка через
samsung SM-A205F / JP, server 256 / group 253 (Franz 2), ClientVersion 261105,
язык 1, launcher SDK flow. Официальная игра не была запущена одновременно.

Первый запуск без пароля проверял сохранённую сессию окна Netmarble. Свежий
GMC2 был получен, но окно завершилось по timeout / manual; SDK / Game Login
в этом запуске не отправлялись. Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/live-login-observations/b62f11cbd880690cd96a1f36a9f0efe13e36fb33c12590f7f8148b39dce427e8/manifest.json`,
SHA256 `b62f11cbd880690cd96a1f36a9f0efe13e36fb33c12590f7f8148b39dce427e8`.

Затем маршрут и контекст получены заново; ранее разрешённый пароль передан
через скрытый ввод, без записи в файл / process arguments. Результат:

- SDK launcher token / sign-in приняты; список серверов и выбранное лобби — code 0.
- Metadata — 312 байт вместо прежних 262; она передана из одного свежего контекста.
- Game Version — code 0; Game Login — code 0.
- CharacterList отправлен и принят, result code 0, одна запись, preferred index 0.
- Game send / receive — 991 / 463 байта; встречены также IDs 17, 8 и 27.
- Выбор персонажа не отправлялся; позиция и готовность мировой сессии не заявлены.
  Сокеты закрыты, временный JP-маршрут остановлен с code 0.

Основной отчёт этой проверки вне Git:
`F:/PhoneExit Resources/Vampir/live-login-observations/118896af22f216d154f551e65d1070c415988c37a69d2fa7f22fd1716775895d/manifest.json`,
SHA256 `118896af22f216d154f551e65d1070c415988c37a69d2fa7f22fd1716775895d`.

Это первый подтверждённый вход самостоятельного бота с новой связкой. Отличия
включают свежий GMC2 и два metadata поля; какая отдельная переменная устранила
наблюдавшийся InvalidState, изолированным экспериментом не установлено.
Удалять поля ради такого эксперимента сейчас не нужно: следующий продуктовый
шаг — выбор полученного персонажа в том же соединении и получение позиции.
Остальные metadata / full callback исследовать при конкретной необходимости,
не удерживать рабочий сценарий ради расширения вспомогательного покрытия.

## Материалы

Каталог библиотеки:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| details/run-00ab3f9ed347/details.json, callback wrapper | 3c6b8b8c45e7e29440bda6484b97dd449d928af1c4cd07292e81f80e2c12f88d |
| details/run-5b8a4894a8ad/details.json, response consumer | 9724b752266af0557878066964b5454b6933b55ad03f68b2c08408cf74c7a21b |
| details/run-f80af1744c74/details.json, geo helper | 88435ba99ed45b90851ff6fd3bac2cb9ebdcd9b51d2aee5dead5e5d386172ee1 |
| details/run-c08799161927/details.json, JSON wrappers | ad7301e234004403fe8702d6a043f720bf21ade2accb3c330c915ed0514453ab |
| details/run-f6a94d9c32d3/details.json, lookup / conversions | abb37322342deb3ebaddddecb487146eeaa6217bbe6caac5cc0f4aeea396bf17 |
| details/run-fa6ef4fc9442/details.json, string branch | 62b1d4eebe1f0b4a3c61dd7584bb496b5be97e4d5a3614875ad27395ed8f5d81 |
| details/run-784447667bfa/details.json, SetCountryCode | 5acdfa85c303bda2002ab56a5e84fb3938c862afa8a46a7dfba217576983804b |
| country-setter-replay/36e09ee434fe70d0b306f543eb7c6262db4c7a205de53cca8dcb568899f0a0f2/manifest.json | 36e09ee434fe70d0b306f543eb7c6262db4c7a205de53cca8dcb568899f0a0f2 |

Задание prepare вне Git:
`F:/PhoneExit Resources/Vampir/knowledge/requests/da25094fa1aa5b26d93f49456784458fd9e16557c5cfb00412b598c534fe447a/manifest.json`.
Коллекция прошла проверку source / output hashes и импортирована в общий индекс.
Прежние constructor / Refresh exports использованы без новой декомпиляции.

Задание SetCountryCode:
`F:/PhoneExit Resources/Vampir/knowledge/requests/fcfd6ad9e0bfcef24dce3ca0493c91b427fc57e6d067aad79896b08b5b04108d/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-country-setter.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_country_setter.py -v
```

Задания JSON helpers (каталог `F:/PhoneExit Resources/Vampir/knowledge/requests/`):

- `00ccfc9db53c33e13d6c3264aa626b6d24c3686e073171586a19fe7d625133d5/manifest.json`;
- `c19065def3a7c49f27a3261bfabc73bad3d5693083e8632e4745186ae9bb012d/manifest.json`;
- `3a6170ef118e69dcdf0e80c8c85962df802f74411b4a9f6588c3866fa3bbd54b/manifest.json`.
