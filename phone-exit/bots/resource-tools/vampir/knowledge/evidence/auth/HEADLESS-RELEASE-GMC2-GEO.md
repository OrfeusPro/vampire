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

## Материалы

Каталог библиотеки:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| details/run-00ab3f9ed347/details.json, callback wrapper | 3c6b8b8c45e7e29440bda6484b97dd449d928af1c4cd07292e81f80e2c12f88d |
| details/run-5b8a4894a8ad/details.json, response consumer | 9724b752266af0557878066964b5454b6933b55ad03f68b2c08408cf74c7a21b |
| details/run-f80af1744c74/details.json, geo helper | 88435ba99ed45b90851ff6fd3bac2cb9ebdcd9b51d2aee5dead5e5d386172ee1 |
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
