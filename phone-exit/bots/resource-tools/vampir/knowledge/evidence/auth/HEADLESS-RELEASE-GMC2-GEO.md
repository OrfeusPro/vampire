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

Прямой вызов geoLocation helper ещё не доказывает запись страны / города:
`0x144552430` пока не выгружен. Нельзя заменить этот путь чтением только
`geoIp.isoCountry`, joined country аккаунта или произвольным значением региона.
Следующий шаг — проверить эту функцию и destinations settings+0x3f0 / +0x3e0.

Для проверки формы сохранённого публичного GMC2 body сверены manifest / body SHA.
В `resultData.geoIp` есть строковые clientIp / geoLocation / isoCountry / isoCity /
cityName / countryName. Выведены только имена и типы, без IP и geo-значений.
Это наблюдение схемы одного ответа, не доказательство активного native cache.

Runtime metadata не изменена; ни старый IP из capture, ни сохранённые geo-данные
не передавались в новый Login. Причина InvalidState остаётся неизвестной.

## Материалы

Каталог библиотеки:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| details/run-00ab3f9ed347/details.json, callback wrapper | 3c6b8b8c45e7e29440bda6484b97dd449d928af1c4cd07292e81f80e2c12f88d |
| details/run-5b8a4894a8ad/details.json, response consumer | 9724b752266af0557878066964b5454b6933b55ad03f68b2c08408cf74c7a21b |
| details/run-f80af1744c74/details.json, geo helper | 88435ba99ed45b90851ff6fd3bac2cb9ebdcd9b51d2aee5dead5e5d386172ee1 |

Задание prepare вне Git:
`F:/PhoneExit Resources/Vampir/knowledge/requests/da25094fa1aa5b26d93f49456784458fd9e16557c5cfb00412b598c534fe447a/manifest.json`.
Коллекция прошла проверку source / output hashes и импортирована в общий индекс.
Прежние constructor / Refresh exports использованы без новой декомпиляции.
