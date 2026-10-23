# Launcher-авторизация в текущем EXE

23 октября 2026. Источник — снимок EXE с полным SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Проверка статическая: игра, авторизация и сетевые запросы не запускались.
Продолжение [живого контроля создания](../characters/HEADLESS-CREATE-LIVE-PREFLIGHT.md).
Прежние [launcher-исследования](HEADLESS-LAUNCHER-TOKEN-CONTEXT.md)
относятся к другому SHA и сами по себе не подтверждают текущие адреса.

## Запросы

Текущие корни найдены по полным diagnostic literals в ASCII. LEA проверены
на границах инструкций целых unwind roots, затем получены полные Ghidra-экспорты.

| Операция | Текущий корень | Literal диагностической сигнатуры | HTTP wrapper |
| --- | --- | --- | --- |
| `GetTokenByLauncher` | `0x1444ef840` | `0x149532cc0` | `0x144523b00` |
| `SignInByLauncher` | `0x144504980` | `0x149532ed0` | `0x144523c80` |

Обе функции собирают начальные пары по глобальным ключам `0x14b564d10`,
`0x14b564d00`, `0x14b564d70`, `0x14b564d80`. Их текущие имена
`nmDeviceKey`, `deviceKey`, `countryCode`, `os` проверены ранее
[целыми initializers](HEADLESS-RELEASE-SIGN-UP-KEYS.md).
Адрес сервиса ищется по ASCII `authUrl` в `0x149530ed0`.

В `GetTokenByLauncher` при непустом credential вызывается его virtual `+0x8`.
Полученный объект дополняется двумя парами, затем помещается во внешнее поле
`credential`. Статически прослежены `gameCode` из service settings `+0x38`
и `buildCode`, преобразованный helper `0x144532f30` из settings byte `+0x48`.
Суффикс запроса — UTF-16 `launcher/token` в `0x149532da0`.

В `SignInByLauncher` значение credential `+0x58` передаётся с отдельным ключом
`launcherToken` в map заголовков; эта map передаётся отдельно от JSON body.
Суффикс — UTF-16 `launcher/sign-in` в `0x149532fb0`.
Это соответствует разделению двух запросов в
[runtime planner](../../../../../vampir-shared/vampir_core/sdk_launcher_auth.py).
Полный HTTP wrapper, заголовки по умолчанию, получение значений settings
и допустимость этих значений сервером в данном исследовании не исполнены.

Три имени дополнительно проверены по текущим initializers и байтам литералов:

| Initializer | Global FString | Имя |
| --- | --- | --- |
| `0x1411b0260` | `0x14b564cb0` | `buildCode` |
| `0x1411b04d0` | `0x14b564ca0` | `gameCode` |
| `0x1411b0590` | `0x14b564cf0` | `launcherToken` |

## Ответы и граница ошибки

Два callback pointer не имеют собственных unwind roots. `collect` оставил
их в очереди с этой причиной. Проверены реальные пятибайтовые переходы:

- `0x1444dfc20`: `e9fbd3feff` → `0x1444cd020`, ответ launcher/token;
- `0x1444dfd10`: `e98b48ffff` → `0x1444d45a0`, ответ launcher/sign-in.

Затем отдельно выгружены только эти два настоящих корня.
В обоих прослежены JSON / errorCode gates и диапазон HTTP 200–206.
Первый читает `resultData` строковым getter `0x14447dfd0` и передаёт результат
в `0x1444e6360`. Второй использует object getter `0x14447dd80`, обходит
вложенные данные и передаёт результат в `0x1444e7630`.
Семантика всех полей owner и полного dispatcher пока не проверена на текущем SHA.
Второй handler также переносит credential byte `+0x68` в module byte `+0x88`,
когда credential существует. Это не то же поле, что channel byte `+0x50`.

В неуспешной ветви `errorCode` преобразуется через `_wtoi`; ненулевое значение
передаётся в error result и `0x1444e7630`. Прямой ссылки на текущий SignUp
`0x144506cf0` в обоих обработчиках нет. Это **не исключает** отдельное решение
в последующем consumer или косвенном вызове. Причина серверного `1203`,
состояние SDK-профиля нового аккаунта и необходимость отдельной операции
по этим функциям не установлены. Автоматический SignUp не добавлен.

Read-only сравнение локальных назначений `bot-test` и `nightraven` подтвердило:
оба используют `launcher`, регион EU и одинаковые три наблюдённых ключа ПК.
Их серверы различаются: 384 и 381; выбор сервера происходит после SDK.
Пароли, provider country, token и профиль официального лаунчера при сравнении
не читались. Совпадение сохранённых ключей не доказывает равенство полных
запросов или серверного состояния аккаунтов.

## Воспроизводимость и ограничения

[audit-release-launcher-contract.py](../../../audit-release-launcher-contract.py)
сверяет полный SHA EXE, SHA трёх экспортов, байты всех экспортированных
инструкций, отдельное декодирование каждой инструкции, ключи, суффиксы и E9.
Это проверка связей и происхождения, **не native replay** и не доказательство
семантики аргументов по одному наличию ссылки. Смысл вызовов выше разобран
вручную по псевдокоду и инструкциям.

Все пути Ghidra ниже относительны к
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-4f6c93310580/details.json` — два запроса | `e184e1cb16b2f4e85dabe9bafec8099744bb82335dbb5955ca8ec044bef20a9a` |
| `details/run-82294ab74cc0/details.json` — три initializer | `9c65601c33add974231d636a77bf0ce314cbf7a92f8030ee477c00338f435df8` |
| `details/run-5f5b69ab5cf7/details.json` — два ответа | `8526f7380efb1838a063c0d6b5ec80c01e5df1b5f46def43104b6017f1ef3bf3` |

Отчёт аудита:
`F:/PhoneExit Resources/Vampir/code-clues/release-launcher-contract/e932511a686b5b130c15cf289b856a7f0772453dcd5cf37da8086bf0e5ddcb14/manifest.json`.
SHA256 совпадает с именем каталога. Семь функций проверены статически.
Три теста проверили текущие связи и отклонение изменённых EXE / export;
check `release-launcher-contract` привязан к этим зависимостям.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-release-launcher-contract.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_launcher_contract.py
```

Следом — текущий `0x1444e7630` и фактический consumer сохранённого callback:
где приложение принимает решение после SDK error, какие значения передаёт
и чем отличается первый вход нового аккаунта. До этого новые массовые входы,
регистрации или предположения о неверном пароле не дают обоснованной проверки.
