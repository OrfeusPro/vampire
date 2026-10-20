# NID: полный базовый набор параметров штатного окна входа

20 октября 2026. Проверена сборка десяти базовых пар внутри
`FNetmarbleIDContent::CheckPossibleToOpen`, `0x1450de4f0`. Отдельно исполнен
getter webViewType для всех 256 значений байта. Общий runtime теперь готовит
этот контекст из явных настроек и зарегистрированных ключей устройства.
Адрес целиком, открытие браузера и реальная авторизация ещё не проверены.

## Источники

Исследован собранный Windows-клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

Ghidra 12.1.4: 276 функций, 110 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-7eceee836f52`.
SHA256 манифеста:
`8387b9fdf52e9c273f934b401e8ebb9c24467074e4822b6f0be2101eb3faf345`.
SHA256 `functions.json`:
`95ad6ab541f90a07006f5cb25f7e895f4cdcc53a835bc52bee570789e3679580`.

Переиспользованы прежние [NID key callsites](HEADLESS-NID-DEVICE-CONTEXT.md),
[device lifecycle](HEADLESS-DEVICE-LIFECYCLE.md) и
[отличие NMDeviceKey](HEADLESS-VERSION-DEVICE-INPUT.md).
В новом replay исполняются инструкции `0x1450de8c8..0x1450deb18`,
остановка — перед конструктором map `0x143bf76c0`.

| Пара | Подтверждённый источник |
| --- | --- |
| gameCode | NMSDK settings `+0x38` |
| buildCode | getter `0x14452b820`, byte settings `+0x48` |
| countryCode | service getter `0x144522160` |
| language | getter `0x143d163c0` |
| os | getter `0x1444e66b0` |
| nmDeviceKey | настоящий getter `0x1444e5ff0` |
| deviceKey | отдельный NID getter `0x144522b50(settings, output, true)` |
| osVersion | getter `0x1444e64f0` |
| clientId | NMSDK settings `+0x98` |
| nidV | строковый литерал `3`, `0x14898db1c` |

Пары извлекаются из последовательных descriptor pointers по `RBP+0x4a0`
с шагом 16 байт. Проверяются имена, порядок и фактические значения.
NM getter исполняется с заполненным cache fixture; NID и остальные context
getters, включая build selector, — явные fixtures. Выбор build A / B / C
ранее проверен отдельно на всех 256 входах; здесь не объявляется повторно
исполненным его body. FString storage / constructor также ограничены fixtures.

Восемь сценариев покрывают build bytes 0 / 1 / 2 / 3 / 255, пустые допустимые
поля страны / версии ОС, Unicode-язык и независимые NM / NID ключи.
Ни один реальный ключ или токен в replay не передаётся.

## webViewType и дальнейшие ветви

Полный `0x1450e7bc0` исполняется отдельно, verbose logging выключен.
Литералы и native ветви дают:

| Raw byte | Результат |
| --- | --- |
| 30 | steam |
| 31 | epic |
| 34 | xbox |
| Все остальные | sdk |

Для обычной ветви caller передаёт в этот helper 0. Для raw режима owner
4 / 5 использует другое состояние и может добавлять credential. Native switch
owner mode 0 / 4 добавляет authType=signin, 1 / 5 — linkidp, 2 — withdraw,
3 — agreements. Эти ветви после базовой сборки проверены по Ghidra и literals,
в данном replay switch не исполняется. Они не используются для утверждения,
что установлена активная ветвь провайдера игры.

После этого возможны дополнительные accessToken / playerId / joinedCountryCode
из кешированного состояния. Для первого входа общий helper их не подставляет.
Getter osVersion вызывает уже найденный Windows version helper `0x1415c3960`.
OS getter имеет собственные console / platform условия; строка `windows`
в сценарии — fixture, а не доказанное активное значение установленного SDK.

## Runtime и оставшаяся граница

`vampir_core.nid_web_context.prepare_nid_sign_in_context(...)` возвращает
неизменяемые пары с десятью базовыми полями, webViewType и authType=signin.
Все настройки явные; deviceKey берётся из `binding.nid_device_key`, а не
из `binding.device_key`, предназначенного для SDK sign-in. Неизвестные поля
не заполняются выводами из имени или числового ID. Содержимое скрыто в repr.

Требуются real-профиль, обе записанные identity и provenance. При confirmation
required подготовка блокируется; unknown допускает первую попытку, которая
может запросить подтверждение. Входные строки и общий byte budget ограничены.
Этот helper не генерирует ключи, не получает credential и не выполняет HTTP.

Native `0x144586a30` обходит map и собирает пары форматом `{0}={1}` через
преобразование значения `0x141c13850`, затем объединяет их разделителем.
Caller дописывает query к authWebViewUrl. Сериализация пока исследована
статически; точный encoding / порядок map и полный URL ещё не проверены
исполнением. Поэтому runtime helper возвращает контекст, а не выдаёт
стандартный urlencode за побайтное воспроизведение native builder.

Следующий конкретный участок — `0x141c13850` и сериализация query, затем
доставка результата штатного окна в бот без запуска игры. Почтовая ветка
возвращает provider accessToken, [а не обязательно authorization code](HEADLESS-NID-RESULT.md).
reCAPTCHA и проверки профиля должны проходить штатным способом; их результат
не заменяется синтетическими значениями. Аккаунт в этом этапе не открывался.

## Проверки

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/nid-web-context-replay.json`.
SHA256: `0c1e89b779fa4e113d7413008a5fac87c42c371b1a22250ade831a83fae546ec`.
Сохранены полный native root / helper instructions, SHA, восемь профилей,
256 результатов getter и явные границы исполнения.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-web-context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_web_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_nid_device_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Все 12 выбранных тестов прошли: три новых, один прежнего NID context,
пять Login context и три provenance Ghidra.
