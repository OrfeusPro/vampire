# Vampir — полный адрес offline token request

19 октября 2026. Продолжение [карты SDK и auth lookup](HEADLESS-SDK-MAP.md).
План code/refresh запроса теперь связывается с явно переданным authTokenUrl.
Актуальные серверные данные, получение кода и реальный вход ещё не реализованы.

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA относятся к image base `0x140000000`. Версия игры и Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-path.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_path.py -v
```

Зависимости закреплены в `requirements-native.txt`; дополнительный интеграционный
тест расшифровки использует optional backend из `requirements-crypto-analysis.txt`.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-path.json`, SHA256
`734ffd3259ff35d1a2bfcae55af4f6f528176816a492f2417202323ff393a00c`.
Сохранены source/tool/fragment hashes, инструкции, литералы, смещения и результаты.
Игра, сеть и аккаунты не использовались; адреса и ключи искусственные.

## Правило path append

Code caller `0x1450e2aef..0x1450e2b01` и refresh caller
`0x1450e343f..0x1450e3451` передают литерал `v2/access-token`, длину 15 и
скопированную базовую строку в `0x14142c9d0`. Этот helper исполнялся в Unicorn.

| База / сегмент | Поведение |
|---|---|
| Пустая база | Возвращается сегмент без добавленного слеша |
| База заканчивается `/` или `\` | Сегмент дописывается целиком |
| Сегмент начинается `/` | Дописывается без дополнительного слеша |
| Остальные непустые значения | Между базой и сегментом добавляется `/` |
| Пустой сегмент | Непустая база получает `/`, если ещё не заканчивается `/` или `\` |

Двойные слеши сохраняются. Например, `base/` + `/part` даёт `base//part`.
Обратный слеш в конце базы тоже сохраняется; начальный обратный слеш сегмента
не равен `/` и не подавляет добавление разделителя. Query/fragment не разбираются.
Это FString path concatenation, а не RFC URL resolution или нормализация.

70 native сценариев покрывают оба представления пустой FString (count 0/1),
пустой сегмент, `/`/`\` с обеих сторон, двойные слеши, Unicode и строки с query.
Buffer capacity предвыделена; growth branch не исполнялась. Единственный внешний
copy вызов использует ограниченный memcpy shim прежнего эмулятора.
Unicode проверен как UTF-16 единицы, URL encoding этим не восстанавливается.

## Общий код и связанный план

[sdk_config.py](../../vampir-shared/vampir_core/sdk_config.py) содержит
`append_sdk_path`. Правило соответствует native векторам; локальные ограничения:
4096 UTF-16 единиц для каждого входа и результата, NUL отклоняется.

[auth_request.py](../../vampir-shared/vampir_core/auth_request.py) дополнен
`bind_token_request(plan, constants)` и immutable `BoundTokenRequestPlan`.
Принимается существующий code/refresh plan: POST, authTokenUrl, v2/access-token,
form-urlencoded. База извлекается через общий SDK getter, path добавляется по
проверенному правилу; form body сохраняется без преобразования.
URL и body скрыты в repr. Функция не отправляет запрос и не хранит секреты.

Binder намеренно строже native prefix check: требует host и допустимый port,
отклоняет userinfo, query/fragment, backslash, пробельные и управляющие символы.
Scheme HTTP/HTTPS берётся из явной конфигурации. Она не выбирается по строкам
EXE; hostname не резолвится. Это локальная политика подготовки плана,
а не проверка доверия endpoint или серверной совместимости.

Пять тестов сверяют все native vectors/replay и оба auth callers, metadata,
body/repr и ошибки. Один интеграционный offline тест проходит настоящую цепочку:
искусственный RSA chunk → secret list → merge карты → code form → полный адрес.
Он не доказывает работу входа с сервером. Android runtime всё ещё не проверен.

## Преобразование JSON-значений: дополнительное статическое свидетельство

В отчёт включён helper `0x144476940`, используемый parser при заполнении карты.
По полю value+8: 2 вызывает `0x1415e48f0`, 3 сначала вызывает virtual slot `0x58`
для строки, затем при отказе helper `0x1415e4780` и formatter `0x141432760`;
4 выбирает литералы `true`/`false` после `0x1415e4730`. Остальные ветви дают пустую
FString. Этот helper здесь не исполнялся: формат числа и конкретные JSON value
implementations не объявлены восстановленными. Общее ядро не подставляет str().

Дальше требуется восстановить активные SDK settings и получение GMC2/DECKEY,
заполнение SDK+`0x310`, а также семантику преобразования значений. До этого
планы остаются offline, `network_ready=false`; игровой session handoff не готов.
