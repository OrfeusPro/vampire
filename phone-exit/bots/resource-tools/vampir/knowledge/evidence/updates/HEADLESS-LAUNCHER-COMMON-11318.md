# Общий launcher transport 1.13.18: метод, заголовки и тело

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [проверки wrappers](HEADLESS-LAUNCHER-TRANSPORT-11318.md).
Общий обработчик `0x1445231a0`: 997 инструкций, все unwind ranges и bytes
сверены с EXE. Проверены complete block/direct-flow coverage и conditional
fallthroughs. Непросмотренная цель прерывает исполнение.

## Источники

| Экспорт | SHA256 | Содержимое |
| --- | --- | --- |
| run-cea84c0140a4 | dc9945d73e758aec186dbd2fe0c0cf42952e4b2451a437c29cf22d6dda9b08f6 | Общий обработчик |
| run-89bc7497bac0 | f9cc85c42ef46d269cd4095d5157617109803a919eb5d64c2b57be14a10f8588 | Шесть инициализаторов заголовков |

Второй export получен по явным roots, найденным candidate RIP scan. Кандидаты
проверены декодированием полных функций, exact literal bytes и аргументами
вызова строкового конструктора; совпадение смещения не заменяет эту проверку.
Общий cleanup tail `0x1487e976c` указан в collector request явно.

| Заголовок | Инициализатор | UTF-16 literal | Global |
| --- | --- | --- | --- |
| Accept | 1411B5090 | 148AE4C30 | 14B564718 |
| accessToken | 1411B50C0 | 14952CB68 | 14B564698 |
| authToken | 1411B50F0 | 14952CBB8 | 14B5646C8 |
| buildCode | 1411B5120 | 14952CBE8 | 14B5646E8 |
| Content-Type | 1411B51E0 | 148AEBC00 | 14B5646F8 |
| gameCode | 1411B5390 | 14952CBD0 | 14B5646D8 |

Все шесть инициализаторов исполнены с явной fixture строкового конструктора:
она проверяет RCX/global, RDX/literal и точный текст, затем использует неизменяемый
literal вместо выделения FString. Регистрация cleanup тоже fixture.

## Четыре сценария общего обработчика

Комбинации: тело пустое/непустое и поле контекста пустое/непустое. Во всех
случаях сервис и request существуют, custom headers пусты, исходный callback
пуст, логирование отключено, TLS/CVar представлены уже инициализированными fixtures.
Целая native функция доходит до возврата исходного output pointer.

Последовательность проверена по перехваченным аргументам и событиям:

1. Factory virtual+40 создаёт request; request virtual+68 получает исходный URL.
2. Virtual+B0 получает Content-Type/Accept со значением `application/json`.
3. Тот же метод получает gameCode из context+110 → data+38, buildCode — из
   результата formatter `0x1445323c0` над data+48. Сам formatter заменён fixture;
   реальное значение buildCode и назначение байта data+48 не установлены.
4. Если FString data+78 содержит текст (Num > 1), accessToken и authToken
   получают один и тот же исходный data+78. При пустой строке обоих вызовов нет.
5. Virtual+60 получает `POST`; virtual+90 получает исходный body только при Num > 1.
6. Virtual+F0 и `0x144511700` привязывают completion thunk `0x144538a40`
   с исходным manager и созданным holder; virtual+E8 вызывается ровно один раз.
7. Native cleanup вызывает destructor holder и очистку контейнера.

`application/json` по адресу `1495379A0` и `POST` по `149539F50` в EXE —
ASCII literals, преобразуемые вызовом `141426950`, а имена заголовков — UTF-16.
Входные manager, route, body, headers, delegate и SDK data сохраняются.
Проверено наличие holder при binding и порядок cleanup; асинхронный результат
этими вызовами не подтверждён.

Tool `replay-launcher-common-11318.py`, тест `test_vampir_launcher_common_11318.py`,
check `launcher-common-11318`.
Артефакт: `code-clues/launcher-common-11318/a5ef655a97058c3db3b8ebfe0e8ce7cfa39b2e566ce6c475c3ca565ef19f4113/manifest.json`.

## Границы и продолжение

Factory/HTTP virtual methods, allocation, FString conversion, SDK/service lookup,
buildCode formatter, completion binding и cleanup — явные fixtures. Отправка
всегда возвращает true. Native ветви ошибок, CVar initialization, непустые custom
headers, активный callback/capture и асинхронный lifecycle здесь не выполнены.
Настоящий клиент, process memory и сеть не использовались; действующая сессия
сохранена. `native_execution=true`, `network_used=false`, `profile_activation=false`,
`compatibility=not_established`.

Значение body передаётся как готовая строка: состав JSON и его сериализатор
нужно подтвердить в callers. Также остаются происхождение SDK/token context,
response getters/dispatch и ошибки отправки. Результат не включает live auth
и не разрешает перенос старого профиля или квестовых команд на новый EXE.
