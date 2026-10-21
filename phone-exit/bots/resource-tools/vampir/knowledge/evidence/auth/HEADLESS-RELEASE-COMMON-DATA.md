# Заполнение common data в новой сборке

21 октября 2026. Источник EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [вопроса о заполнении полей](HEADLESS-NID-USER-INFO-FIELDS.md),
с учётом [проверки перехода лобби → игра](../network/HEADLESS-LIVE-TCP-CAPTURE.md#дополнительная-сверка-перехода-лобби--игра).
Первый этап — статическая проверка Ghidra / инструкций. Затем выполнен bounded
native replay отдельного setter, описанный ниже. Живого входа здесь нет.

## Что проверено заново после обновления

Выгружены текущие candidates collector `0x14560c880`, writer `0x144558870`
и owner constructor `0x144516ce0`. Constructor сохраняет таблицы
`0x149543170` в owner и `0x14953ff00` во вложенный объект размером 0x278;
37 строк начинаются во вложенном объекте+0x28. Просмотр первых 0x40 байт обеих
таблиц нашёл только destructor в slot 0; далее уже текстовые данные.
Не расширять этот путь как неизвестную виртуальную initialization-цепочку.

Текущие compiled diagnostics и проверенные RIP references привели к:

| Адрес | Имя из diagnostic literal |
| --- | --- |
| 0x1445307a0 | FLogImpl::Initialize |
| 0x1445567d0 | FLogImpl::Start |
| 0x144536f80 | FLogImpl::MakeSessionID |

Start вызывает MakeSessionID, затем передаёт `*(owner+0x28)` в
`0x144555470`. Последняя функция получает SDK service через weak reference,
регистрирует callbacks и **записывает FString descriptors в сам вложенный объект**.
Это найденный writer первоначальных значений, а не ранее исследованный ToMap,
Save, copy или SendSignIn. Ветка без service выходит до заполнения.

## Найденные записи

Пусть P — вложенный объект, D = P+0x28 — common-data строки.
В текущем псевдокоде и инструкциях видны переносы результатов helpers:

| Destination | Offset в D | Helper / источник перед записью |
| --- | --- | --- |
| P+0x28 | D+0x00 | 0x1444eda80 |
| P+0x38 | D+0x10 | 0x1444edc00 |
| P+0x48 | D+0x20 | 0x1444ebd40 |
| P+0x58 | D+0x30 | 0x1444ebd20 |
| P+0x68 | D+0x40 | 0x1444ed290 |
| P+0xa8 | D+0x80 | 0x1444eb690 |
| P+0xb8 | D+0x90 | literal 0x149545af8 через FString constructor |
| P+0x218 | D+0x1f0 | 0x1444eb880 |
| P+0x228 | D+0x200 | 0x1444ed230 |
| P+0x238 | D+0x210 | 0x1444f0e30 |
| P+0x248 | D+0x220 | 0x1444ed2b0 |

Новый writer ToMap сохраняет соответствующие field/key связи; ранее они
разобраны для ОС / версии ОС / модели / производителя / модели производителя,
GameVersion / SDKVersion, CPU / RAM / GPU / resolution. **Семантика helpers,
формат их строк и live значения ещё не подтверждены native-сценариями новой
сборки.** Не заменять их произвольными Python / WMI значениями по имени поля.

MakeSessionID создаёт значение через `0x1415600a0`, форматирует через
`0x14154eb20` с raw argument 0, обрабатывает `0x141439810`, сохраняет строку
в owner+0x98. Функция заполнения копирует её из SDK service+0x310 / owner+0x98
и передаёт в setter `0x14455cb10(P, string)`. Проверка setter ниже установила,
что это отдельный I_NMSessionID; подстановка этой строки в I_TID неверна.

## I_NMSessionID и I_TID имеют разные источники

Setter `0x14455cb10` сравнивает FString с полем **P+0x1d8**, то есть
**D+0x1b0**, и вызывает assignment только при отличии. Current ToMap связывает
D+0x1b0 с literal `I_NMSessionID` по `0x1495401d8`. В selector sequence
collector этого ключа нет. MakeSessionID не является найденным источником I_TID.

[replay-release-session-setter.py](../../../replay-release-session-setter.py)
исполняет весь actual setter при выключенной diagnostic logging. Восемь случаев:
пустые / равные / отличающиеся / разной длины / Unicode строки. Проверены low-byte
возврат 0 / 1, вызов assignment только при отличии, destination descriptor,
неизменность входного descriptor и всех соседних байтов 0x278-байтового объекта.
Сравнение UTF-16 и descriptor assignment — явные fixtures; реальное выделение,
освобождение и FString backend не исполняются. Тесты повторяют actual native
выполнение. Используются только синтетические строки.

У **I_TID** другой путь в actual writer `0x144555470`:

1. Проверяется FString count settings+0x610 — descriptor начинается в +0x608.
2. Если count < 2, вызываются `0x1415600a0` и formatter `0x14154eb20` с mode 0,
   результат переносится в settings+0x608, затем вызывается `0x144544500`.
3. Строка settings+0x608 копируется в **P+0xf8**, то есть **D+0xd0**.
4. Current ToMap связывает D+0xd0 с `I_TID`, literal `0x14954010c`.

Генератор `0x1415600a0` обнуляет 16 байт и вызывает `0x1415c4fc0`;
Ghidra определяет платформенный вызов как CoCreateGuid. Default branch formatter
меняет порядок байтов четырёх uint32 и вызывает hex helper `0x1415b30d0`
с длиной 16. Формат и Save mapping затем проверены ниже. Нельзя генерировать
I_TID при каждом Login или заменять её NMSessionID.
Обязательность поля для принятия Game Login по-прежнему не установлена.

## Формат I_TID и сохранение

[replay-release-guid-format.py](../../../replay-release-guid-format.py)
исполняет actual current formatter mode 0 и целый hex helper `0x1415b30d0`.
Четыре набора синтетических uint32, включая нули, максимумы и разные позиции
байтов, дали **32 uppercase hex symbols без дефисов**, FString count 33 с NUL.
Порядок соответствует объединению четырёх uint32 в виде `%08X`, а не стандартному
тексту Windows GUID. Например, слова 01234567 / 89ABCDEF / FEDCBA98 / 76543210
дали `0123456789ABCDEFFEDCBA9876543210`. Guards после 66 байт выхода не изменились.

FString заранее имеет capacity 64; allocator branch не исполнен. Cookie backend
задан fixture с проверкой значения. GUID generator, registry, SaveGame и SDK
lifecycle в replay не исполняются. Отдельный реальный вызов Windows CoCreateGuid
проверен без вывода / сохранения созданного значения.

Current Save `0x144544500` переносит settings+0x608 / count+0x610 в FString
SaveGame object+0x1f8 перед сериализацией. Это подтверждает сохранение TID,
а не смену при каждой авторизации. Полный Save/Load и чтение активного файла
установленной игры этим проходом не выполнены.

## Runtime: отдельный постоянный TID бота

[metadata_tid.py](../../../../../vampir-shared/vampir_core/metadata_tid.py)
повторяет проверенные Windows generation / word-format / reuse правила, но
хранит собственное состояние в `vampir-headless/.local/metadata.sqlite3`.
Это явная локальная политика runtime вместо записи в SaveGame установленной
игры. Значение **не объявляется наблюдённым TID официального клиента** и не
копируется из TCP capture. Привязка — фиксированный наблюдённый NMDeviceKey
и game scope thered; сам ключ в новой таблице не сохраняется, используется hash.

При первом использовании вызывается Windows CoCreateGuid, 16 native bytes
форматируются как четыре little-endian uint32 в uppercase hex. Транзакция
SQLite гарантирует одно значение при одновременном первом обращении. Повторное
открытие возвращает прежнее значение. Некорректное сохранённое состояние
отклоняется без молчаливой регенерации. В отличие от permissive native кэша,
локальная политика требует nonzero / 32 uppercase hex. Секреты авторизации
в хранилище не записываются; TID не выводится в summary / ошибки.

Для проверенного нового SHA ветвь `sdk-with-partial-metadata` теперь включает
I_TID. Прежний профиль / пустая metadata ветвь не получают это поле. Полная
metadata не восстановлена: source helpers остальных полей ещё открыты.
При прежних размерах шести полей ожидаемый subset увеличивается с 219 до
262 байт; реальное новое значение длины будет проверено при следующем входе.

Тесты: четыре проверки хранения / source guard / concurrency / native-format
comparison, пять lobby-context проверок и пять selected-game проверок прошли.
Fixtures не пишут реальную metadata DB; её первое создание происходит только
при запуске соответствующей авторизации. Затем выполнена одна живая попытка ниже.

## Живая попытка с I_TID

21 октября, samsung SM-A205F / JP, игра предварительно закрыта, телефон свободен.
Получены свежие CDN / GMC2 через тот же SOCKS 17948. Launcher flow, ClientVersion
261105, язык 1, server 256 / group 253; SDK joined country HK. SDK принят,
лобби Version / ServerList / Login имеют code 0. Summary подтвердила metadata
**262 байта** вместо 219. Собственное постоянное состояние TID создано в
игнорируемой `.local/metadata.sqlite3`, значение не выведено и не сохранено
в отчёте авторизации.

Game Version code 0, получен ID 17, ранний Ping отправлен. Game Login вновь
вернул **16 / InvalidState**, body 131 байт; отправлено 930, получено 114 байт.
List / Select не отправлялись. Owner сам закрыл соединение на отказе, затем
временный маршрут остановлен с code 0. Раннего Ping и собственного постоянного
I_TID недостаточно для входа в этой попытке; это не доказывает ненужность
остальной metadata или причину отказа.

Report вне Git:
`F:/PhoneExit Resources/Vampir/live-login-observations/2836f7c27733a06f9dc52ecf616b5f8a53e93e275462697892939acad6e2b59f/manifest.json`,
SHA256 `2836f7c27733a06f9dc52ecf616b5f8a53e93e275462697892939acad6e2b59f`.
CDN snapshot `e5164c345e2930a41b38794a6496a9d0614f533fb2887209de00e007076f63a3`,
GMC2 `2a17713dde46b673cac5439175be2a3308f8da8ff61a8bde84cbc66d2fa847d3`.
Report включает hashes runner / metadata_tid / clock / probe code и публичную
summary; credentials, device keys и raw packet bodies отсутствуют.

## Обновление сессионных полей из SDK и GMC2

После проверки общего индекса экспортированы шесть ранее отсутствовавших callees
actual writer. Их diagnostic literals и записи в объект дают следующие связи.
Как и выше, P — вложенный объект, D = P+0x28.

| Current function | Diagnostic method | Источник → destination |
| --- | --- | --- |
| 0x14455bc40 | UpdateGmc2 | settings+0x38 → P+0x108 и P+0x118; settings+0x3f0 → P+0x128; settings+0x3e0 → P+0x138 |
| 0x14455c110 | UpdatePlayer | player и getters → P+0x148…0x1c8, P+0x258 / P+0x268; условные channel / NID ветви ещё не исполнены |
| 0x14455c020 | UpdateLanguage | helper 0x143d1d470 → P+0x1a8 |
| 0x14455cc40 | UpdateTimeZone | helper 0x1444ef630 при доступном service → P+0x1e8 |
| 0x14455c950 | UpdateSDKSetting | SDK settings+0x38 → P+0xc8; helper 0x144532f30(settings byte+0x48) → P+0xd8; settings+0x28 → P+0xe8 |
| 0x14455bad0 | UpdateDisplayMetrics | helper 0x1444ed2b0 при доступном service → P+0x248 |

В текущем ToMap `0x144558870` заново сверены destinations и key literals:
D+0xe0 / `I_ConnectIP`, D+0xf0 / `I_NMMobileIP`, D+0x100 / `I_CountryCD`,
D+0x110 / `I_City`, D+0xa0 / `I_GameCode`, D+0xb0 / `I_NMBuildCode`,
D+0xc0 / `I_NMMarket`. Это статическая привязка текущего ToMap; его целое
native выполнение в этом проходе не заявляется. Два IP поля имеют один source
descriptor; отдельного определения мобильного IP в UpdateGmc2 нет.

[replay-release-common-context.py](../../../replay-release-common-context.py)
исполняет **целые UpdateGmc2 и UpdateSDKSetting**. 31 сценарий проверяет:

- готовый service, отсутствие service после lazy initialization и его появление;
- равные / разные / разной длины / Unicode строки;
- эквивалентность пустых FString с count 0 и count 1;
- независимые изменения полей, включая общий источник двух IP destinations;
- low-byte changed flag, сохранность соседних полей и исходного settings object.

Service lookup / lazy initialization, FString backend и bounded CRT copy заданы
fixtures; diagnostic logging выключен. Market helper также fixture: доказаны
его входной byte и destination, **не значения market mapping**. Current helper
`0x144532f30` уже найден в прежнем экспорте `details/run-ff5be244c76f`;
повторно выгружать его без новых входов не требуется. Три regression tests
повторно исполнили native сценарии и прошли.

Метаданные runtime в этом проходе не расширены. Источник записи settings+0x3f0
из ответа GMC2 ещё не связан с текущей функцией; `I_CountryCD` нельзя автоматически
приравнивать к joined country аккаунта. Аналогично, IP нельзя брать из старого
capture. Следующая проверка — current producer этих settings и условные
channel / NID ветви UpdatePlayer. Новый живой вход пока не выполнялся.

## Материалы и воспроизведение

Общий каталог вне Git:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Файл | SHA256 |
| --- | --- |
| details/run-a9346fc63f34/details.json, current collector / writer / owner | bd853e57aca595e219a6b2a7700e382e359380f710534bb603c1fa3215d50980 |
| bootstrap/run-f058526ab03a/export/bootstrap.json, tables / full diagnostic literals | fd8aba696a92ba2386783c3ea7db6e49658161140906fe6b08ff289daf9154cc |
| bootstrap/sdk-reference-candidates/a626c39388b2b3cf89274475f6430304a00b38963de52855bf0f817c69baae1b/manifest.json | a626c39388b2b3cf89274475f6430304a00b38963de52855bf0f817c69baae1b |
| details/run-5f0d1ef45af5/details.json, Initialize / Start / MakeSessionID | f887dfd5e24b4be3a03a5bacabca975153f1b65d617e3811a6d82a61dd6778b2 |
| sdk-reference-candidates/429e8650a7159e02ba40d4f60adcab4422ce6d935a52d6f7d80ed304932ccf6f/manifest.json | 429e8650a7159e02ba40d4f60adcab4422ce6d935a52d6f7d80ed304932ccf6f |
| details/run-c2c88fe32275/details.json, actual common-data writer | 1eb0b48a69fdc9b5a287a328d203d6ccf491bd12034a3eb5cf67629ae159df03 |
| details/run-3d333551d1d8/details.json, session setter | 01f72bd93f2d2cb81a1d382c8661e9a913e7b8299d9a615db9e46b6eca2a8cd0 |
| details/run-1fe12e787a88/details.json, generator / formatter / FString transfer | 3bcf0b7a1265fee453fbc7be4f641046f47e379fbf9615bdfc174dc562ccb25d |
| session-setter-replay/908880228b62b955d36a4c3f2e82115e599538d1efd93ad09dc77f13464d9bef/manifest.json | 908880228b62b955d36a4c3f2e82115e599538d1efd93ad09dc77f13464d9bef |
| details/run-9b65c26bd51d/details.json, current Save | e674e1f649421c606184463b367e9c7c63f09e551b847afdac161f3da2986d85 |
| details/run-765554611ab2/details.json, hex writer | 31bc1d2e366b30de909b740493e30d974154b161019b376a782d1515a909e9ae |
| guid-format-replay/14cf5b41499c1c7f5402fb39f83430d3002fcab2211efdcf199665fa2f0afbfa/manifest.json | 14cf5b41499c1c7f5402fb39f83430d3002fcab2211efdcf199665fa2f0afbfa |
| sdk-reference-candidates/a62001cdb34ba87c0038866ae78704484b413855a5d8bf212bce82826e72bd72/manifest.json, writer direct targets | a62001cdb34ba87c0038866ae78704484b413855a5d8bf212bce82826e72bd72 |
| details/run-af8c285547dd/details.json, шесть update callees | 741a018c06373c2c6524aeb0ccae30e17e0a37915a51ad0e910a0afc08998bc7 |
| common-context-replay/4aaf376d50e17036b0392e084b71cd132ede62f232b22a1a94d575fc44895eaa/manifest.json | 4aaf376d50e17036b0392e084b71cd132ede62f232b22a1a94d575fc44895eaa |

Промежуточные table / substring exports сохранены рядом; финальный literal
export выше содержит полные строки с return type, поэтому RIP candidates
следуют к началу diagnostic, а не к середине строки с именем класса.
SDK reference finder принимает SHA как comparison (`new_source_sha256`),
так и standalone export (`source_sha256`); несовпадение по-прежнему отклоняется.
Выгрузки сохранены вместе с invocation / source / tool / output hashes.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --common-data
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-session-setter.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_session_setter.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-guid-format.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_metadata_tid.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-common-context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_common_context.py -v
```

Следом — source helpers / callbacks остальных metadata полей и отличие lobby
lifecycle. Не повторять попытку на том же context без нового подтверждённого
изменения. Проверенную ветвь NMSessionID не повторять как неизвестный TID.
Память игры и её SaveGame не читались и не менялись.
