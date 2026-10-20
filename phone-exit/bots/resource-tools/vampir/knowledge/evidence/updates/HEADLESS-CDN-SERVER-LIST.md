# CDN: выбор сервера и данные лобби, 19 октября 2026

Проверка `0x145661a70` после ReadJson оказалась функцией `_SetServerList`
(имя в compiled diagnostic). Выбор связывает `select_server → type` с первым
совпадением в `server_list`, затем читает четыре поля detail. Реального config
и подключения ещё нет; адреса в replay — искусственные `.invalid`.

## Источник и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект.
Инструмент: [build-headless-cdn-server-list.py](../../../build-headless-cdn-server-list.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-server-list.py`.
Capstone 5.0.6/Unicorn 2.1.4, Windows CRT path/SHA записаны в отчёте.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-server-list.json`.
SHA256: `c281805515792cbd2074ef506b2e4daae770af2b45a9e9c246661627bc01dcb2`.
В нём source/tool/prior SHA, инструкции/offsets/bytes, литералы, comparator/
fold table bytes, `_wtoi` import и 31 вход/результат исполнения.

## Подтверждённая цепочка

1. ReadJson slice `0x14565a6b8..0x14565a753` создаёт ключи select_server/type,
   вызывает `0x14563da10`, конвертирует значение в FString и переносит его
   в config+0x28. Missing идёт в branch `0x14565f6a2`, а не задаёт default.
2. `_SetServerList` вызывает top-level lookup `0x14563dc30` для server_list,
   затем array conversion `0x1415e4680`. Missing list возвращает false.
3. Для каждого объекта берётся поле type. Missing пропускается. Native сравнивает
   длину FString, затем helper `0x1414596e0`: без учёта ASCII-регистра; non-ASCII
   units сравниваются буквально. Unicode casefold и trim не выполняются.
4. Первое совпадение сохраняется, обход заканчивается. Пустой список и отсутствие
   совпадений дают false. Пустой type может совпасть с пустым type.
5. По выбранному объекту читаются detail/field через `0x14563da10`:

| Поле | Call lookup | Destination FString |
|---|---|---|
| lobbyAddress | `0x145661ded` | config+0xd0 |
| lobbyPort | `0x145661fa7` | config+0xe0 |
| patchURL | `0x145662105` | config+0xf0 |
| dataURL | `0x14566225f` | config+0x100 |

При найденном поле исполняется native FString move. При missing добавляется
diagnostic, прежнее значение поля остаётся; функция всё равно может вернуть
true. Это **выбор и присвоение**, не полная проверка пригодности endpoints.
В конце адрес копируется в global, а port преобразуется actual Windows `_wtoi`
на `0x1456623bf`. В проверенных fixtures `2junk` → 2, `-1` → uint32 max,
65536 сохраняется. Проверки диапазона TCP-порта на этом участке нет.

## Границы исполнения

31 replay: один missing select_server/type останавливается на missing branch
до `_SetServerList`; в остальных 30 функция исполняется целиком. Включены missing/
empty/no-match, первый из дубликатов, ASCII/non-ASCII/space/empty comparison,
все 16 сочетаний наличия detail fields и четыре port boundary/quirk fixtures.
После каждой ветки проверены итоговые поля и return/global values.

JSON lookup/array/object/hash/type conversion, FString ctor/free/concat и
diagnostics — явные bounded shims; reference-count control pointers — fixtures 0.
Native loop, ветвления, comparator/fold table, field moves и port conversion
исполняются. Семантика произвольных JSON типов и native key matching внутри
lookup helpers не доказана. Это не полный ReadJson или реальный startup.

## Общий переносимый код

[cdn_servers.py](../../../../../vampir-shared/vampir_core/cdn_servers.py):
`select_cdn_server(document)` возвращает frozen CdnServerSelection: index,
requested/entry type и raw lobby_address/lobby_port/patch_url/data_url.
Endpoint fields скрыты в repr. Нет глобального состояния адресов между аккаунтами.

Missing fields дают None — «не заменять», без переноса прежних значений другого
аккаунта. Port остаётся исходной строкой, без permissive `_wtoi`; host/URLs
не нормализуются, не проверяются на доверие и не используются для IO.
Caller должен отдельно подтвердить обязательные endpoint fields и валидность
порта/адреса перед подключением. Выбор не объявляет конфигурацию готовой.

**Локальная политика:** exact JSON names, dict/list/string types, не более
1024 entries, type 128 UTF-16 units, detail field 4096 units, без NUL и malformed
Unicode. Missing item type пропускается, неправильный тип вызывает ошибку.
Нет guessed/default сервера при missing/no-match.

Семь тестов проверяют source/literals/CRT/инструкции, все 31 replay и общий
selector, порядок/ASCII-only comparison, missing field isolation, port quirks,
budgets/schema и JSON document → SDK environment + lobby detail plan.

Продолжение: физический источник актуальных CDN settings, реальный document,
остальные поля ReadJson/полный startup, endpoint validation и auth handoff.
Patch/data URLs пока только raw поля; обновление ресурсов ими не выполняется.
`network_ready=false`.
