# Автоматический Version: подготовка и ответ 20 → 22

Полный target SHA 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Последняя reviewed база обоих новых семейств — 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
[Машинные квитанции и измерения](AUTO-VERSION-11322.json).

## VersionResult и input buffer

Generic `version-result-v1` переносит 15 настоящих unwind roots и пять bounded
leaves. Проверяются все инструкции, локальные ветвления, вызовы, RIP-ссылки,
таблицы, constructor defaults и строка `PktVersionResult`. Несколько похожих
UTF-8 converter кандидатов разрешаются прямым вызовом string reader, без выбора
по близости адреса. Leaf u8 заканчивается `JMP [rax + 0x90]`: это отдельный
точный tail-dispatch, не произвольная разрешённая ветвь и не returning leaf.

Reader перенесён `0x1456dc620 → 0x1456dc670`, packet table — на `0x149929888`.
Constructor использует два подтверждённых uint32 defaults со значением 1.
Input table содержит 19 указателей: исполняемые slots связаны с точными ролями,
остальные записи остаются за пределами semantic coverage.

Выполнены 127 случаев на реальном EXE 1.13.22:

- 32 полных тела ID 2; форма `u32, u32, bool, u32, u32`, 17 байт.
- 17 усечённых тел, пять отказов на конкретной операции и один trailing-input случай.
- 72 случая native buffer constructors: размеры, mode / endian, padding, canaries
  и Win64 ABI, включая R13 и XMM6–XMM15.

Новый `portable_buffer_proof` даёт локальный допуск только доказанному constructor /
table / layout точного SHA. Shared helper сверяет proof, фактические PE bytes и
точный nested context; общего расширения старого SHA whitelist нет. Пустой или
чужой proof не даёт разрешения. Legacy путь с явными прежними SHA сохранён.

String / UTF-8 decode функции включены в исходные связи и exports, но в этих
пакетах не исполняются. Big-endian swap, strings, registration, dispatch и handler
не объявляются подтверждёнными. Этот input фундамент смогут использовать другие
ответы только после собственных reader / object / nested layout проверок.

## Базовая подготовка Version

Generic `version-prepare-v1` исполняет только prepare `0x1467d1ba0` и constructor
`0x1456d7c10`. Остальные provider / CPU / Windows / platform / combiners / strings /
allocator / send зависимости остаются именованными fixtures.
Сравниваются whole instruction shape, точные call offsets, fixture boundaries,
packet table с уже подтверждённым Version writer и wrapper slots `+0x38 / +0x48`.

Статические данные имеют отдельные роли: `_`, text descriptor, enum, compiled tag
pointer и 32-значная hex-строка, logging inputs. BSS принимается только в доказанном
PE zero-fill interval, без фиктивного чтения отсутствующих file bytes.
Пустой logger — строго заданный `ret 0` leaf; остальные fixture targets требуют
unwind entry и не должны совпадать с исполняемыми roots или друг с другом.

64 native сценария проверили десять строк / три integers, context present / absent,
пустые значения, send return, очистку временных allocations, сохранность входов и
owner reset. Все `native_nm_used`, `native_system_used`, `native_combiners_used` и
`native_platform_used` равны false. Происхождение настоящих SDK / hardware values
этим базовым уровнем не подтверждено. Последующие helper integration уровни — отдельно.

## Подключение и повтор

Оба семейства зарегистрированы в [native-check-adapters.json](../../native-check-adapters.json)
и запускаются обычным обновлятором. При сборке использованы готовые материалы:
для ответа собраны только 11 missing roots из 15, для preparation — два roots.
Ghidra project переиспользован. Полный EXE analysis не запускался.
Далее selected drivers используют общий Journal / cache, проверку sources / artifacts,
и публикуют immutable context / proof / semantic report перед atomic index update.
Последняя база каждого семейства выбирается самим adapter; historical source sets
и рабочая игровая сессия не меняются.

Указатели базы — `knowledge/generated-version-results/index.json` и
`knowledge/generated-version-prepare/index.json` в библиотеке. Они не являются
runtime профилями. Same-target повтор использует прежний proof, без self-transfer.
После каждого первого исполнения два повтора прошли без JVM и native replay.
Изменение одного семейства не повторяет независимые готовые suites.

Два субагента дали read-only разбор и кодовый черновик reader; оба достигли лимита.
Интеграция, завершение кода / тестов и реальная проверка выполнены координатором.
14 synthetic tests reader, 10 preparation и четыре общих driver tests входят
в штатный tooling aggregate. До этого подтверждённые 559 wire-сценариев не повторялись;
191 новый случай даёт отдельные proof scopes, а не 750 доказательств игрового входа.

Остаток: native helper integration подготовки Version, SDK / metadata / Login prepare,
handlers / registration / response composition, clock / heartbeat и world.
Новая авторизация, сетевые команды, профиль и онлайн-допуск не выполнялись.
