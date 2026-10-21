# Новый compiled tag Version / Login и код 1

21 октября 2026. Продолжение [профиля SDK новой версии](CLIENT-SDK-PROFILE-UPDATE.md)
и [успешного HK-захвата](../network/HEADLESS-LIVE-TCP-CAPTURE.md#успешный-hk-захват-2d150317-после-обновления).
Код и данные собранного клиента, не исходный C++ проект. Новый EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

Все comparison-relative пути ниже относятся к
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

## Код 1: текущий mapper, а не перенос старого значения

По реестру сначала прочитан старый ResultError_Text / popup. Exact correlator
дал candidate ResultError_Popup 0x145fd5370; роль не переносилась автоматически.
Ghidra export пары `details/run-4d1035d2befb/details.json`, SHA256
`26ed50f4c7ff83354cd36b651cfc7453f117a5587feca54f6ee36e81cde65ae1`,
подтвердил вызов fallback mapper 0x145814800. Table override / popup не исполнялись.

Finder дополнен поддержкой new-side сравнительных Ghidra exports: old-side
игнорируется, instructions / flows нормализуются и bytes сверяются с текущим EXE
до использования ссылок. Первый проход с прежним форматом отклонил запрос,
поскольку видел только functions / references; guards не обходились.
Reference manifest
`sdk-reference-candidates/d463a5d15bc0100bb18b1db1ea8466a467011f9d1a3e6145fc6a6c0a17d9d4c1/manifest.json`.

Выборочный Ghidra export mapper: `details/run-5f520de02cee/details.json`, SHA256
`329dcdce6357bcc5a9f1747dc992d17e7beb637acf457d02646cf8b18dacc88c`.
Для явно выбранных targets лимит функции повышен с 20000 до 65536 байт:
mapper занимает около 42 КиБ. В псевдокоде есть warnings о плохих / unreachable
инструкциях; он не использовался как единственное доказательство поведения.

[replay-release-result-error.py](../../../replay-release-result-error.py)
переиспользует готовый bounded mapper harness, но с новым ENTRY 0x145814800,
новым FString ASCII constructor 0x141426a30 и полным SHA нового EXE.
Полные native вызовы 0 / 1 / 16 / 58 дали соответственно Success /
**InvalidPacketVersion** / InvalidState / BlockedIp. Сохранены достигнутые
инструкции и literal bytes; constructor — ограниченный fixture.
Первый отчёт `9cf65b97…` сохранён; после добавления явного historical source
API общий harness перечитан с тем же поведением. Актуальный отчёт `result-error-replay/7ae5b3da2cb51deda2e29775b7226d39cc34f9544e35d25ad87b4b94df3add5b/manifest.json`.
Runtime теперь сообщает для 1 «Несовместимая версия игровых пакетов».
Сам ключ не указывает конкретное отклонённое поле и не доказывает причину.

## Конкретное расхождение compiled строки

В успешном HK-захвате поле Login +0x110 не совпало с прежней строкой бота.
Значение из захвата не публиковалось до проверки наличия того же ASCII literal
в текущем EXE. Прежнего literal с NUL в новом источнике нет.

Ghidra candidate Version_Prepare 0x1467cfd30 выгружен попарно:
`details/run-56062ef20a38/details.json`, SHA256
`93787c26752347f476463f92ecf99d4b6f0a038f72dd2b1b43b9e81dbb85fb0d`.
На 0x1467cff6a инструкция читает pointer global 0x14b1bce98, затем вызывает
ASCII FString constructor и копирует результат в поле пакета.

| Источник | Старый EXE c7552efd… | Новый EXE 98802d55… |
| --- | --- | --- |
| Pointer global VA | 0x14b14ae28 | 0x14b1bce98 |
| Pointer file offset | 185899560 | 186362008 |
| Pointer bytes | 30ec904901000000 | 401f964901000000 |
| Literal VA | 0x14990ec30 | 0x149961f40 |
| Literal file offset | 160487472 | 160827200 |
| ASCII tag | AC7F34E3AFA91ED417BE86CD45BF18C8 | 32283C4C6485307BCF524765A84409C3 |

Это публичная compiled-константа, не credential аккаунта. Имя «compiled tag»
сохранено: алгоритм получения и значение формата не установлены, строка не
объявляется SHA / device ID только по виду 32 hex characters.

[replay-release-compiled-tag.py](../../../replay-release-compiled-tag.py)
исполняет actual slice 0x1467cff6a..0x1467cffc1 на четырёх заполнениях объекта:
pointer read → ASCII FString → копирование выходного descriptor / UTF-16 данных.
FString storage, allocation и проверенный CRT memcpy — fixtures. Guards сохранены.
Старый source snapshot используется только для ранее установленного pointer /
literal binding, адреса не применяются к новому EXE.
Отчёт `compiled-tag-replay/fa03e8e7ddb7591d31b410c780c4c93c9b36c4c4ab7490c361285547ad998126/manifest.json`.

Тот же инструмент использует готовый capture inspector с in-memory consumer:
после проверки SHA / исходящих CRC сравнивает suffix Version ID 1 и строго
декодированное поле Login ID 3 с публичным literal нового EXE. Оба совпали.
Consumer не добавляет raw body / credentials в отчёт. Полный native Version
preparation, serializer и runtime overrides этим slice не исполнены.

## Исправление профиля и ограниченная проверка списка

Game source profile теперь возвращает compiled_tag после проверки SHA EXE,
а также pointer bytes / literal bytes по проверенным offsets выбранной версии.
Он сохраняет связь old source → old tag и new source → new tag. Бот передаёт
его в Version builder и Login builder; mixed Version / expected tag отклоняется.
Старый default остаётся только для прежних явных API-вызовов / fixtures;
реальные runners передают tag из выбранного профиля. Смена AppVersion и SDK
профиля сама по себе больше не оставляет прежний tag в Game Login.

Добавлен явный режим `--read-character-list`. Только после успешного Login
caller разрешает list entry в существующем GameConnection / CharacterSelectionFlow,
затем отправляется ID 101 и ожидается ID 102 с отдельным timeout / лимитами.
Это диагностическое разрешение владельца, а не полное воспроизведение UI gates
игры. При отказе Login список не отправляется. Character selection и готовность
мира этим флагом не заявляются. Проверены socketpair: последовательность
Version → Login → List на одном сокете, отказ кода 1 без List и отказ самого List
без выбора / retry. В summary нет значений персонажей / credentials.

Один исторический native regression test сначала остановился на guard
«Client changed»: он пытался читать установленный новый EXE старыми адресами.
API исторического replay и двух mapper replays получили явный source_snapshot;
тесты теперь выполняют
полностью те же старые cases / fragments на immutable snapshot с прежним SHA,
сравнивая весь отчёт с поправкой только на source path и SHA самого инструмента.
SHA guard сохранён; текущий source этим не объявляется совместимым со старым reset.
Все три исторические regression-проверки прошли на своих pinned snapshots;
прежние отчёты не перезаписаны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-result-error.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-compiled-tag.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_compiled_tag.py -v
```

## Live результат

Первый запуск нового list option остановился на NameError до вызова игрового
exchange: флаг не был передан в _after_lobby. Ошибка исправлена, добавлена
проверка передачи флага через весь callback path. В том запуске SDK / лобби
выполнены, игровой сокет закрыт до отправки Version / Login.

Затем выполнены две ограниченные проверки с новым tag и неизменными
ClientVersion 261105 / Franz 2 (256 / 253) / языком 1 / launcher flow /
partial metadata 219 байт. Перед каждым входом получены свежие GMC2 / CDN.
Официальный клиент на ПК не работал, фиксированные ключи не заменялись.

| Выход | GMC2 snapshot | CDN snapshot | Game Login |
| --- | --- | --- | --- |
| samsung SM-A205F / JP | e32ffc682b86669caceec9c3d1f224def8058845995c2be504111c97782e7a56 | 531a9756980f46c6f90aa2396d0b0e502d3a969d91b4c7ee59fe9f9ce03894d5 | 16 / InvalidState |
| Redmi M2103K19Y / HK | 71d3dcc093a16af29d4e0a270ff86258aaf787e42e5bee9ce593cbb7d28d8cc2 | 59fefcbf8325fc33f3e87ab960da1f6e46fe2b0dfe63b49f5c3423bc7a60638a | 16 / InvalidState |

Каталоги snapshots расположены непосредственно под
`F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/` и
`F:/PhoneExit Resources/Vampir/public-cdn-snapshots/`; каждый содержит manifest.json.
Для HK geoIp.isoCountry свежего SDK response также подтвердил HK.
Обе попытки: SDK принят, joined country аккаунта HK; лобби IDs 2 / 104 / 4
имеют code 0, 55 групп / 98 серверов, 766 отправленных / 11466 полученных байт.
Лобби оставалось открытым во время игрового обмена. Game Version code 0;
LoginResult code 16, body 131 байт, send 860 / recv 94, счётчики полные,
других packet IDs нет. List не отправлялся; character selection не выполнялся.

Таким образом, код 1 после исправления не повторился; найденное расхождение
устранено. Общая причина InvalidState не установлена. Один переход JP → HK
при том же частичном контексте не устранил отказ; это не доказывает равенство
IP, телефона и состояния с успешным HK-захватом официального клиента.
Metadata 792 против 219 байт остаётся отличием, но её обязательность и источники
всех недостающих полей не подтверждены. Новых попыток с тем же контекстом нет.

Machine-captured sanitized runner summaries:

- `F:/PhoneExit Resources/Vampir/live-login-observations/2d6f118ef5e632bafa8c48535b845408f56948c19f4a83f64d68716a22d555e5/manifest.json` — JP.
- `F:/PhoneExit Resources/Vampir/live-login-observations/561ac8e2ef93bfa20ff86cee7cd17a592acf6d6d1dec1610ca0fd6682377972b/manifest.json` — HK.

SHA256 каждого manifest совпадает с каталогом. В отличие от первого summary
кода 1 они автоматически сохранены из returned result, но raw packet bodies,
credentials / device keys / account IDs / runtime constants по-прежнему не
сохраняются. Временные route helpers завершились штатно с code 0, listener
17948 закрыт. Самостоятельный runtime, получение списка / выбора / позиции и
универсальное обновление всех полей клиента остаются незавершёнными.

## Дальше

Сопоставить подтверждённые источники оставшихся полей Game Login и NID metadata
с успешным текущим HK-захватом. Отдельно проверить равенство фиксированных
идентификаторов без их вывода и ранние сообщения до Login; наличие пакета само
по себе не доказывает его обязательность. Следующий сетевой эксперимент — только
после конкретного обоснованного изменения, без копирования сессионных значений.
