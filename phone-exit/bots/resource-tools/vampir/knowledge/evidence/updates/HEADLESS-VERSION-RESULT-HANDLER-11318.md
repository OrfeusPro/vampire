# VersionResult 1.13.18: reader → handler → gate → Login entry

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Используется [готовый reader/input archive](HEADLESS-VERSION-RESULT-READER-11318.md).
Реального входа, сокетов или активации профиля не было.

## Код и inline data

Экспорт `run-450b89173dc1/details.json`, SHA256
`c4a61844217b6edda4cf4ebc7fdd639b0178ad28460927ef690be9122f14da1c`,
содержит whole handler `14679D680` (42 инструкции) и gate `1467CDC80`
(251 инструкция), с completed blocks/direct flow. Handler E9 связывается с
явно указанным Login prepare `1467CE500`; prepare здесь capture на входе.

Unwind диапазон gate содержит код до RET `1467CE096`, NOP `1467CE097`,
затем inline data. Поэтому линейное декодирование всего диапазона ранее
останавливалось на данных. Ghidra экспорт совпадает буквально со всеми 251
инструкциями ограниченного code диапазона `1467CDC80..1467CE097`.
Данные не объявлены исполняемым кодом и не игнорируются.

`version-gate-switch-11318.py` проверяет source SHA, unwind/code boundaries,
bytes dispatch и bounds, оба SHA таблиц и все targets:

- byte index table `1467CE0A8`, 227 значений 0..3, SHA256
  `80b46077930ed5c4209bac8836c3206d2cea4cc9687597d79612f82100069e54`;
- four-RVA table `1467CE098`, SHA256
  `7ac50e5a186878319d6d6ac853c5f3e006f2d98eca064c61198cc403bf958e56`;
- цели `1467CE065`, `1467CDE9F`, `1467CDFA7`, `1467CE065` находятся на
  границах подтверждённых инструкций;
- actual unsigned bound `code-0x519 <= 0xE2`, image base и две native
  table reads перед indirect JMP `1467CDE9D` закреплены exact bytes.

Все прямые branches замкнуты в code диапазоне. Единственный indirect jump —
объявленный switch. Прочие roots композиции проходят обычную проверку whole
unwind ranges. Это source-specific исключение для доказанных inline data,
а не отключение полноты анализа для произвольных функций.

## Регистрация и полная композиция

Bounded registration window `1467B515B..1467B51A4` статически связывает
constructor `1456D8070` / packet ID 2 и handler table `149DC8020`, slot+10
к `14679D680`. Проверяются исходные bytes/SHA/instructions, unwind owner,
constructor call и актуальная packet table. Сам dispatcher не исполняется.

В одной VM выполняются actual input constructors/reader, затем тот же packet
передаётся whole handler и native gate. Бюджет 19 roots сохранён; фактически
17 roots, без обхода остальных callees. 16 случаев: восемь result codes ×
два состояния gate. Проверяются потребление 17 байт, code projection, порядок
error/peer/Login calls, неизменность packet/guards и ABI.

Обычный code 0 достигает Login entry. При `0x1197` и state flag 0 native gate
сначала вызывает error service, затем возвращает true; handler вызывает
peer/Login entry. При flag 1 этот code не проходит. Поэтому допуск gate не
является server success. Строгий portable parser не ослаблен.

Дополнительно исполняются 72 варианта input buffer construction. Все 227
switch indices проходят actual gate comparison/index/RVA instructions; VM
останавливается на выбранном target до его внешних services. Это доказывает
выбор ветви, но не выполнение services сложных ветвей `0x523/0x524/0x5F1/0x5FB`.
Итого 315 случаев (16 pipeline + 72 construction + 227 dispatch).

Шесть unittest тестов прошли: старые регрессии и новые pipeline/switch,
неверная registration/source, повреждённые таблицы и пропавшая export instruction.
Подробный report в библиотеке ресурсов:
`knowledge/native-version-result-handler-checks/c52a84fe1f3ee1e0783fbe67ff3d6f107423a007ed9cdd47c7811295030aab39/manifest.json`.

## Автоматизация и ограничения

`native-version-result-handler-context` получил текущий SHA, source context,
зависимости и оба pinned exports; `on_update` сохранён. Reviewed handler
binding добавлен в Version contract; gate/handler scopes закреплены в target.
Старые contexts и source bounds сохранены.

Gate state getter, strings/log/error/peer services, input storage/copy/free /
security и Login prepare entry — fixtures. Никакие настоящие credentials или
сетевые данные не использовались. Registration static, engine delivery и
полная Login preparation/SDK/server acceptance не доказаны. Version coverage
остаётся partial до отдельного замыкания prepare→wire и остальных требований.
