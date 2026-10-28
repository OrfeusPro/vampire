# Автоматический перенос string writer 20 → 22

28 октября 2026. Target 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Baseline 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
[Машинная квитанция](AUTO-STRING-WRITER-11322.json).

## Результат

Общий `string-writer-v1` переносит целый FString writer и связывает его с уже
подтверждённым UTF-8 context целевого SHA. Native execution завершился успешно:
228 случаев, включая UTF-16 / NUL / count gate, короткие и длинные строки,
inline / heap branches, четыре archive return values, очистку, canaries и Win64 ABI.
Проверяются все GPR nonvolatile и XMM6–XMM15. Allocator, free, security и archive
остаются явными fixtures; их реальное системное поведение не доказано.

Writer переместился `0x144aad3d0 → 0x144aad400`. Сверены все инструкции / границы /
ветвления, порядок и offsets внешних вызовов, повторные allocator / memcpy роли,
отсутствие alias fixtures с исполняемыми функциями. Cookie определяется по PE32+
load config и соответствующей RIP-инструкции; target bytes сохраняются в proof.
Пустая UTF-16 константа сверяется по данным. Оба error calls должны использовать
один IAT slot с точной DLL / symbol; archive dispatch остаётся `[rax + 0x28]`.

`cpp_allocate` и `cpp_free` — проверяемые leaf tail thunks, без собственного unwind.
Они не выдаются за экспортированные или исполненные native roots. Их ограниченные
формы и targets проверяются отдельно; остальные fixture targets требуют unwind root.
Неизвестные layouts, branches, aliases, imports и изменённая форма дают блокер.

## Подключение к обновлению

Правило зарегистрировано в [native-check-adapters.json](../../native-check-adapters.json).
Штатный `update --auto` вызывает driver после публикации UTF-8. Driver использует
тот же Journal, общий кэш и последовательный missing-only Ghidra collector.
Для этого пакета понадобились только два новых root exports; готовый length
и прежние baseline exports повторно использованы. Проект Ghidra также переиспользован.

Подтверждённый context публикуется в `knowledge/generated-string-writers/index.json`
библиотеки и становится последней базой string-writer для следующего патча.
Каталог функций импортирует его реальные exports. JSON index остаётся указателем,
а context / semantic check — неизменяемыми квитанциями. До atomic publication
проверяются source, scope, context SHA, число сценариев и guards.

Старый UTF-8 proof engine и его harness не изменялись: добавление другого
семейства не потребовало повторного исполнения 222 готовых UTF-8 сценариев.
Ключи нового пакета зависят от выбранных baseline / exports / registry / tools,
target UTF-8 и semantic context. Несвязанные записи mutable index не меняют ключ.
Повтор того же target использует прежний proof, без цепи target → тот же target.

## Проверки и остаток

Изолированно выполнен реальный штатный driver с Journal и существующей базой:

| Проход | Время | Reuse | Native suites | Новые JVM |
| --- | ---: | ---: | ---: | ---: |
| Первое выполнение writer | 27,824 с | 0 | 1 | 0 |
| Повтор после publication | 12,238 с | 2 | 0 | 0 |
| Неизменный повтор | 12,093 с | 3 | 0 | 0 |

Получение двух missing exports было отдельным `prepare → collect` до этих проходов.
Тайминги относятся к выбранному driver, а не к полному аудиту установки.
25 новых synthetic tests проверяют отрицательные случаи, кэш и публикацию;
агрегат automation — 67 tests. Каталог / его adoption и экспортные проверки прошли.

Обновлён только offline слой исследования. Профиль / admission игрового входа
1.13.22 не назначен, игровые команды и авторизация не выполнялись.
Следующий общий пакет — archive IO и целые Version / Login wire writers, затем
остальные preparation / response / session контракты. Старые сценарии без
изменения входов повторять не нужно.
