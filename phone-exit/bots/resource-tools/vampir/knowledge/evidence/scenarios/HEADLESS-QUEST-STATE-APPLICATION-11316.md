# Применение прогресса к существующей задаче

Источник EXE 1.13.16 SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [статической связи модели](HEADLESS-QUEST-MODEL-BINDING-11316.md).
Сеть, память процесса и игровое управление не используются.

## Фабрика: статическое подтверждение

Factory `1455b8ff0` выбирает тип по byte `progress+8`. При успешно созданном
объекте четыре MOVUPS по `1455b9fec..1455b9ff9` копируют 32 байта progress
в `task+0x20..0x3f`. Поэтому index byte `progress+9` попадает в `task+0x29`.
Это общий участок после успешного создания, не гарантия результата allocator.
Fallback / null allocation, shared ownership и lifecycle требуют отдельной проверки.

Case 6 вызывает constructor `1455ab5d0`; он устанавливает table `149905340`.
У 23 явно проверенных task tables, включая этот тип и fallback, slot `+0x10`
содержит общий leaf `1455cec20`. Все ссылки проверены по точным байтам EXE.
Этот 16-байтовый leaf не имеет unwind root: его не передавали в collect как root.
Четыре MOVUPS копируют те же 32 байта, затем RET. Новые типы и обновления клиента
не получают этот контракт автоматически.

Exports: `run-8087d5072f02` (factory, 128 blocks / 1061 instructions),
`run-f6b719e56790` (case 6 constructor), `run-dee1f2864d6e` (state / progress).
Полные SHA закреплены в
`knowledge/native-contexts/quest-state-application-11316.json`.

## Native replay существующей задачи

`replay-quest-state-application-11316.py` вызывает целые `1455f4a80` и
`1455fd350` только с существующим task, чей key совпадает с progress key.
Virtual `+0x10` исполняет настоящий leaf `1455cec20`, не Python copy fixture.
После применения исполняется настоящий sender getter `1455e7510`.
Factory / constructor здесь проверены статически; их native execution не заявляется.

324 комбинации: keys 0 / 110120005 / UINT64_MAX; old/new state 0 / 2 / 255;
index 0 / 1 / 127 / 128 / 254 / 255; два выравнивания входа (0 / 3).
Проверены все 32 скопированных байта, guards, неизменность progress, единственное
изменение record state по `+0x28` и чтение index из `task+0x29` sender getter.
Необычные значения показывают поведение native кода, не разрешённые runtime ID.

Task callbacks `+0x28` / `+0x30` — явные fixtures. Они проверяют, что copy уже
состоялся, а record state ещё прежний. Переход old != 2 → new == 2 вызывает
первый callback, остальные сочетания — второй. После возврата state сохраняется.
Игровой смысл и эффекты callbacks не устанавливаются.

Тест `test_vampir_quest_state_application_11316.py` прошёл; offline check
`native-quest-state-application-11316` зарегистрирован с зависимостями и exports.
Артефакт:
`code-clues/quest-state-application-11316/ac49a6a439bf283f26198731b3cfb90053492c026ee67415bf49f8d2d6a3135c/manifest.json`.

## Уточнение сборщика Ghidra

Первый collect factory остановился до JVM: линейный Capstone scan unwind range
`1455b8ff0..1455ba488` не разобрал байты после `1455ba434`. Последний настоящий
RET в успешном Ghidra export — `1455ba40a`; хвост содержит данные switch.
Прежняя попытка не запускалась повторно без изменения входов.

Collector теперь при точной ошибке `Fragment not fully decoded` не использует
частичный prefix для tail models. Он отмечает `deferred_to_ghidra`; остальные
ошибки PE / unwind / budgets продолжают отклоняться. Ghidra проверяет blocks
в исходных явных unwind ranges, а export сохраняет linear_tail_scan metadata.
В реальной выгрузке покрытие блоков подтверждено, body 5090 байт, tail models нет.
13 тестов collector прошли, в том числе отказ при неполном Ghidra coverage после
deferred scan. Это уточняет необязательный preflight, не отменяет проверки экспорта.

## Следующий шаг и границы

Открыты whole factory / replacement, ownership cleanup, native callbacks,
загрузка / порядок таблицы задач и соответствие current QuestTask CSV.
Нет доказательства реального выполнения маршрута, диалога, skip или экипировки.
Online owner остаётся прежним; новые contracts / игровые команды не включались.
