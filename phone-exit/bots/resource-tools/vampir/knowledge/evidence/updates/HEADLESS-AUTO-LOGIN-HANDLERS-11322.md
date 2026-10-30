# LoginResult: continuation, ранние ошибки и повтор публикаций

30 октября 2026. Источники 1.13.20 → 1.13.22:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c` →
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинные отчёты и измерения](AUTO-LOGIN-HANDLERS-11322.json).

## Новые области

| Семейство | Native roots | Сценарии | Проверяемое поведение |
| --- | --- | --- | --- |
| `login-continuation` | 2 и getter leaf | 8 | Constructor, singleton / vptr и final virtual reset |
| `login-handler-early` | 1 | 14 | Whole handler на ошибках 54, 9818, 9819 и 90021 |

Continuation проверяется для уровней 0 / 1 / 2 / 5 и capacity 128 / 256.
Контракт сверяет точные значения полей, порядок helper calls и stores с размерами,
значениями и относительными offsets. Проверяются base / final vptr конструктора,
getter → singleton и reset в virtual slot +0x28. GPR, XMM6–15, RSP и canaries
сохраняются. Engine / container / allocation / cleanup helpers возвращают fixture
zero; непустые destructor loops и реальные helper effects остаются открытыми.
Factory и handler anchors доказывают только статические связи.

Ранние ошибки проверяются при двух заполнениях памяти, с присутствующим либо
отсутствующим optional object. В отчёте сверяются действия, порядок и call offsets;
аргументы проверяются внутри fixtures. Packet 352 байта, optional object и guards
не изменяются; ABI сохраняется. Localization / строки, logging, popup, lookup,
actions и finalization остаются fixtures. Stored callbacks не вызываются.
Result gate и успешная ветка Login этим семейством не исполняются.

Оба verifier требуют checked context и source-bound transfer proof перед native
исполнением. Неизвестная область, дополнительный root или fixture, заменяющий
исполняемый код, отклоняются. Native evidence не расширяет scope прежних reports.

## Автоматический перенос

Общий lifecycle хранит отдельные proof / report / publication indexes:
`generated-login-handlers/login-continuation/index.json` и
`generated-login-handlers/login-handler-early/index.json`. Новые роли подключены
к [штатному реестру](../../native-check-adapters.json) и `update --auto`.

Проверены полные инструкции / branches / calls, typed RIP inputs, pointer-table
alias partitions, singleton / flag, getter / call / handler anchors и fixture
boundaries. Материалы новых roots собираются единым missing-only заданием.
Ранний handler содержит и неисполненные ветки: их call links сохраняются как
статические данные, без semantic admission.

## Повторная публикация без повторного transfer

Новый `native-publication-cache.py` сохраняет отдельную immutable квитанцию только
после обычного полного adapter publish / validate. Первый проход не получает
ускоренный допуск по одному cached native report или строке индекса.

При повторе проверяются точные context / report pointers, source SHA, scope,
полная транзитивная цепочка proofs / contexts / reports / exports, tools, runtime
и выбранные publication rows всех зависимых семейств. Большие Ghidra JSON
сверяются по SHA без повторного разбора. Изменение чужой валидной строки индекса
не инвалидирует текущую роль; повреждение либо неоднозначность индекса оставляет
блокер. Отсутствующую запись восстанавливает обычная полная публикация.

Перед завершением прохода повторно проверяются файлы, выбранные rows, сама
квитанция кэша и её указатель, инструменты и runtime. SourceStore выполняет общий
полный барьер исходных EXE, без чтения одного EXE заново для каждой роли.
Прерванный или изменившийся проход не сохраняет новую доверенную квитанцию.
Только после всех барьеров публикуются новые validation receipts.

Готовые proof engines и сценарии прежних семейств не менялись. Это ускорение
повторной проверки сохранённых доказательств; native-сценарии и runtime admission
оно не заменяет. Поле `publication_cache.seconds` измеряет весь интервал cache
Session, включая этапы driver; это не отдельный таймер одного publish.

Зарегистрированный tooling набор: 399 тестов passed. Новые 8 + 14 native
сценариев прошли с исправленным эталоном; два повтора не запустили native либо JVM.
До этого строгий oracle отклонил два отчёта из-за ошибочного выбора shared helper callsite.
Два диагностических прогона сохранили фактические rows; выбор веток независимо сверен
со старым export 20. После изменения oracle повторены только новые 22 случая.
Последний повтор двух ролей: reused 6, publication reused 2, 3.736167 с.
Общий проход 21 drivers с первым заполнением publication cache: 249.984057 с;
повтор тех же 21 drivers: 45.973637 с, ускорение 5.44 раза в этом замере.
В обоих общих проходах 63 semantic stages переиспользованы, новых JVM / native нет.
В тёплом проходе publication receipts reused 21; полных publish/transfer 0.
PE images rebuilt 0; исходники по-прежнему читаются по полному SHA и проверяются финальным барьером.
Холодный publication проход включает прежний полный publish и создание новых квитанций;
это сравнение двух режимов одной и той же группы, а не обещание времени будущего патча.
Три субагента подготовили pure rules, case contracts и publication cache. Независимая
ревизия обнаружила и закрыла пробел повторной проверки cache receipt / lookup после
чтения. Регрессии проверяют обе подмены. Координатор выполнил интеграцию, collection,
native acceptance, общий повтор и фиксацию доказательств.

## Следующие пробелы

Полный LoginResult handler, result gate, registration, post-state и композиция
остаются отдельными областями. Для post-state wrapper и его tail target сохранён
общий явный набор; адреса кандидатов и нужные материалы перечислены в квитанции
подготовки следующего пакета. Clock / heartbeat, world и настоящий SDK backend
сохраняют свои ограничения. Текущая игровая сессия, профиль и вход не менялись.

Глобальная integrity сверка исторического индекса остаётся отдельной задачей
ускорения. Метрики выбранных drivers не включают prepare / collect и полный
аудит установки. Счётчики сценариев и consumers не означают подтверждение целого
входа или число полностью доказанных функций.
