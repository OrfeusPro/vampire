# LoginResult: автоматическая проверка регистрационного helper

30 октября 2026. Источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
База роли 1.13.18:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Машинные доказательства, reports и замеры](AUTO-LOGIN-REGISTRATION-11322.json).

## Проверенная область

`registration-v1` / `login-registration` связывает текущие проверенные nested
и whole-handler contexts с 75-байтовым окном регистрации и целым helper.
Окно owner `0x1467b8040`, адрес `0x1467b80b4`, проверяется статически:
allocation → packet constructor → handler table → registration helper.
Большая функция owner не выгружалась целиком и не исполнялась фрагментом.

Helper `0x1467cebc0` исполняется целиком: 101 инструкция, 395 байт, 11 calls.
Native ID getter `0x141453ca0` возвращает 4; таблица packet `0x149929050`
и handler slot `0x149dc93d8 + 0x10 → 0x14679e320` проверены по данным EXE.
Оригинальная тройка owner / packet / handler и ID наблюдаются перед изменением
outpair fixture. После вызова insert ветвление использует байт статуса outpair,
а не RAX или прежнее содержимое handler.

34 сценария: шесть ненулевых статусов (1, 2, 255 × два poison) и 28 diagnostic
вариантов (семь имён × null/non-null current pair × два poison). Имена покрывают
null pointer, count 0 с игнорируемым указателем, пустую строку, ASCII,
`Ж界🙂`, 127 и 128 ASCII bytes. Native helper сканирует UTF-16 до NUL;
count 1 для длинных строк проверяет, что count не подменяет длину сканирования.
Граница UTF-8 с NUL 128 / 129 bytes различает stack и heap fixture.
Сверяются точные calls / аргументы / порядок, ABI, неизменность входов,
canaries, logger line `0xb27`, temporary и current-pair cleanup.

Запрос выделения packet в регистрационном окне — **344 байта (`0x158`)**.
Прежние reader / handler / composition стенды резервировали **352 байта (`0x160`)**;
это проверочный storage extent, а не аргумент запроса allocation клиента.
Фактическое округление размера внутри allocator этим не устанавливается.
Новый контекст хранит `packet_allocation_bytes` и `packet_bytes` раздельно,
helper проверяется с canaries непосредственно вокруг 344 bytes. Исторические
contexts и reports не переписываются; отдельный packet constructor тут не исполняется.

## Границы fixtures

Реальный container insert `0x1467b77e0` остаётся fixture. Ненулевой synthetic
статус не доказывает фактическое добавление в контейнер или доставку packet.
Виртуальный name getter также fixture: возвращает внешний FString descriptor
через RAX и сохраняет RDX outparam. Поэтому free текущего outpair означает
`insert_out_pointer_preserved_by_name_fixture`; владение реального getter
и освобождение исходного packet этим не подтверждаются.
UTF-8 length / conversion, diagnostic allocation / free, logger и security
имеют явные fixture контракты. Null allocation branches окна проверены
статически; безопасность реального OOM не доказана.

Native owner / window / packet constructor / handler / insert backend /
name getter / dispatch / session здесь не исполняются. Их самостоятельные
reports и текущая reader→handler композиция не расширяют этот scope.
Профиль и игровая сессия не менялись, сеть не использовалась.

## Перенос, обновление и кэш

Правило нормализует весь helper 18 → 22 с relocated calls / RIP data,
проверяет уникальный constructor xref, все 75 bytes окна, actual allocation,
handler table, native ID leaf, cookie и typed literals. Fixture entry boundaries
привязаны к целевому SHA; их неисполненные effects не объявляются неизменными.
Проверенные целевые nested / full-handler proofs и reports входят в dependencies.
Missing export, повреждённое evidence, другой layout, несколько окон или
изменённый контракт дают блокер. Готовые прежние suites не повторяются.

Семейство добавлено в [native-check-adapters.json](../../native-check-adapters.json),
`update --auto`, resumable journal и publication cache. После новой публикации
база этой роли выбирается по её собственному proof. Указатель результата —
`generated-login-registration/index.json` в библиотеке ресурсов.

Независимая ревизия сверила native/static границы, fixture ownership,
allocation/storage и контракт adapter→rule. До native приёмки исправлены
классификатор direct/virtual call sites и имя `handler_pointer`;
регрессионные тесты включены в общий автоматический набор.

Штатный tooling check первоначально прерван лимитом 180 секунд при параллельном
анализе; отдельный запуск того же набора прошёл 602 теста за 141.220 секунды.
Для выросшего набора лимит поднят до 600 секунд, состав проверок не менялся.
Исходный timeout report сохранён; итоговый штатный report имеет новый cache key.

Пройдено тестов общего набора: 602; 34 новых native случая прошли.
Первый проход семейства с новым native доказательством: 1037.366478 с.
Два повтора семейства не запускали native / JVM; последний использовал 3 этапа и одну publication receipt, 38.808568 с.
Первый общий проход 26 drivers: 829.252635 с; тёплый: 77.785473 с.
Оба использовали 78 готовых semantic stages без native replay и JVM.
Тёплый проход: publications reused 26, полных publish/transfer 0, PE rebuild 0.
Prepare/collect переиспользовали три функции из двух готовых exports; missing 0, Ghidra не запускался.
Byte SHA 42 инструментов / contexts совпали с результатом Git checkout.
Замеры относятся к выбранным drivers; глобальная сверка исторического индекса учитывается отдельно.

## Остаток

Нужны real container insert, native name getter / ownership, lookup и dispatch
с доставкой packet в reader / handler. Интеграции post-state / continuation,
clock / heartbeat, world и настоящий SDK backend остаются открытыми.
Целый онлайн-вход этим пакетом не допускается. Глобальный аудит исторического
индекса, устранение повторных проверок child proofs при холодной публикации
и ordered-pair input seed — отдельные инфраструктурные задачи.
