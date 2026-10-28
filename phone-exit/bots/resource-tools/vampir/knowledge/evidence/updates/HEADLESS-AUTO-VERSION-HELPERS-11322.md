# Автоматические helpers Version 20 → 22

Target EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Reviewed база каждого нового семейства 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Контексты, proof, native reports, повтор и измерения перечислены в
[AUTO-VERSION-HELPERS-11322.json](AUTO-VERSION-HELPERS-11322.json).

## Области native-проверки

| Семейство | Roots | Сценарии |
| --- | ---: | ---: |
| NM provider / device getter | 2 | 36 |
| CPU formatter / getters / trim | 6 | 72 |
| Windows suffix | 1 | 48 |
| String combiners / copy / append / grow | 5 | 256 + 2 overflow |
| Platform selector / store / lookup | 3 | 116 |
| Prepare с NM | 4 | 64 |
| Prepare с NM / CPU / Windows | 11 | 64 |
| Prepare с предыдущими helpers и combiners | 16 | 64 |
| Prepare с предыдущими helpers и platform | 19 | 288 |

Итого 1008 строк сценариев и две отдельные проверки переполнения. Roots и
исполнение пересекаются между standalone и integration уровнями; эти числа
не означают независимые функции или доказательства целого входа.
Отдельная готовая base-prepare suite не запускалась повторно. Её caller / constructor
исполнялись внутри новых integration сценариев для проверки совместного поведения.

NM исполняет provider wrapper и getter с тёплым кэшем, сохранённым значением,
отказами чтения / разбора / записи и генерацией fixture GUID. Storage descriptors
инициализируются искусственно; реальные пути registry, GUID и идентичность
пользователя не читаются. Диагностическая ветвь отключена в памяти эмулятора.
Её call links и литералы сохранены статически, logger bodies не подтверждаются.

CPU исполняет formatter, два getters и trim wrapper / start / end. Vendor и brand
buffers заполняются синтетически. Compiled третий ввод — `Unknown`: проверена
исполняемая ветвь двух значений, альтернативные ветви не объявляются покрытыми.
CRT whitespace, formatting, strings, allocation / shrink / memmove остаются fixtures.

Windows исполняет suffix helper с вариантами synthetic TLS guard / epoch,
успехом / отказом version API и двумя заданными наборами полей версии.
Импорты GetNativeSystemInfo / GetVersionExW проверены как KERNEL32.dll; iswspace
и memmove / memset закреплены по фактическим DLL / names. API и CRT bodies
не вызываются, реальные сведения об ОС и оборудовании не получаются.

Combiners проверяют строки, пустые и выделенные descriptors, spare capacity,
передачу владения, Unicode, embedded NUL, cleanup и переполнение. Allocation,
internal copy, size quantization и overflow handler остаются именованными fixtures.
Copy boundary — точный E9 к проверенному memcpy с 11 CC padding bytes;
quantize — ограниченное тело с явно проверенным manager input и padding.
Эти заменяемые тела не исполняются и не разрешают произвольный virtual dispatch.

Platform исполняет selector / store / lookup, включая cache cold / warm / absent,
пустую платформу, отрицательный count, отсутствующее и повторное значение.
Литералы платформ и `ENnOsType` проверяются отдельно. FName construction / equality,
reflection factory, store resolver и value-at остаются fixtures; их реальное
поведение по строкам и enum не подтверждено. Integration использует девять
готовых platform сценариев вместе с NM / CPU / Windows / combiners.

Все verifiers проверяют Win64 ABI, включая R13 и XMM6–XMM15. Сохранены проверки
памяти, canaries, владения и очистки. Допуск отчёта сверяет точную уникальную
матрицу и native flags каждого уровня; число строк без полного покрытия недостаточно.

## Перенос и зависимости

Два pure rule modules сравнивают целые инструкции и ветвления, caller / callee
constraints, типизированные RIP inputs, bounded literals, imports и границы fixtures.
Seed получается из независимо проверенного base Version caller того же target SHA.
Похожий CPU getter разрешается прямым call edge; близость адресов не используется.
Новые адреса не дописываются в Python по номеру выпуска.

Общий `version-helper-v1` обслуживает девять отдельных ролей. Последняя база,
proof, semantic report, plan / context / check stages и publication index принадлежат
каждой роли отдельно. Integration сравнивает собственную reviewed базу и её helpers
с новыми independently proved contexts; более свежая база другого семейства
не подменяет это сравнение. NM / system / combiners / platform добавляются последовательно.

Активный fixture не может перекрыть исполняемый root другого семейства.
Делегированные outer roles должны точно совпадать с native helper roles.
Неизвестные optional native scopes, неверный budget / type, конфликт SHA одного
export run и неоднозначная связь дают блокер до исполнения / публикации.
19 roots разрешены только в полном platform integration layout; общий budget
harness и frozen engine не расширялись.

Plan cache включает только фактическую цепочку баз / proof / exports выбранной
роли, target dependencies, правила и нужные verifiers / fixtures. Внутри frozen
прохода общая подготовка seed и PE images переиспользуются; SourceStore проверяет
полные SHA до / после. Same-target повтор сохраняет исходный proof без self-transfer.
После успешного отчёта атомарно обновляется отдельный
`knowledge/generated-version-helpers/<family>/index.json` в библиотеке ресурсов.
Эти индексы не являются runtime profiles и не заменяют admission contracts.

## Пакет и повтор

Единый request содержит 19 roots. Два base roots уже имели готовые exports;
остальные 17 собраны одним Ghidra пакетом в прежнем проекте. Полный EXE analysis
не запускался. Два субагента подготовили transfer rules, третий — case contracts
и общие тесты. Независимая проверка нашла три закрытых admission gaps; регрессии
подключены к штатному aggregate из 215 тестов.

Каждая новая suite выполнена один раз. Два повтора не запускали native или JVM;
последний повтор девяти семейств использовал 27 этапов кэша. Общий проход всех
15 drivers переиспользовал 45 этапов, без повторного исполнения готовых suites.
Selected driver timings не включают предварительный сбор exports и полный аудит
установки; результаты относятся к сохранённым snapshot SHA.

Правила зарегистрированы в [native-check-adapters.json](../../native-check-adapters.json)
и применяются обычным `update --auto`. На следующем SHA нужны новые source-bound
доказательства; неизвестный layout или реальные изменения остаются явным блокером.

Остаются Login metadata и настоящий SDK backend / provider effects, остальные
response readers / handlers / registration / composition, clock / heartbeat и world.
Полный вход 1.13.22 и онлайн-квесты этим пакетом не допускаются. Игровые команды,
авторизация и переключение текущего профиля не выполнялись.
