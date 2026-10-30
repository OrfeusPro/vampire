# Общий result gate и post-state: автоматический перенос

30 октября 2026. Целевой источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Базы выбираются отдельно: gate — проверенная 1.13.20
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`,
post-state — проверенная 1.13.18
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Квитанции, проверки и замеры](AUTO-RESPONSE-11322.json).

## Что проверяется

| Семейство | Roots | Сценарии | Область |
| --- | --- | --- | --- |
| `result-gate` | 1 | 16 + 227 | Полные вызовы над state/error fixtures и выбор каждого index |
| `login-post-state` | 2 + getter leaf | 44 | Wrapper, tail callee, class checks, branches и service slot |

Gate является общим для VersionResult и LoginResult, но эти handlers в новом
семействе не исполняются. 16 полных вызовов покрывают восемь кодов × два state
flag: 0, 1, 42, 58, 708, 1304, 0xffffffff, 0x1197. Проверяются low AL, действия
fixture services с аргументами / call offsets, GPR / XMM6–15 / RSP, state и
24-байтовый temporary с canaries. Raw RAX не называется кодом успеха.

Для каждого из 227 index inputs настоящий код выполняет двухуровневую
byte-index → RVA → branch адресацию. Исполнение останавливается перед выбранной
веткой: её native effects и ABI возврата этим случаем не подтверждаются.
State/error services — явные fixtures. Наличие generic gate не даёт допуск
полного ответа, SDK / сети или игрового входа.

Post-state покрывает 32 сочетания mode / predicate / fallback / list-match /
eligible, восемь wrapper boundaries и четыре прямых вызова target. Проверяются
точные events / writes / field values, tail entry и stack, receiver/argument
контракты, canaries и сохранность GPR / XMM6–15 / RSP. Wrapper выполняет настоящий
getter, lookup / class checks и tail в callee. Actor, service, class arrays,
backend и virtual methods являются fixtures. Реальные containers / engine
callbacks / CharacterListRead / успешный Login не подразумеваются.

## Границы кода и данных

Gate unwind содержит 1047 байт кода (251 инструкция), один padding byte,
четыре 32-битных RVA и 227 байт индекса. Специальное правило сверяет эти области
раздельно, точные dispatch / range guard / PE base, internal branch targets,
полный export с coverage flags, call/RIP роли, typed inputs и table aliases.
Две indexed displacements переносимы только как адреса именно этих таблиц.
Остальные инструкции проходят обычное полное сопоставление. Inline data не
попадают в native instruction allowlist. Изменённый layout или неоднозначный
кандидат остаётся блокером; near-address match не заменяет доказательство.

Post-state проверяет полные unwind bodies wrapper / target, единственный E9 tail
и модель tail в Ghidra export, source-bound getter / globals, exact fixture
boundaries и direct / virtual call roles. Отдельный синтетический virtual callback
не может перекрыть native root или leaf. Неподтверждённые fixture effects не
переносятся в runtime capability.

## Штатное обновление

Обе роли подключены к [реестру adapters](../../native-check-adapters.json),
`update --auto`, resumable journal и отдельным immutable proof / reports.
Указатели публикаций: `generated-responses/result-gate/index.json` и
`generated-responses/login-post-state/index.json` в библиотеке ресурсов.
Готовый target становится базой своей роли для следующего патча. Исторические
proof engines и доказательства прежних выпусков не переписывались.

Publication cache проверяет фактические pointers / reports / lineage / tools /
runtime и полный SHA каждого использованного EXE до и после работы. После
изменения списка зарегистрированных семейств его guard изменился: первый общий
проход создаёт новые квитанции публикации, без повторного исполнения прежних
native-сценариев. Тёплый повтор использует квитанции с проверкой целостности.
Метрики publication cache теперь сохраняются в `native_contexts.publication_cache`
обычного update journal, наряду с результатом Python API драйвера.

Зарегистрированный tooling набор: 472 тестов passed. Новые 243 + 44 native
сценария прошли; два повтора не запустили native либо JVM.
Последний повтор двух ролей: reused 6, publications reused 2, 4.114605 с.
Первый общий проход 23 drivers после регистрации: 246.945226 с;
тёплый повтор: 60.92297 с. Оба переиспользовали 69 этапов, без новых JVM / native.
В тёплом проходе publications reused 23; полных publish/transfer 0; PE rebuild 0.
Три source-bound roots уже находились в индексе: collect вернул reuse без Ghidra.
Последняя база каждой роли выбрана отдельно, source 18 не заменён неполным 20 context.
Три субагента подготовили typed gate, portable verifier/contracts и post-state пакет;
независимый обзор проверил boundaries, исключённые effects и raw-return oracle.
Координатор выполнил интеграцию, native acceptance и общую проверку кэша.
Byte SHA 29 инструментов / contexts дополнительно проверены после Git checkout.
Эти замеры относятся к выбранным drivers; скорость будущего полного обновления не обещается.

## Оставшиеся пробелы

Полный LoginResult success handler содержит новые действия с trailing FString
+0x140 и u32 +0x150 / +0x154. Для них нужны собственные predicate / apply /
cleanup сценарии, затем композиция с актуальным reader 352 байта / 28 операций.
Регистрационный owner/window, clock / heartbeat, world и настоящий SDK backend
сохраняют свои пробелы. Готовые exports и новые generic gate / post-state надо
переиспользовать по кэшу. Авторизация, игровые команды, назначение профиля и
текущая сессия этим offline пакетом не менялись.
