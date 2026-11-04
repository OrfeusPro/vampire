# Общий статический перенос readers квестов и обучения

Штатный обновлятор получил отдельное правило quest-reader-transfer-v1.
Оно готовит source-bound контексты QuestSync 1854 и Tutorial 9905 на новом
EXE: 15 новых основных функций связаны с семью готовыми INPUT-функциями.
Итого 22 уникальных основных функции. Подготовка статическая; исполнение
целевых пакетов, применение handlers и онлайн-допуск остаются открытыми.

## Источники и правило

База: d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960 (1.13.16).
Цель: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f (1.13.22).
[Reviewed rules](../../quest-reader-transfer-rules.json) закрепляют SHA
двух исходных contexts, роли, точные call offsets / RIP refs, девять leaves,
13 таблиц и fixture boundaries. Целевые адреса в правило не вписаны.
[Selector](../../quest-reader-transfer.json) включает этап обычного update.

Правило использует готовый упорядоченный INPUT seed с отдельно проверенным
VersionResult цели. Семь уже готовых функций и его native suite повторно
не разбираются. Все исходные roots сверяются с целыми SHA-bound exports
и точным EXE; целевые инструкции берутся из точного PE / unwind span.
Кандидаты ограничены размером и окном поиска, полными инструкциями,
ветвлениями и согласованными direct / RIP links. Неоднозначность остаётся
конкретным blocker; перенос по одной адресной дельте не применяется.

Цикл массивов имеет уникальный whole-shape candidate. Общий packet reader
имел два похожих кандидата; связь через ID getter 1854 / 9905 и таблицы
обоих пакетов разрешила один и тот же reader. У constructors было по три
кандидата, у reserve wrappers — по 12. Их разрешили packet table и уже
связанные callees. Проверяются INPUT table +0x18 (vector), +0x68 (u16),
descriptor reserve / callback и используемые вложенные dispatch slots.

Девять leaves проверяются по исходным bytes, границам инструкций и точным
типизированным tails; RIP displacement переносится только по известным
связям. У 13 таблиц проверяются bytes, used slots и alias partition.
Неиспользованные table bodies этим не считаются проверенными. 12 storage /
cleanup / no-growth границ подтверждают только callable unwind entry;
их тела остаются fixtures. Memcpy отдельно подтверждает IAT import identity.
Fixtures не могут перекрывать исполняемые roots / leaves или менять alias
partition. Результат содержит 705 связей адресов — это не число функций.

## Приёмка и кэш

Готовы два статических target_contexts с functions / leaves / bindings /
fixtures. Они сохраняются внутри quest-reader-transfer-proofs-v1 библиотеки.
Это отдельные исследовательские контексты; native publication registry,
runtime SHA allowlists и профиль игры не менялись. Готовность target exports
не подтверждалась и записана как target_exports_verified=false. Целевой
packet harness и недостающие exact exports требуют отдельного этапа.

Журнал обычного обновлятора содержит quest_reader_transfer и одноимённый
stage. Он идёт после готового INPUT seed. Ключ включает точный seed proof,
упорядоченные source SHA / consumer pointers, reviewed rule, код, lineage,
runtime и aliases. При кэше сверяются SHA proof, package scope, root / leaf /
table / boundary inventory и все flags. Перед публикацией после SourceStore
и installed SHA barriers выполняются seed.finalize и reader.finalize.
Они привязаны к тому же владельцу и перечитывают выбранные материалы.

Настоящий компонентный проход: 18.385749 с, один новый static
transfer; INPUT seed взят из кэша. Повтор: 2.014346 с,
оба этапа cached, ноль transfer и новых PE builds. Оба завершили свежие
SourceStore, installed EXE SHA и final selected-file guards. Новых JVM,
native replay, полного CLI update, watcher и игрового входа не было.

## Проверки и оставшийся пакет

Добавлены 36 случаев: 20 orchestration / cache / owner / SHA-barrier,
11 целевых pure-rule проверок и пять ordinary update интеграций.
Pure tests используют настоящее сопоставление инструкций и Capstone с
синтетическими данными: ID/table anchors, ограничения callers, неоднозначность,
изменённые вызовы / RIP, alias topology и fixture entries. Реальная приёмка
отдельно проверяет точные сохранённые EXE. Общий набор: 1852 теста,
три прежних пропуска; шесть дополнительных checks прошли. Независимый
обзор реализации не выявил блокирующих ошибок.

Новое исследовательское правило оформлено prepare → collect → finish
по 15 исходным roots с готовыми exports базы 1.13.16. Машинная квитанция
переноса содержит оба полных SHA и доказательства целевого PE. Scoped fact
фиксирует правило базы; он не выдаётся за target native / export admission.
Сохранены 218 прежних facts базы, 51 fact текущего выпуска,
59 frozen native inputs и исторические разделы README / TASKS.

Дальше нужен общий proof-bound native harness для двух target contexts:
целые сценарии ID 1854 / 9905 с caller / memory / ABI guards и явными storage
fixtures. Затем отдельно QuestUpdate 1810 и handlers. 15 функций закрыты
по статическому переносу; native consumer semantics ещё не подтверждены.
Готовые семь INPUT mappings и 54 resource inputs / 247 hashes не повторять.

- [Машинная приёмка](AUTO-QUEST-READER-TRANSFER-V1-11322.json).
- [Исходный INPUT seed](HEADLESS-QUEST-INPUT-SEED-V2-11322.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
