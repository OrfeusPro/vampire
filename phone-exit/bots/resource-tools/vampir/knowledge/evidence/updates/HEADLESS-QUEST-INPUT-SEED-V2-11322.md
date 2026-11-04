# Общая подготовка входных readers квестов и обучения

Штатный обновлятор получил отдельный статический этап quest-input-seed-v2.
Он связывает семь общих primitive / buffer функций двух потребителей с
уже опубликованным и отдельно проверенным VersionResult INPUT текущего EXE.
Это подготовка source-bound контекста; новые native-сценарии пакетов,
семантика квестов / обучения и онлайн-вход этим этапом не подтверждаются.

## Источники и область

База: d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960 (1.13.16).
Цель: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f (1.13.22).
Selector [quest-input-seed.json](../../quest-input-seed.json) содержит точные
SHA и пути трёх контекстов: VersionResult, QuestSync 1854 и Tutorial 9905.
База каждой из этих ролей уже исследована на 1.13.16; старый release list
и OUTPUT archive-wire не используются как доказательство INPUT readers.

Проверяется равенство семи адресов потребителей ролям исходного VersionResult:
input constructor, buffer constructor, u16, u32, u64, bool и raw.
Штатное статическое правило переносит полную VersionResult closure между
точными EXE и сравнивает весь результат с независимо опубликованным target
контекстом. Проверяются экспорты, зависимости, поля, таблицы и source-bound
semantic receipt цели; готовые native-сценарии повторно не запускаются.
Полная relation из 803 связей адресов сохраняется в библиотеке доказательств.
Эти связи не называются 803 подтверждёнными функциями.

Два consumer contexts содержат 22 уникальные основные функции, девять общих.
Подготовлены семь общих функций. Остальные 15 основных функций, включая
vector loop и общий packet reader, остаются открытыми. Их дополнительные
leaves, callbacks, storage fixtures и зависимости требуют собственного
переноса и проверки; число 15 не означает полное число оставшихся задач.

## Штатный путь, кэш и финальная проверка

Этап выполняется после native drivers, используя их завершённые declaration
и passed outcome VersionResult. Он не сканирует историческую базу заново.
В журнале: quest_input_seed и stage native-input-seed-quest-tutorial-v2.
Доказательства: quest-input-seed-proofs-v2 библиотеки ресурсов. Ключ явно
различает упорядоченные baseline / target pointers и SHA, target check,
consumer contexts, lineage, инструменты, selector и фактический runtime.
Старая реализация login-input.seed и frozen engines не изменялись.

Кэш сверяет SHA выходного доказательства, точные inputs, mappings, inventory,
границы и flags; повреждение или неоднозначность дают конкретный блокер.
Оба EXE входят в SourceStore и его свежий конечный барьер. После полной
проверки установки, перед публикацией пакета, finalize перечитывает выбранные
материалы, код, runtime, selector и aliases. Он привязан к тому же владельцу
и SourceStore. Кэшированное доказательство остаётся неизменяемым.

Первый статический stage занял 20.842353 с и сохранился в durable
журнале. Измеритель приёмки сначала наблюдал другой экземпляр динамического
модуля; его неверный счётчик не отменил готовый результат. Приёмка продолжена
из сохранённого stage без повторного переноса. Два свежих прохода проверки
и кэша заняли 1.466203 и 1.452072 с:
по одному reused stage, ноль transfer, новых PE builds, JVM и native replay.
Оба прошли SourceStore, installed SHA и финальную проверку seed.

## Проверки и ограничения

Добавлены 24 теста helper и пять проверок обычного обновлятора. Проверены
источники и роли, неоднозначность, повреждённый / подменённый кэш, порядок
baseline / target, изменения lineage / кода / runtime, смена SourceStore,
позднее изменение доказательств и отказ до публикации. Эти проверки нашли
и закрыли пропущенную проверку кэшированного отчёта. Общий набор:
1816 тестов, три прежних пропуска; шесть дополнительных checks прошли.
Независимый обзор helper и финального hook не выявил блокирующих ошибок.

Положительный результат имеет state=prepared_static, method=static,
native_consumer_verified=false, runtime_activated=false и profile_activated=false.
Списки native checks / runtime SHA, текущая сессия, prepared-next и admission
не повышались. Полный update, watcher, Ghidra и вход не запускались.
59 frozen inputs, 50 прежних facts и исторические разделы сохранены.

Следующий общий пакет — vector / packet reader и оставшаяся closure
QuestSync 1854 / Tutorial 9905 с новым proof-bound packet harness.
После этого отдельно QuestUpdate 1810. Готовые семь общих mappings,
54 ресурсных inputs и 247 hashes повторно разбирать не нужно.

- [Машинная приёмка](AUTO-QUEST-INPUT-SEED-V2-11322.json).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
- [Исходный QuestSync](../../native-contexts/quest-sync-11316.json).
- [Исходный Tutorial](../../native-contexts/tutorial-update-11316.json).
