# Пакетное хэширование выбранных записей PAK

Штатное обновление дополняет хэши только неизвестных записей, совпавших с
объявленными зависимостями partial-контекстов карты, квестов и UI. Повторные
обращения разных потребителей объединяются по exact archive slot / SHA / offset.
Старые каталоги и индексы не переписываются, готовые decoded SHA не пересчитываются.

## Входы и ограниченный декодер

Selector resource-selected-hashes.json задаёт отдельный рецепт
selected-record-hashes-v1. Лимиты: 32 MiB stored / decoded на запись,
1 GiB decoded и 512 MiB stored на проход, не более 4096 уникальных записей.
Новый helper использует существующий SHA-checked reader и Oodle; перед его
запуском проверяет свежий header, все поля exact record, stored_record_sha256,
число blocks, положительные последовательные spans и их сумму. Чтения должны
быть точными и оставаться внутри проверенной записи. Plain size обязан
совпасть с decoded size. Шифрованные, слишком большие и отсутствующие в
линейном индексе записи сохраняют собственные причины fallback.

Результат содержит только decoded SHA и происхождение. Payload не сохраняется.
Ключ отдельной записи учитывает source SHA / size / slot, exact record index,
offset / sizes / stored SHA, reader / Oodle, правила, бюджеты и runtime.
Cache pointer назначается общим owner только после свежего барьера источников,
выходов, runtime и aliases. Тёплый повтор проверяет доказательства и исходный
архив заново, но Oodle для готового record hash не вызывается.

Однократный memo сохраняет общий результат для всех patterns и consumers.
Перед memo повторно проверяются source SHA и совпадение directory metadata
с точной индексной записью. Смена источника или размеров не может получить
прежний hash по одному offset. Повреждённый cache не перестраивается скрытно.

## Обычный update и текущий результат

Resource context keys запрашивают supplementary hash только у совпавших
записей без decoded SHA. Доказательства остаются отдельно от устойчивых
content keys и записываются в selected_record_hashes контекстного proof.
Код helper, selector, reader / Oodle и runtime входят в rule digest.
Prepared receipt содержит selected_hashes metrics. Новый helper и selector
подключены к definitions, aggregate on_update и обычному context_inputs.
Partial contract guard, semantic checks и runtime admission сохранены.

EXE: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f; ресурсный патч Revision268356.
16 прежних fallback inputs дали 486 обращений к 247 уникальным записям.
244 записи декодированы один раз; для трёх сохранён явный missing-index blocker.
Обработано 918580558 decoded bytes и 273194369 stored bytes.
Декодер выполняется последовательно; наибольшая запись укладывается в 32 MiB.

| Контекст | Inputs по содержимому | Fallback по архиву | Записей в суженных inputs |
| --- | ---: | ---: | ---: |
| game-ui | 17 | 1 | 27318 |
| map-data | 25 | 2 | 5345 |
| quests | 9 | 0 | 414 |

Итого 51 из 54 inputs используют точные выбранные файлы; 3 сохраняют весь PAK.
Прежние 38 готовых content inputs не требуют повторного разбора. Остались:

- Engine/Plugins/Developer/Concert/ConcertUI/ConcertSharedSlate/ConcertSharedSlate.uplugin
- Engine/Plugins/WorldMetrics/WorldMetrics.uplugin
- ProjectRED/Content/RED/NavMesh/TestNavData_Nav.bin

Все три имени есть в полном каталоге, но их offsets отсутствуют в сохранённом
линейном индексе. Два plugin records имеют обычные headers, третий файл пустой;
наблюдение header само по себе не заменяет зарегистрированное доказательство.
Следующий отдельный рецепт должен подтвердить directory → fresh header → bytes
и пустую запись; подставлять синтетическую индексную строку текущему decoder нельзя.

## Приёмка и кэш

Первый компонентный проход занял 52.529831 с: 244 decode, 0 hash cache hits.
Повтор занял 41.633936 с: 244 hash cache hits, 0 decode; три missing-index
blockers сохранены. Контекстные values совпали, свежие proof / owner receipts
отражают разные execution counters. В отдельном component-selected-hash-*
пространстве три диагностических requires_review этапа исполнены, затем
переиспользованы. Это не пропуск semantic checks и не допуск игрового профиля.

27 новых случаев: 23 decoder / owner / cache и 4 context integration.
Проверены header bounds и blocks, truncation, stored SHA, source identity,
metadata до memo, runtime, deferred publication, corruption и бюджеты.
Общий набор завершил 1735 тестов с тремя прежними пропусками; шесть
дополнительных checks прошли. Новых JVM, native replay сценариев, CSV extraction,
полного ordinary CLI update и игрового входа не было. Oodle используется
только для отдельного bounded resource decode, что учтено своим счётчиком.

Далее — три missing-index records и подтверждение полной runtime / data
closure перед применением к source_checks / builders. Девять исторических
unknown hashes, ближайшая prepatch named база и перенос legacy checks
этим пакетом не закрыты. Watcher / prepared-next / live session не менялись.
59 frozen native inputs, 47 прежних facts и исторические разделы сохранены.

- [Машинный отчёт](AUTO-RESOURCE-SELECTED-HASHES-V1-268356.json).
- [Ключи объявленных ресурсов](HEADLESS-RESOURCE-CONTEXT-KEYS-V1-268356.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
