# Ключи объявленных ресурсов незавершённых контекстов

Ресурсная часть контекстов карты, квестов и UI теперь может сохранять ключ
при изменении постороннего содержимого PAK. Правило ограничено точными
зарегистрированными partial contracts без builder и context checks. Оно
не сужает legacy semantic checks и не подтверждает готовность runtime.

## Что потребляется и что подтверждено

Selector resource-context-keys.json закрепляет fingerprint технической части
трёх contract declarations; purpose / limits / next_check в него не входят.
Смена checks, patterns, bindings или других технических полей возвращает
полный archive SHA. Даже с обновлённым fingerprint coverage=source_checks,
builder или context adapter запрещают применение partial-правила.

Полный текущий directory report принимается от того же открытого SHA owner:
проверяются source path / SHA, recipe, rules, runtime и авторитетность описи.
Неоднозначные имена отвергаются; path gaps и unmatched CSV дают fallback.
По объявленному pattern выбираются все совпавшие записи, включая uasset /
uexp и другие расширения. Схема CSV и имя похожей таблицы не используются.
Суженный ключ содержит archive slot, pattern и точные path / decoded SHA /
размеры совпавших записей. Полная опись без совпадений даёт пустой набор.

Если хотя бы у одной совпавшей записи нет проверенного decoded SHA, остаётся
прежний ключ по целому архиву. Неизвестные посторонние записи сами по себе
не расширяют объявленную зависимость. В частности, две большие текстуры
DailyQuestEvent не объявляются CSV; отсутствие их hash сохраняет fallback.

Это уточнение объявленных inputs частичного контекста, а не доказательство
полноты потребностей работающей игры. Проверки пакетов квестов / обучения
используют EXE и синтетические payloads, их отдельный cache не изменён.
Legacy map audit читает архив целиком; он не переписывался и не переносился
на текущий SHA. Его archive / atlas inputs и прежние границы сохранены.
В декларацию map-data добавлен World: он явно читается старым auditor
вместе с Map. Регрессионная проверка контролирует эту зависимость и guard.

## Обычный pipeline и защита публикации

После resource processing обычный update получает resource_inputs через
pipeline.context_inputs. При выключенном selector / неподходящем contract
действует прежний путь. Source SHA клиента, bindings, checks, зависимости
контракта и остальные входы его context / stage остаются в ключах.
Изменение нужного имени, payload или состава выбранных путей меняет ключ.
Новый EXE также меняет контекст независимо от совпавших ресурсов.

Свежие source SHA и directory pointers хранятся отдельно от стабильного
контекста в resource-context-key-proofs-v1. Включение этих pointers в сам
ключ отменило бы пользу сужения после постороннего изменения архива.
Код правила, selector и существенный Python runtime входят в rule digest.
Общий owner проверяет proofs, источники и aliases перед публикацией.

После owner barrier создаётся resource-context-key-receipts-v1. В журнале
обычного update поле resource_context_keys содержит receipt / proof / metrics;
копия находится в metrics.resource_pipeline.context_keys. До завершения owner,
при порче proof или смене источника новая квитанция не публикуется.
Проверки выполняются штатным способом; coverage, readiness и admission
не повышаются из-за устойчивого ресурсного ключа.

## Реальный компонентный проход

EXE: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f; ресурсный патч Revision268356.
Выбраны девять изменённых архивов: 54 сочетания archive/pattern трёх partial
контрактов. Новая схема начинается с текущих доказанных данных; старые
неименованные snapshots не переименовываются по предположению.

| Контекст | Inputs по содержимому | Fallback по архиву | Выбранных записей в суженных inputs |
| --- | ---: | ---: | ---: |
| game-ui | 11 | 7 | 268 |
| map-data | 19 | 8 | 536 |
| quests | 8 | 1 | 328 |

Итого 38 inputs по содержимому и 16 по целому архиву. Два прохода получили
одинаковые resource values и proof, но разные свежие owner receipts.
Первый проход занял 214.314738 с, второй — 338.183536 с.
Проверка stage cache использует отдельные component-resource-key-* имена и
requires_review результаты: три диагностических этапа исполнены сначала,
затем три переиспользованы. Это не три пропущенных native / semantic проверки.
Полный ordinary update и подготовка игрового допуска не запускались.
Новые JVM, native replay и CSV extraction отсутствуют.

## Проверки и остаток

22 новых автоматических случая покрывают посторонний / нужный patch,
добавление / удаление имени, пустое совпадение, non-CSV assets, unknown hashes,
инвентарные gaps, contract guard, повышение coverage, builder, context checks,
порчу pointer, разные owner, fresh barrier и путь обычного update.
Общий набор завершил 1708 тестов с тремя прежними пропусками; шесть
дополнительных checks прошли. Изменение включено в definitions / on_update.

Далее нужны проверенные decoded hashes совпавших записей для 16 fallback
inputs: группировать их по archive SHA / record offset и получать один раз
для всех потребителей. Отдельно требуется подтверждение полных runtime / data зависимостей до
применения к source_checks контрактам. Старые source-bound checks карты,
квестов и обучения сохраняют собственные пробелы переноса. Девять старых
unknown hashes и ближайшая prepatch named база этим правилом не закрыты.
Watcher / live session / prepared-next не менялись. 59 frozen native inputs,
46 прежних facts и исторические разделы документации сохранены.

- [Машинный отчёт](AUTO-RESOURCE-CONTEXT-KEYS-V1-268356.json).
- [Влияние ресурсов](HEADLESS-RESOURCE-IMPACT-V1-268356.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
