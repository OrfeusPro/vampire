# Vampir: имена числовых ContentsLockCondition

15 октября 2026. Продолжение [CONTENTS-LOCKS.md](CONTENTS-LOCKS.md).
Найдено нативное сопоставление имён и чисел, которого не было среди извлечённых
reflected enum-массивов. Значения взяты из инициализации словаря, не из порядка строк.

## Подтверждённая схема

| ConditionType | Имя в клиенте |
|---:|---|
| 0 | CharacterLevel |
| 1 | CompletedQuest |
| 2 | CompletedQuestTask |
| 3 | GuildLevel |
| 4 | EnterArea |
| 5 | EngravingId |
| 6 | AdditionalSlotRarity |
| 7 | EngravingAdditionalRarity |
| 8 | GuildJoined |
| 9 | PetTileCollectionGroupCount |
| 10 | ForcedLock |

Fallback преобразования строки — байт11; его символическое имя не найдено,
поэтому не подписывать как Max без отдельного подтверждения.

## Цепочка доказательств

EXE SHA256:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

1. Модификатор данных `0x145901730` сравнивает имена колонок с точными
   ASCII-литералами ConditionType/ConditionTypeValue1/ConditionTypeValue2.
2. Для ConditionType вызывается thunk `0x1457f6dc0`, затем AL записывается
   в поле+0x10. Thunk делает JMP в конвертер `0x1457a9000`.
3. Конвертер при инициализации создаёт пары «строка → byte». Например,
   строка CompletedQuest загружается в `0x1457a914b`, а значение1 записывается
   в `0x1457a9168`. Первая строка словаря AdditionalSlotRarity имеет значение6,
   а следующая CharacterLevel —0: порядок строк не является числовым порядком.
4. В обработке Value1 результат вызова записывается как qword в+0x18,
   Value2 — qword в+0x20. Сами функции преобразования/сравнения значений
   ещё не разобраны; это описание хранения, не готовая арифметика evaluator.
5. Все330 исходных условий CSV entry70 сопоставлены с этой картой имён,
   с SHA таблицы, логическим csv_record и исходной строкой без изменений.

## Как найти и повторить

`python phone-exit/bots/resource-tools/vampir/build-lock-condition-types.py`
создаёт `F:/PhoneExit Resources/Vampir/quest-graph/condition-types.json`.
Нужны native-enums.json и table-study/index-pakchunk1-Windows.json.
Capstone закреплён в requirements-native.txt. Сохраняются все фрагменты конвертера
и модификатора, байты thunk, имена с offset, инструкции инициализации и CSV.
Четыре теста проверяют пары по значениям, дубликаты, разрывы слотов и неизвестное.

## Что это меняет в ранней цепочке

Для Guide901030 условие199 типа1 теперь имеет подтверждённое имя CompletedQuest;
исходный Value1=901010. Для Guide901010 условие198 того же типа содержит110190.
Это усиливает связь с завершением требуемых квестов, но **не доказывает**
проверяемое серверное состояние, точную операцию Value1/Value2 или время применения.

Сравнения чисел, логика AND/OR, исключения отсутствующих Quest908020/908030/908150,
серверные группы и сохранение разблокировок остаются неизвестными. Ни одно условие
не вычислялось для персонажа; runtime evaluator не включён.

## Каталог модуля: referenceRevision3

build-runtime-chain.py теперь загружает condition-types.json и проверяет:
тот же EXE, тот же CSV entry70, полную карту11 уникальных типов, исходные значения
каждой строки и её csv_record. Проверки всех связей проходят до добавления имён.
После этого condition.typeName и contentsLockConditionTypes включаются в
quest-runtime.json; SHA отчёта сохраняется в sourceReports.

Все330 условий получили подтверждённые имена. evaluation=not_evaluated,
combination=unknown_do_not_assume_AND_OR и lockEvaluator=not_implemented сохранены.
schemaVersion остаётся1; referenceRevision повышен с2 до3 — это дополнение
справочника, не новый исполняемый evaluator. В локальной неопубликованной1.0.8
имена доступны модулю; установленная на телефоне1.0.7 от этого не изменилась.
