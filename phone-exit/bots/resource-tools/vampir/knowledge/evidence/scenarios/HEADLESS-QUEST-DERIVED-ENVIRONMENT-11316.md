# Производное окружение: virtual A8/B8/C8 вместо базовой подстановки

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [ID204 → readiness](HEADLESS-QUEST-WORLD-HANDLER-11316.md).
Это исследование 1.13.16; установленная 1.13.18 не получает допуск автоматически.

## Фабрика и таблица методов

Поиск E8 callers базового constructor1456001D0 дал проверенный вызов145D9C7DF
в фабрике145D9C7C0. После вызова базы она записывает primary vptr149A3DAC0,
secondary vptr149A3DB98 по+8 и149A3DBA0 по+28.
Проверены source bytes, целые функции и complete block/direct-flow coverage,
включая conditional fallthroughs. Поиск прямых вызовов не доказывает отсутствие
косвенных constructors или других записей vptr.

Фабрика и базовый constructor исполняются вместе с явными allocation/registry
fixtures. Запрашивается1B0 hex байт; при успехе возвращается исходный this,
global14B5E5EA8 всё ещё указывает на него, но primary vtable уже производная.
Также проверено private word+F0=6420 hex. Отказ allocation возвращает0 и не
вызывает базовую регистрацию. Это source factory binding, не наблюдение её
активного вызова в настоящем engine lifecycle.

| Slot | Базовая таблица149909370 | Производная149A3DAC0 |
| --- | --- | --- |
| A8 | 141403AB0, false leaf | 145DB0150 |
| B0 | отдельно не используется этим выводом | 1418AF880, читает int+40 |
| B8 | 1418AF880, читает int+40 | 145DA1D40 |
| C8 | 14144E120, пустой FString | 145DB5480 |

Следовательно, прежняя проверка base virtual+B8 == world+40 относится к
явно заданной базовой таблице. Она не доказывает значение getter производного
объекта. На основании одного committed world ID нельзя разрешать quest readiness.

## Значение getter B8

Derived145DA1D40 вызывает virtual+B0 (тот же exact leaf чтения+40), затем
lookup145C79950 с полученным ID. Exact leaf141488490 читает record pointer
из handle+8. При missing record возвращается source constant1496706E0, равная0;
при наличии — record int32+0C. Повторное чтение handle не вызывает lookup снова.

Восемь сценариев: record missing/present × поле0/1/7/FFFFFFFF. World ID во всех
случаях10012. Результат при наличии равен полю записи, при отсутствии0,
и не равен самому10012. Lookup — fixture; назначение поля+0C и источник
настоящей таблицы ещё не установлены. Значения stress input не являются
допустимыми игровыми enum и не привязаны к текущему QuestTask data+14.

## Имена и ветвь A8

Derived145DB5480 (C8) получает запись через тот же lookup/handle, вызывает
record virtual+20 и копирует полученный FString в output. Missing record
даёт пустой FString. Record getter и строковое копирование — fixtures.

Derived145DB0150 (A8) вызывает C8 дважды: для committed+40 и pending+44.
Затем сравнивает длины строк и при одинаковой длине не менее2 вызывает
сравнение14145F1E0; true соответствует непустому результату сравнения.
Особый gate для разных Num и суммы1 сохраняет эквивалентность empty Num0/1.

Десять наборов имён проверяют empty Num0/1, одинаковые/разные строки, разную
длину и ASCII case variant. Lookup получает ровно committed/pending IDs,
record getter/copy вызываются дважды, память environment1B0 не изменяется.
Comparison fixture ограничена ASCII и использует lower; совпадение case variant
проверяет взаимодействие с fixture, а не настоящий Unicode/locale алгоритм
14145F1E0. String copy/free также fixtures, заимствованные буферы не освобождаются
в настоящем allocator.

## Воспроизведение и границы

Новый export run-ca617b011bc3 SHA256
`6d544a194b99d1597156d3e4b8280ecb9d3979090789b5a450c0b884911f902c`.
Base export run-430fed1bb906 SHA256
`6e162d6a5056ba52dbfe8bf50bec54e02b66ab2271c8c4d489e5c2f54a68bd06`.
В новом export есть также virtual+10 initializer145DA3540; он не исполнялся
этим replay и его наличие не закрывает lifecycle initialization.

Tool `replay-quest-derived-environment-11316.py`, тест
`test_vampir_quest_derived_environment_11316.py`, check `native-quest-derived-environment-11316`.
Артефакт: `code-clues/quest-derived-environment-11316/ef5f9ca4527858a6aa5742184ca3cbeea67cae62d9e7f179d79fd76043c1e529/manifest.json`.
19 случаев: десять имён, восемь полей записи, один отказ фабрики.

Registry/allocation, table lookup, record name virtual getter, FString copy/free
и compare — fixtures. Фабрика, базовый constructor и derived A8/B8/C8 исполняются
native. ID204 receiver/Time здесь не скомпонованы с производной таблицей;
прежний receiver replay по-прежнему явно использует A8=true fixture.
`network_used=false`, `action_admitted=false`.

Далее источник record+0C/record name, actual initialization/phase completion
и composition с receiver/readiness. Онлайн-сессия уже закрылась после обрыва
интернета; новая авторизация и игровые действия не выполнялись.
