# Текущий allocation и перенос CDO defaults: ограниченная модель

6 ноября 2026. EXE SHA256:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Продолжение [constructor / descriptors](HEADLESS-PRESET-DEFAULTS-CURRENT.md)
и [ClassInfo consumers](HEADLESS-VIPER-CLASS-CONSUMERS-CURRENT.md).

## Что исполнено

[Проверка](../../../verify-viper-cdo-current.py) исполняет 24 новых сценария:
шесть fresh-allocation случаев и 18 композиций обычного создания объекта.
Матрицы 25 constructor / 49 ClassInfo случаев не повторяются. Их готовые
экспорты используются с полной SHA-проверкой; constructors здесь исполняются
внутри новой композиции с allocation и completion.

| Роль | Текущий root | Whole instructions |
| --- | --- | ---: |
| Обычное создание | `0x1417e6e60` | 161 |
| Allocation | `0x1417e62c0` | 668 |
| Completion | `0x1417cc040` | 111 |
| Postconstruct | `0x1417dd6e0` | 331 |
| InitProperties | `0x1417dabb0` | 244 |
| Default-copy wrapper | `0x1417ddbb0` | 16 |

Первые пять экспортов проверяются по всем PE unwind ranges и каждому байту
инструкций, включая chained ranges. Вместе с ними выполняются текущие preset,
DataAsset и UObject constructors из прежнего готового экспорта.

Allocation исполняется целиком по fresh-ветке с null outer / null name и flags
`0xb`. Три poison-памяти и размеры `0x30` / `0x78` подтверждают ровно один
вызов `memset(destination, 0, size)`, аргументы heap backend, reuse byte = 0,
native header и сохранность памяти за пределами размера. Идентичность
`VCRUNTIME140.dll!memset` проверяется по PE import binding текущего EXE.
Heap backend, создание имени и регистрация объекта остаются fixtures.

В 18 композициях настоящий ordinary caller вызывает настоящий allocator,
три constructors, completion, postconstruct, InitProperties и wrapper.
Каждый из девяти native roots исполняется ровно один раз. Проверены три poison,
два source-вектора и три списка свойств: пустой, все 17 полей и чётные индексы
схемы. Списки используют class `+0x88` и property next `+0x60`.
Обычный initializer получает copy flag = 1 и переданный source. Итоговые flags
равны `0xb`, оба счётчика initializer возвращаются к нулю, внешние guards целы.

Пустой список сохраняет constructor-результат. При полном списке копируются
17 полей; при частичном — девять выбранных. Контрольный source содержит
намеренно изменённые значения, поэтому сохранение constructor defaults
отличается от фактического копирования. Эти значения никуда не отправляются.

## Wrapper и граница Ghidra

Первый scoped collect шести roots остановился на строгом guard
`Decompiler block outside requested unwind ranges` у `0x1417ddbb0`.
Его последние инструкции передают выполнение через `JMP 0x141403bd0` в
no-unwind leaf `RET 0`. Decompiler включил leaf за пределами wrapper.
Guard не ослаблялся; частичный экспорт не принимается за готовый.

Пять остальных roots собраны отдельно. Wrapper проверяется отдельным правилом:
точный unwind root, полный вектор всех 16 инструкций и неизменный tail target.
В replay исполняются все эти инструкции и точные bytes leaf `c20000`.
Binding preset vtable `+0x50 → 0x1417ddbb0` также сверяется по текущему EXE.
В машинном отчёте wrapper имеет `provenance=whole_pe_unwind_bytes` и
`ghidra_export_admitted=false`.

## Fixtures и оставшееся неизвестное

Это условная offline модель, а не чтение загруженного Viper asset или live CDO.
Source CDO задан fixture: девять integer = 0, семь float = 0.5, voice = 0.
Целая fresh-ветка подтверждает нулевую память до constructor; constructor
устанавливает float / voice. Однако получение первоначального CDO, загрузка
package и последующие overrides здесь не исполняются. Отсутствующие integer
в исходных F / M ресурсах остаются неизвестными как свойства загруженного asset.

Class / property metadata, POD flags и принадлежность спискам синтетические.
Три virtual class provider slots `+0x388`, `+0x398`, `+0x3b8` используют
явные RET fixtures. Context push / lookup, object registration / bookkeeping,
flags helpers, security, bounded CRT memory effects и owner notification также
fixtures. TLS обнулён; config, subobjects, delegates и deferred queue пусты.
Это не подтверждает поведение реальных class providers или deferred completion.

Object reuse, специальные outer / CDO allocation, сериализация asset,
актуальный producer Create103/104 и серверное создание не проверены.
`runtime_admitted`, `loaded_preset_verified`, `complete_viper_payload_verified`
и `network_used` в отчёте равны false. Никакая учётная запись не запускалась.

## Воспроизведение и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-viper-cdo-current.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_viper_cdo_current.py
```

[Контекст](../../native-contexts/viper-cdo-11322.json),
[четыре теста](../../../../../test_vampir_viper_cdo_current.py).
Тесты проверяют selective copy и границы, отказ при усечённом / изменённом
wrapper, изменённом vtable binding и другом SHA. Новые JVM им не требуются.
Следующее действие — зарегистрировать `viper-cdo-current` как source-bound
on_update check с этим context и зависимостями, затем применить кэш и scoped finish.
Этот документ не объявляет ещё не выполненную регистрацию готовой.

Scoped request пяти roots:
`research-scoped-v2-requests/dfc4e5db0c876b550cef51ce17984fa9d3661504ff92e1f50f5ec20242418fb5/manifest.json`.
Collection:
`research-scoped-v2-collections/38f52d77e04393860c5cf8f1f264ad248f30372bca9dce65f2cbaa6ed4d09602/manifest.json`.
Исходный отклонённый request:
`research-scoped-v2-requests/66384d01bed96a89bbe062a94e787d3a09b543503401fc9e50db10895accf6a6/manifest.json`.

В библиотеке `F:/PhoneExit Resources/Vampir/`:

- Новый экспорт: `ghidra/request-exports/03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f/run-40ba4fb51df9/details.json`,
  SHA `6a7d2ca4eae7d298b7780bdc50f9a93435bd2734c4bfa8545f986c0e47181821`.
- Прежние constructors: `run-ddd300a85f1d/details.json` в том же namespace,
  SHA `13f0a8487595a35f933bd36c9b68ec54a63e778bb9cdf5fa845c49291cfbcf4f`.
- Semantic report: `code-clues/viper-cdo-current-v1/5b873c1ea661a5447a9bfbf8f4583d0356bd6765e4ac2a9c2642b1fd979d96c3/manifest.json`.

Cache dependencies: tool, context, constructor context, harness, PE reader,
whole-source normalizer, knowledge-index, audit-client-release, named-import
reader, extract-native-enums, requirements-native, test module и два точных
экспорта. Runtime: Capstone 5.0.6 / Unicorn 2.1.4. Готовые проверки constructor
и ClassInfo входят отдельными зависимостями без повторного native исполнения.
