# Пресет: немедленное завершение, очередь и шаблон asset

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [initializer и postconstruct](HEADLESS-CREATE-PRESET-INITIALIZER.md).

## Native wrapper завершения

Исполнены целые `0x1417cbe90`, selector `0x141638a20` и проверка отложенной
инициализации `0x141633290`, вместе с ранее проверенными constructors и
немедленным postconstruct. Всего **24 сценария**: три poison-памяти, два состояния
callback initializer и четыре маршрута завершения.

Selector `0x141638a20` читает cached setting `0x14b3c6b58` и результат вызова
`0x141640fc0`. Последний здесь возвращает явно заданный fixture bool; его смысл
и фактическое состояние живого процесса этой проверкой не устанавливаются.

| Маршрут | Условия модели | Результат |
| --- | --- | --- |
| immediate_dependency_false | dependency = 0 | Selector возвращает 1; postconstruct сразу |
| immediate_setting | dependency = 1, setting = 1 | Selector возвращает 1; postconstruct сразу |
| immediate_class_ready | dependency = 1, setting = 0, internal class flag bit 25 | Проверка очереди возвращает 0; postconstruct сразу |
| deferred | dependency = 1, setting = 0, class / parent не готовы, queue lookup miss | Queue insertion возвращает копию initializer; wrapper ставит ей byte +0x13 = 1 |

В 18 немедленных случаях выполняется весь ранее проверенный postconstruct:
object flags `0x231 → 0x31`, pointer объекта в initializer очищен, остальные байты
объекта и guards сохранены. В шести отложенных случаях object flags остаются
`0x231`, pointer сохраняется и postconstruct сразу не вызывается.
Это различие проверяется по состоянию объекта и факту вызова queue insertion.

Во всех случаях wrapper снимает internal object-array bit 31, возвращает оба
счётчика context к нулю и восстанавливает предыдущий context object.
Native leaf `0x1417d7090` читает class из объекта initializer; исполняются
проверенные байты `48 8b 01 48 8b 40 10 c3`.

## Границы fixtures

TLS/context lookup, bool dependency `0x141640fc0`, queue lookup / insertion,
очистка пустых контейнеров и delegate, UObject bookkeeping, feature query и
security-cookie check — fixtures. Queue insertion копирует initializer в другой
буфер; **пометку этой копии делает native wrapper**, не fixture.
Реализация хранения очереди и последующее выполнение отложенного initializer
не проверены. Cached TLS, object-array metadata, class flags без config и пустые
subobjects заданы явно. Cold initialization и другие типы объектов не покрыты.

## Шаблон двух текущих assets

В текущих именованных `DA_PresetDarkMage3_F` и `DA_PresetDarkMage3_M` проверены
не только type name, но и export/import references:

- `class_index = -1` → `/Script/NnFramework.NnDataAssetForCustomizePreset`;
- `template_index = -2` → `/Script/NnFramework.Default__NnDataAssetForCustomizePreset`;
- `super_index = 0`, единственный export каждого package.

Extractor теперь отклоняет чужой native class, чужой / локальный template и
неподдержанный superclass. Сохраняются исходные байты export table и полные
пути imports. Пять тестов extractor проверяют текущие связи, четыре подмены
class/template/super, повторяемость, constructor defaults, короткие префиксы
и повреждённый индекс.

Эта привязка доказывает, какой CDO указан в файлах. Она **не исполняет загрузчик**
и не доказывает значения полей после применения defaults и десериализации.
Отсутствующие int32 extractor по-прежнему оставляет unresolved; runtime запроса
создания этим изменением не включается. Следующая проверка — перенос defaults
из этого native template при загрузке asset и границы поздних изменений.
Повторять проверенные constructors или механическое ветвление wrapper не нужно.

## Воспроизведение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-preset-completion.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_preset_completion.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_presets.py
```

[Completion tool](../../../replay-release-preset-completion.py),
[общая native цепочка](../../../replay-release-preset-initializer.py),
[extractor](../../../extract-release-creation-presets.py).
Offline check `release-preset-completion`; авторизация, игра и сеть не запускаются.

Отчёты в библиотеке ресурсов:

- `code-clues/release-preset-completion/d56efeb83dd9d966b4ba31ea63e9a5d723285811625c9fba58e9034725f26636/manifest.json`;
- `code-clues/release-creation-presets/2897a3ff0e861f5e67a03ef5b0043fcf035a6108bb0292a457b08c5d9847432a/manifest.json`.

Новый полный экспорт:
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-0fc58b2f30f3/details.json`,
SHA256 `5866927a72e3deed60490ccc12bebc63dffc47a4fad916dca4fc6ae65c84c844`.
Все исходные SHA PAK / EXE / blobs и экспорты сохранены в отчётах;
крупные материалы остаются вне Git.
