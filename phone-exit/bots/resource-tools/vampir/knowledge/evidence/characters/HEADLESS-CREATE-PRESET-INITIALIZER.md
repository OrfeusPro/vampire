# Пресет внешности: initializer, базовые constructors и postconstruct

23 октября 2026. Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [границы копирования defaults](HEADLESS-CREATE-PRESET-DEFAULT-COPY.md).

## Цепочка constructor проверена без подмены базовых constructors

Исполняются целиком:

1. `0x1417ca780` — создание initializer;
2. `0x1417d2880` — постановка объекта и initializer в context;
3. `0x1454d6800` — constructor `NnDataAssetForCustomizePreset`;
4. `0x143b5fa80` — базовый constructor DataAsset;
5. `0x1417cbc10` — базовый constructor UObject.

Проверены **24 сценария**: poison памяти `0` / `0xa5` / `0xff`, flags initializer
`0` / `1` / `2` / `3`, feature callback выключен / включён. Целочисленные поля
`+0x30..+0x50` сохраняют исходные байты. Семь float становятся `0.5`, voice — 0.
Initializer сохраняет bits flags в `+0x10` / `+0x11`; context push их не меняет.
UObject constructor снимает внутренний флаг `initializer+0x12`.
Проверены границы памяти объекта и initializer.

В этих сценариях TLS/context lookup, lookup текущего initializer и служебный
вызов UObject `0x14174cb20` — fixtures. Context stack заранее выделен, TLS epoch
задан как уже инициализированный; регистрация объекта через feature flag
`0x14b3ce8c0` выключена. Native allocation здесь не исполняется: poison 0 —
явный вход, а не самостоятельное доказательство обнуления allocator.

## Фактические virtual bindings и postconstruct

Проверены указатели текущего EXE, не имена соседних функций:

| Vtable | Слот | Target |
| --- | --- | --- |
| Preset `0x1498514e8` | +0x50 | 0x1417dda00 |
| Preset `0x1498514e8` | +0x58 / +0x60 | 0x141403c50 |
| UClass `0x148a4c688` | +0x388 / +0x3a0 / +0x3b8 | 0x141403c50 |

`0x141403c50` содержит `c2 00 00` — пустой RET. Включённый callback initializer
действительно проходит по этому native target. `0x1417dda00` вызывает UClass
slot `+0x3b8`, затем `0x14174cc70`; оба пути включены в последующую проверку.

Ещё **шесть сценариев** после constructor исполняют целую `0x1417dd530` с flags
initializer 0, исходными object flags `0x231`, пустыми subobjects и class flags
`0x10000001`. Это явная модель native DataAsset без config. Регистрации пресета
и DataAsset задают flags `0x10000000` и `0x10000001`; активный UClass cache
здесь не читается. Если в нём окажутся другие flags / subobjects, это другая ветка.

Внутри postconstruct реально исполняются `0x14174fce0`, `0x14174ba30`,
`0x1417dda00`, `0x14174cc70`, указанные пустые virtual methods, delegate leaf
и `0x141632690` (снятие object flags). Config helper `0x14174fce0` возвращается
до обработки свойств, потому что отсутствует class flag `0x4`. Поэтому называть
весь этот helper только служебным учётом нельзя: его config-ветка меняет свойства,
но в этих сценариях она не выполняется.

Проверены все байты объекта: postconstruct меняет только flags `0x231 → 0x31`.
Integer / float / voice и guards сохранены, pointer объекта в initializer очищен.
Object-array metadata, TLS metadata и пустые списки — fixtures; feature query
`0x14154ad50` и security-cookie check — fixtures. Config / subobject ветки
не покрыты. Отсутствие записи в этих сценариях не доказывает остальные ветки.

## Что ещё не разрешено

Wrapper завершения `0x1417cbe90` выбирает между немедленным postconstruct и
отложенным initializer. Он пока разобран статически; исполнение postconstruct
напрямую не подтверждает выбор wrapper в реальной сессии. Полный CDO creation
и перенос defaults при загрузке asset также не исполнены.
Поэтому extractor пока сохраняет отсутствующие int32 как unresolved.
Следующий контроль — ветка завершения CDO и чтение defaults при загрузке именно
`NnDataAssetForCustomizePreset`; повторять constructors и пустые slots не требуется.
JSON output, producer запроса и живое создание остаются отдельными проверками.

## Воспроизведение и материалы

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-preset-initializer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_preset_initializer.py
```

[Инструмент](../../../replay-release-preset-initializer.py), offline check
`release-preset-initializer`. Игра, авторизация и сеть не используются.
Отчёт в библиотеке ресурсов:
`code-clues/release-preset-initializer/1113e4e460fcf1294ca122f2646a29412bba3f2c6aa707376a5b560a7b272912/manifest.json`.
Отчёт хранит полные SHA всех использованных экспортов и зависимостей.

Новые полные экспорты в общем comparison project
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Каталог | SHA256 details.json | Функции |
| --- | --- | --- |
| run-e2336a990daa | 00237aa7f19cede98a282985961c256788cbc889adb7082f7d8bcb7e4a23ddaa | context push |
| run-086e862edcea | 6ebabc3c6c14098f757245210c336b7ed1bd64607ab76e8e29f1f8473e5e9131 | object post-init |
| run-fbf8f7b13fe2 | 4cb90c2fe07dda625a360e2098c31d157caa132c255b6d4495aa008397daa103 | config helper, validation, cached TLS helper |
