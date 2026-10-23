# Обычный объект пресета: constructor, перенос defaults и модельная проекция

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [completion и native template](HEADLESS-CREATE-PRESET-COMPLETION.md).

## Найден обычный путь создания

`0x1417d6b00` выбирает archetype / CDO, а не создаёт объект. В проверенной ветке
с нулевым outer, нулевыми flags и уже готовым class CDO он возвращает class
`+0x110`. Эта целая ветка теперь также исполнена native. Специальные outer,
выбор superclass и создание отсутствующего CDO здесь не покрыты.

Обычная цепочка находится в `0x1417e6cb0`. Она заполняет initializer прямо
внутри себя, поэтому поиск только callers `0x1417ca780` её не показывал.
Три подтверждённых CALL:

| Callsite | Target | Операция |
| --- | --- | --- |
| 0x1417e6db4 | 0x1417e6110 | Allocation |
| 0x1417e6f1e | 0x1417d2880 | Context push для встроенного initializer |
| 0x1417e6f30 | 0x1417cbe90 | Completion |

Между context push и completion вызывается constructor из class `+0xb0`.
У обычного initializer byte `+0x11` равен 1, defaults взяты из входного template
по `parameters+0x28`. Это проверено в момент вызова constructor, а не выведено
только из конечных байтов. У начального CDO в той же проверке copy flag равен 0.

В `InitProperties`, если source совпадает с class CDO, используется список из
class `+0x88` с next pointer property `+0x60`. Нельзя подменять его утверждением
«копируются все скалярные поля». Пустой список сохраняет значения constructor.

## 18 native сценариев

Исполняется вся `0x1417e6cb0` и вложенные context push, preset / DataAsset /
UObject constructors, completion, postconstruct и `InitProperties`.
Проверены три poison-памяти, два template-вектора и три списка свойств:
пустой, все 17 полей, чётные индексы схемы. Offsets / типы полей берутся из
проверенных descriptors текущего EXE. Runtime property flags POD и принадлежность
спискам задаются fixtures, а не выдаются за прочитанный engine cache.

Первый template строится native constructors и completion на явно обнулённой
памяти. Получается вектор: девять int32 = 0, семь float = 0.5, voice = 0.
Второй template намеренно изменён после инициализации: разные integer / float /
voice значения позволяют обнаружить, какие поля действительно копируются.
Эти контрольные значения не являются допустимой игровой внешностью и не отправляются.

При пустом списке изменённый template не влияет на поля объекта. При полном
списке копируются все 17 полей, при частичном — только девять выбранных.
Обычный объект завершается с flags `0xb`, оба счётчика context возвращаются к нулю,
guards allocation не меняются. Проверена ровно одна allocation.

В сравнении vtable пресета `0x1498514e8` и DataAsset `0x148aa2ab8` на явном окне
`0..0x2b0` отличается только slot 0 (destructor). Это сравнение заданного окна,
не доказательство полной длины vtable или отсутствия любых поздних изменений.

## Ограничения и применение результата

Allocator — fixture обнуления, соответствующий ранее разобранной fresh-allocation
ветке; целый allocator здесь не исполнен. Class / property metadata, no config,
empty subobjects, cached TLS, object array, lookup текущего initializer,
очистка пустых контейнеров, bookkeeping, feature query, selector bool и security
check — fixtures. Проверено немедленное завершение. Package loader, чтение
сериализованных свойств и поздние overrides не исполнены.

Extractor теперь сохраняет **два разных результата**:

- `decoded`: прежние данные файла; отсутствующие int32 остаются `None` / unresolved;
- `native_default_projection`: те же сериализованные значения плюс отсутствующие
  поля из native модели, с `model_only=true`, `verified_loaded_asset=false`,
  списком `inferred_fields`, origins `native_zero_allocation_model` и ссылкой на отчёт.

В проекции F `DecalIndex` / `DecalColorIndex` равны 0; в M `DecalIndex` /
`EyeTexIndex` равны 0. Это модель, не чтение значений живого asset.
Шесть тестов extractor сохраняют исходные unknown, проверяют эти пометки,
неизменность сериализованных значений и отказ для модели с другим EXE SHA.

Проекция пригодна как **явный кандидат внешности для offline проверки producer**.
Для задачи создания любого персонажа не требуется утверждать, что его внешность
точно повторяет загруженный экран игры. Следующий шаг — целый producer
`0x146449dc0`, JSON и handler ID 104 с этим кандидатом; модель не разрешает
скрытую отправку и не заменяет проверку пустого списка / результата создания.
Фактическая десериализация и поздние изменения asset остаются отдельным unknown;
не повторять найденный обычный constructor ради того же вопроса.

## Воспроизведение и источники

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-preset-object.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_preset_object.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_creation_presets.py
```

[Native tool](../../../replay-release-preset-object.py),
[extractor](../../../extract-release-creation-presets.py).
Offline check `release-preset-object`; сеть, игра и авторизация отсутствуют.
Отчёты в библиотеке ресурсов:

- `code-clues/release-preset-object/95329ca33198169f24f35fab814e67d455cdc3fdc80221ca9561b8b8346fd762/manifest.json`;
- `code-clues/release-creation-presets/73d62137fd8ba1104077f04369bc9babf58ff45b356b6d533c91e88430b08783/manifest.json`.

Новые экспорты в общем comparison project
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Каталог | SHA256 details.json | Роль |
| --- | --- | --- |
| run-4dc9ed45997b | 31a525fd278305c809a76de6f0841513ad54357345f1fc904d314bc5fbe81a61 | Archetype selector 1417d6b00 |
| run-a9f0f96bdeb3 | 895810a930e1e3dfd258c21f9607dac470e1ed00ffd192def4fa641119743d2d | Ordinary constructor 1417e6cb0 |
| run-7fae313980e8 | f70267b5a151b0a6c50ac940979850cbdcd99b27463e7adccacbea7721b82010 | Дополнительный caller 142474130, не используется как общий constructor |
