# Внешность: preset → ползунок → float в записи owner

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [сброса перед preview](HEADLESS-CREATE-APPEARANCE-RESET.md).

## Применение preset и сохранённых параметров

После preview `0x14642f090` повторно готовит параметры mesh / animation через
`0x145667e10`; прямой записи owner map в этой функции не обнаружено.
Следующая развилка в `0x146420910`: при preset ID `-1` вызывается
`0x14642d530`, иначе `0x14642ddc0`.

`0x14642d530` читает сохранённые скалярные поля owner и занятые записи map
owner `+0x38`. Имя записи преобразуется в enum через `0x14640e760`;
float умножается на целочисленный масштаб экрана `+0xc48`, результат
усекается до int32 и передаётся в `0x1464235b0`.

`0x14642ddc0` ищет preset по его ID. Helper `0x145671130` формирует путь
`Customize/DT_CustomizePreset%s`; формат находится в UTF-16 literal
`0x149914080` текущего EXE. Значения берутся из объекта по pointer row `+0x10`.
Соответствие семи float-полей аргументам общей функции:

| Offset в объекте preset | Enum ползунка |
| --- | --- |
| +0x54 | 4 |
| +0x58 | 1 |
| +0x5c | 2 |
| +0x60 | 3 |
| +0x64 | 5 |
| +0x68 | 6 |
| +0x6c | 7 |

Каждый float умножается на масштаб экрана, затем преобразуется в int32.
Предшествуют вызовы setters скалярных полей из preset `+0x30`–`+0x50`;
после семи ползунков применяется voice byte `+0x70`.
Это статические offsets, а не подтверждённая UObject-схема или реальные
значения выбранного Gunner preset. Enum пока не подписывается именами групп
по совпадению числа с ID BoneGroup.

Getter preset ID `0x14644a340` фильтрует строки predicate `0x1464479f0`
и возвращает ID первой выбранной записи либо `0xffffffff`. Predicate и
порядок выбора здесь не проверены. Preview использует отдельный predicate
`0x146447990`, сравнивающий row `+0x48` с type byte строки класса `+0x28`.
Не считать эти две выборки одинаковыми без дальнейшей проверки.

## Как значение попадает в owner

Общая функция `0x1464235b0` получает имя enum и ищет соответствующий виджет
в массиве экрана `+0xb10`, count `+0xb18`, через `0x146416e80`.
Затем вызывает setter `0x145f96550(widget, value, 0)` и обработчик
`0x14642d340(screen, widget)`.

Setter статически ограничивает int64 value полями widget `+0xaa8` / `+0xab0`
и записывает результат в `+0xaa0`. Сами реальные min/max и масштаб экрана
ещё не установлены; от проверки этого обработчика их выводить нельзя.

`0x14642d340` берёт имя widget из FString `+0x970` и int32 value `+0xaa0`.
Он вычисляет `float32(value) / float32(screen.scale)` и вызывает
`0x1464568b0(owner+8, name, value)`. Последний:

1. Вычисляет hash имени через `0x141425e40`.
2. Получает запись map через `0x1464368f0(input+0x30, hash, name)`.
3. Копирует имя в запись через `0x14142a330`.
4. Пишет четыре байта float непосредственно в record `+0x10`.
5. Освобождает переданную копию имени.

Возвращённый lookup pointer — внутренний адрес записи, не обязательно начало
слота sparse storage. Его связь со stride `0x30` / value `+0x20` внешнего
JSON helper требует проверки самого lookup. Затем обработчик вызывает JSON
helper `0x146447e50`, обновляет preview через `0x145679e40` и вызывает owner
vtable `+0x20`. Реальная запись scalar выполняется до JSON и preview.

## Native-проверка и границы

`replay-release-appearance-slider.py` исполняет целый обработчик и целый
`0x1464568b0`, включая native float32 division и непосредственный store.
44 случая: три синтетических имени (включая пустое), семь пар value/scale,
Actor present / absent и два ранних выхода без widget / owner.
Проверены дробь 1/3, значения 0 / 1, -0.25 / 1.25, байты float, порядок
операций, сохранность owner и guards вокруг value. Отсутствующий Actor
приводит к передаче нулевого указателя preview fixture; успешность реального
renderer с таким указателем не заявляется.

Hash, map lookup / insert, FString copy / allocation / free, JSON engine,
Actor lookup, renderer и refresh — ограниченные fixtures / captures.
В частности, запись float настоящая, а поиск или создание реального sparse
слота ещё не исполнены. Setter clamp и весь preset consumer в replay не входят.
Масштабы 100 / 3 / 255 синтетические, не извлечённые настройки игры.
Нулевой масштаб и nonfinite floats не проверялись. Создание персонажа не запускалось.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_appearance_slider.py
```

Report:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-slider/4c7273dd728a936c4787bc3102d8e2f17d7bfea793075ecc6fc6e200bf5e222e/manifest.json`.
SHA256 manifest совпадает с именем каталога.
Ghidra comparison: `c7552efd2125-98802d550890/run-fd4956a37b3c`.

| Run | SHA256 details.json | Содержимое |
| --- | --- | --- |
| run-601884ea0d60 | a42781414d815e833394488220d4696882c208a8520f58baafb0d2642d9732ab | После preview / обе ветки параметров |
| run-505e2e29c0bc | 6620fcbe11893f82540e1e6bbbcd6678df323b8fadba62bfb96ef4cdf23778e8 | Общая функция, preset path / getter / preview predicate |
| run-149218135db0 | 865d2bd50a1179f2ce30ffc235fbf38ead94b6ef865fcc4a28694706c625d67d | Обработчик, setter clamp, поиск виджета |
| run-591e487095e6 | 1218e6bdd0b07828910f6b15f37046e270804d374e1c28a891ea5b28ab9cb4c7 | Hash / lookup / запись float |

Следом проверить `0x1464368f0`, predicate `0x1464479f0`, реальные preset assets,
масштаб и min/max ползунков. Затем actual key conversion / JSON output,
целый producer и handler ID 104. Не отправлять нулевую внешность на основании
сброса или допустимые игровые диапазоны на основании synthetic replay.
