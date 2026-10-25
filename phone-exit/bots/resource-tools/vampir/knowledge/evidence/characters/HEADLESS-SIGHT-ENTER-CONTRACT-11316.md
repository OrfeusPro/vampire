# SightEnter: типы пяти массивов текущего клиента

EXE 1.13.16, полный SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Статически проверена цепочка reader `1456c5390` → descriptor → callback →
constructor → vtable → virtual reader / name getter. Это контракт структур,
не готовый wire decoder и не доказательство живой видимости.

## Порядок и записи

| Поле packet | Descriptor | Resize / callback | Запись / constructor | Reader | Native stride |
| --- | --- | --- | --- | --- | --- |
| +10 | 149924cd8 | 1456d1d30 / 1456c5e60 | PktCharacterOther / 145783670 | 145788180 | 230 |
| +20 | 149924cf0 | 1456d1f30 / 1456c6400 | PktNpcCreateData / 14579a5a0 | 14579e590 | 240 |
| +30 | 149924d08 | 1456d1ef0 / 1456c62f0 | PktGroundEffectData / 14578fef0 | 145793a90 | 78 |
| +40 | 149924d20 | 1456d1eb0 / 1456c6270 | PktGadget / 14578fe30 | 1457938b0 | d0 |
| +70 | 149924d38 | 1456d1ff0 / 1456c67a0 | PktTetherEffectData / 1457a3480 | 1457a83c0 | 90 |

Числа offset / stride в таблице — hex. Это размеры объектов в памяти клиента,
не размеры сериализованной записи. Каждый descriptor содержит
`141b0aa50`, resize и callback. Внешний reader передаёт адрес соответствующего
массива через archive slot +18 в указанном порядке; после четвёртого массива
читает отдельную virtual запись packet+50 через `144aad190`, затем пятый массив.
Последний byte ограничивается 32 и хранится в packet+80.

Имена подтверждены вызовом constructor в callback, записью vtable в начало
объекта, слотом reader +20 и name getter +28, который явно загружает связанный
литерал. Это сильнее совпадения расположенного рядом текста. Native stride
проверен по imul либо последовательности lea / shl в callback.

Содержимое +20 совпадает с `PktNpcCreateData`, уже разобранной внутри
[NPC create](HEADLESS-NPC-CREATE-11316.md). Отдельный notify содержит внешний
flag; этот flag нельзя добавлять к каждой записи SightEnter. Нельзя и искать
следующую запись по размеру native объекта.

`PktCharacterOther` имеет свой reader и вложенные записи. Ground / tether effects
и gadget не включать автоматически в счётчик NPC / игроков. Название класса само
по себе не определяет игровой тип, HP, координаты или право управления actor.
Связь других персонажей с players и поля для UI требуют handler / model проверки.

## Воспроизводимость

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-sight-enter-11316.py
```

Инструмент требует точный SHA и Capstone 5.0.6, проверяет instruction boundaries,
порядок пяти descriptor LEA, точные slot pointers, constructor calls / vtable stores,
name getter / literal и 16 source anchors для аргументов, strides и tail clamp.
Используются 16 явных unwind roots, без полного Ghidra-экспорта EXE.
При отличии источника или цепочки проверка прекращается.

Отчёт вне Git, корень `F:/PhoneExit Resources/Vampir/`:
`code-clues/sight-enter-11316/7dc21ac735c891f2eccfbc0b1ad931f2b87e7977364a0848ab819a1d1d82ee38/manifest.json`.
SHA256 отчёта совпадает с именем каталога.

Публичные Ghidra exports в `ghidra/request-exports/<SHA>/`:

| Экспорт | SHA256 details.json | Состав |
| --- | --- | --- |
| run-f4d4115c1822 | 351b23e89787415525d3fea68dd505089c9e6b22d53cf1d32c5c9b85a594225e | внешний reader |
| run-81dc5e726695 | 62286b3af2b7f845dccc3dcd0e53bdc387febeccb08b75471080cb0a556c2d94 | 5 resize и 5 callbacks |
| run-6a3c2fd0e46f | 311e436526b3750d8133625eaef6253be0711f4cba67dcc7464c362f6429cb19 | 4 constructors, ground / gadget / tether readers |
| run-fa0e43376ec9 | 3500e3b849cc519c3117b3e31122febc377a9cb95e11931563946c5189c3efa9 | CharacterOther reader, прежние NPC readers |

Два новых collect завершились успешно; недостающие выбранные функции получены.
Статическая проверка не запускает игровой клиент, вход или сеть. Native execution
внешнего SightEnter / callbacks на этом этапе не выполнялся. Ранее пройденный
NPC create replay не доказывает целый SightEnter.

## Следующая проверка

Установить запись packet+50 и вложенные типы `PktCharacterOther` / `PktGadget`.
Затем исполнить внешний reader с настоящим input и всеми callbacks на mixed
arrays, префиксах и граничных counts; сравнить полный portable разбор. Общий
лимит коллекций должен учитывать все пять массивов и вложенные записи вместе.
Проверить handler → actor / world, затем подключить к изолированной модели.

В runtime пока остаются только [частичные create / leave события](HEADLESS-OBSERVED-ENVIRONMENT-11316.md).
`coverage.entities=partial`, `players_received=false` сохраняются. Пустой
наблюдаемый список не доказывает отсутствие объектов при входе.
