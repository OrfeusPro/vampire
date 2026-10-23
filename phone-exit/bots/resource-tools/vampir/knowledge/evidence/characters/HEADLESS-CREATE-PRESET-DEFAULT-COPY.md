# Пресеты внешности: обнуление новой памяти и граница копирования defaults

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [поиска CDO](HEADLESS-CREATE-CUSTOMIZE-SCALE.md) и
[извлечения текущих пресетов](HEADLESS-CREATE-CURRENT-PRESETS.md).

## Проверенный участок

В `0x1417e6110` при нулевом входном имени используется отдельная ветка:
получение имени через `0x1417dccf0`, размер из class `+0x58`, новая allocation,
`cVar18 = 0`. Перед базовой инициализацией объект целиком обнуляется через
`memset(object, 0, class_size)`. Повторное использование существующего объекта
идёт по другой ветке; обнуление для неё не утверждается. Это статический разбор
полного экспорта, allocator в replay не исполнялся.

Initializer `0x1417ca780` сохраняет объект и defaults, разделяет два входных
flag bits в поля `+0x10` / `+0x11`. Завершение `0x1417cbe90` может перейти в
`0x1417dd530`; тот при включённом копировании вызывает `0x1417daa00`.
Сам факт наличия этого вызова не доказывает, что он выполняется для каждого CDO.

Superclass getter пресета `0x1437efa40` — leaf JMP в `0x143b6c050`.
Регистрация DataAsset задаёт размер **0x30**. Поля пресета начинаются с `+0x30`.
В `0x1417daa00` граница копирования проверяется по формуле:

```text
property_offset + element_count * element_size <= source_class_size
```

Исполнена целая `0x1417daa00` в **36 native сценариях**: обычный путь с отдельным
source class и оптимизированный путь с actual class; размеры `0x30` / `0x34` /
`0x78`; поля по `+0x2c`, `+0x30`, `+0x40`, `+0x50`, `+0x70` и массив из двух
int32 по `+0x2c`. При размере `0x30` скопирован только int32, заканчивающийся
ровно на границе. Ни одно поле с offset от `0x30` не скопировано. Проверены все
байты объекта и guards, а не только ожидаемое значение поля.

## Границы и следующий шаг

Метаданные классов / свойств и исходные байты в replay заданы fixtures.
Два начальных служебных вызова и bounded CRT memcpy также fixtures.
Проверены POD properties без transient flags; virtual property copy, копирование
из собственного CDO и остальные ветки здесь не покрыты.
Полный цикл создания CDO, десериализация и последующие overrides не исполнялись.

Результат исключает копирование родительских байтов DataAsset в собственные
поля пресета в проверенных ветках. Он **не превращает** отсутствующие int32 в
доказанные нули готового asset: `DecalIndex` F/M, `DecalColorIndex` F и
`EyeTexIndex` M по-прежнему отмечены unresolved в extractor. Следующий контроль —
завершение инициализации именно preset CDO и перенос defaults в загруженный asset;
после него можно менять значения extractor. Реальные slider limits, JSON output,
полный producer и живое создание остаются отдельными проверками.

## Воспроизведение и материалы

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-preset-default-copy.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_preset_default_copy.py
```

Инструмент: [replay-release-preset-default-copy.py](../../../replay-release-preset-default-copy.py).
Проверка знаний: `release-preset-default-copy`; авторизация и сеть не используются.
Отчёт в библиотеке ресурсов:
`code-clues/release-preset-default-copy/c034d7e011e3d7a7223e3fdd6775567c9b91eec2f8a8666c9a76d9e0b4b94cd5/manifest.json`.

Полные экспорты в общем comparison project
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Каталог | SHA256 details.json | Функции |
| --- | --- | --- |
| run-d156ab446138 | 269c2a6b770cbc23877e87eef0c307f437bacefc5546a6fe7d432dedf95730f9 | allocator, initializer, completion |
| run-8d3476afb3ca | 6ccc08da7e16914ec25df902900a55e91eb462920a15f59da0946cc012274a0a | postconstruct |
| run-5ec4a8b50550 | 241744686e1b958ff818da0b6cbfe675f10b6f7da64cd3aa3df96dd1cafbed85 | InitProperties, DataAsset registration |
