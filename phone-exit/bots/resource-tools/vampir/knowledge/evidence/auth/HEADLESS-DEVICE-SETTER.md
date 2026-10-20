# SetDeviceKey: сравнение, запись и изменение settings

19 октября 2026. Продолжение [getter lifecycle](HEADLESS-DEVICE-LIFECYCLE.md).
Источник — тот же собранный Windows EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это код клиента, не исходный C++ проект.

Инструмент: `replay-device-key-setter.py`.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/device-key-setter-replay.json`.
SHA256: `e689f3aa65faa13b1e0a098be004b4bd4d8eb45675a03b05c06eb0757dc7be0c`.
Отчёт содержит SHA инструментов/предыдущих source reports, native compare
bytes/table и статические Save/path fragments с file offsets/bytes/SHA.

## Граница исполнения

Исполнены prologue и проверенные ветви `UNMServiceSettings::SetDeviceKey`
`0x14454b390..0x14454b40c`, `0x14454b464..0x14454b54f`, при выключенных
verbose logs. На `0x14454b40c` platform/TLS block явно заменён переходом:
для platform fixture=3 к `0x14454b464`, иначе к `0x14454b523`.
Реальный выбор PlatformType этим не подтверждается.

Case-insensitive compare `0x1414596e0..0x141459727` исполнен native вместе
со 128-byte ASCII table. Bytes переиспользованы из
[NID primitives](HEADLESS-NID-PRIMITIVES.md), без повторного поиска.
StoredValue read/write, store/section getters, FString assignment/allocation/free
остаются fixtures/captures. Код настоящего registry API и Save не исполняется.

## Матрица из 56 fixtures

Семь пар value/stored: обе пустые, одинаковые, различаются ASCII-регистром,
различаются символом при равной длине, различаются длиной, удаление значения,
новое значение вместо пустого. Каждая пара проверена с force=false/true,
platform=3/1 и write result=false/true.

| Условие | Вызов StoredValue write | Settings после setter |
| --- | --- | --- |
| Platform fixture=1 | Нет | Переданный value |
| Platform fixture=3, force=true | Всегда, включая пустое или совпадающее значение | Переданный value |
| Platform fixture=3, force=false, строки совпадают без учёта ASCII-регистра | Нет | Переданный value с исходным регистром |
| Platform fixture=3, force=false, строки различаются | Да | Переданный value |
| Любой вызов write вернул false | Повторной попытки внутри setter нет | Всё равно переданный value |

Native gate: `0x14454b4ab` проверяет force, `0x14454b4b0..0x14454b4db`
сравнивает FString counts/ASCII text. Вызов write на `0x14454b4f1`;
его bool return не проверяется. После этого `0x14454b523..0x14454b53f`
обновляет settings+`0x618` и освобождает входной аргумент через fixture calls.
Это не доказывает полную Unicode-семантику или реальные побочные эффекты хранения.

## Двенадцать интеграционных getter fixtures

Ранее [getter](HEADLESS-DEVICE-LIFECYCLE.md) использовал capture тела setter.
Новый replay вызывает native setter prologue/body и native compare из того же
getter slice, сохраняя platform/store/section как явные fixtures.
Все write и Save captures здесь возвращают false.

Для platform=3 при отсутствии storage строки getter вызывает setter с force=false,
но setter всё равно выполняет write, поскольку значение отличается от пустого.
Это проверено и для существующего settings key, и для нового GUID, при обоих
save flags getter. Сам Save вызывается только после генерации и save flag=true.
Platform=1 не вызывает StoredValue read/write внутри setter. При прямом принятии
storage строки getter вообще не вызывает setter.

Следовательно, getter flag нельзя трактовать как выключатель всех записей.
Нельзя также считать результат getter или settings доказательством persistence:
write=false/Save=false не мешают вернуть ключ.

## Save: следующий этап

В отчёт отдельно сохранены **статические**, не исполненные fragments
`Save` `0x14453cdf0` и path getter `0x144520bd0`.
Source содержит ветви диагностики `SaveGameToMemory() Failed`,
`SaveArrayToFile` и повтор после создания каталога. Это ориентиры для следующего
разбора, не доказательство формата файла/шифрования/успешной записи.
Чтения настоящих файлов Saved, реестра и токенов не было.

Далее: проверить Save/load, формирование пути и активные platform/SDKZone.
После этого определить получение реальных device keys основной почты и связать
их с [постоянным реестром](../../../../../vampir-headless/DEVICES.md).
Обработка server device confirmation остаётся отдельной зависимостью.

Проверка: `python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_device_setter.py' -v`.
Три regression tests проверяют воспроизведение source report, все 56 setter
fixtures и 12 native getter/setter integrations.
