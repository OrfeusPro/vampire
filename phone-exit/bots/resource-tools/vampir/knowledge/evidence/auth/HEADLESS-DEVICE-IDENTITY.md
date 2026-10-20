# Windows SDK: постоянные device keys

19 октября 2026. Клиентский EXE, не исходный C++ проект.
Источник: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA ниже рассчитаны при image base `0x140000000`.

## Источники и воспроизведение

`build-headless-device-identity.py` читает только EXE и прежний source manifest.
Экспортирует 19 unwind fragments, проверенные initializer references, literals,
PE imports и три ограниченных instruction spans. Полный GUID formatter содержит
jump table, поэтому не выдаётся за полностью декодированный линейный диапазон.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-device-identity.json`.
SHA256: `748e7c99379916d565e73c1873efe740484bd4456a6ce9f7c6b36d1231356ba1`.
В нём file offsets/bytes/SHA, цепочка references и границы статических выводов.

`replay-device-guid-format.py` исполняет default format=0 branch и hex writer
на трёх наборах искусственных uint32. Отчёт:
`F:/PhoneExit Resources/Vampir/code-clues/device-guid-format-replay.json`.
SHA256: `04aef4cc4b8d3619cfc6423dcb821290adc69d825388aff285784c9dcb48750e`.
FString capacity и stack cookie — fixtures; security check — capture.
Остальные ветви formatter, getters, генератор и storage не исполнялись.

Дополнение: [getter branches исполнены на 20 fixtures](HEADLESS-DEVICE-LIFECYCLE.md).
Storage/parser/platform/setter/Save остаются fixtures, реальные ключи не читались.

## nmDeviceKey

`FDeviceInfo::GetNMDeviceKey` `0x1444e5ff0` сначала проверяет FString cache
`0x14b4f13a0` (count > 1). При заполненном cache возвращает его копию.
Иначе вызывает `0x1415c59c0` с globals:

| Аргумент | Global | Подтверждённая строка |
| --- | --- | --- |
| RCX, store | 0x14b4f1030 | Netmarble |
| RDX, section | 0x14b4f1040 | NetmarbleSDK |
| R8, key | 0x14b4f1070 | NMDeviceKey |

Initializer references проверены по decoded instruction boundaries, не только
по совпадению байтов LEA. Windows helper строит путь от `Software`, заменяет
разделители и передаёт HKCU (`0xffffffff80000001`) в reader `0x1415ce230`.
PE import names подтвердили RegOpenKeyExW/RegQueryValueExW/RegCloseKey.
Это статическая цепочка к записи `Software\Netmarble\NetmarbleSDK`,
не чтение настоящего реестра или подтверждение наличия записи.

Затем `0x14155abf0` разбирает сохранённую строку в четыре uint32.
Если parser вернул false либо OR четырёх слов равен нулю, caller вызывает
`0x14155a550`: zero-init 16 bytes → leaf JMP `0x1415bf470` → PE import
**CoCreateGuid**. Далее formatter `0x141548fd0` с format=0, перенос в cache
и SetStoredValue `0x1415d1990` с теми же store/section/key.
Результат записи не проверяется caller: сам вызов не гарантирует persistence.
При валидном ненулевом GUID caller копирует исходную сохранённую строку в cache;
не следует автоматически нормализовать ранее сохранённое значение.

## deviceKey

`UNMServiceSettings::GetDeviceKey(bool)` `0x144522820` использует отдельную
FString settings+`0x618` и условную ветвь `NMSDK.PlatformType == 3`.
В этой ветви сначала пробует StoredValue с ключом **DeviceKey**
(`0x14b4f1a88`). Store getter `0x14452f230` начинает с Netmarble и при
settings byte+`0x49 != 2` дописывает пробел и строку helper `0x14452bcd0`.
Section getter `0x14452f170` копирует gameCode из settings+`0x38`.
Активные значения platform/environment/gameCode пока не установлены.

Непустая сохранённая строка копируется в settings без GUID parser этого caller.
Если storage ветвь не дала строку, caller использует существующую settings
identity, вызывая SetDeviceKey `0x14454b390` с flag=false. Если settings пусты,
создаёт GUID тем же генератором/format=0 и вызывает SetDeviceKey.
Только ветвь создания нового GUID дополнительно вызывает Save `0x14453cdf0`
при входном bool=true (`0x144522a8d..0x144522a95`).
Это не означает отсутствие registry write при bool=false: setter имеет свою
ветвь сравнения StoredValue/записи для PlatformType 3.
Поэтому флаг getter нельзя описывать как полный запрет persistence.

Имя PlatformType и значение 3 не доказывают физический тип устройства.
Полный Save/load lifecycle, имена environment, активный platform и обработка
ошибок хранения ещё требуют проверки. Нельзя смешивать deviceKey с nmDeviceKey.

## Проверенный формат нового значения

Actual native formatter prologue `0x141548fd0..0x141549019`, branch
`0x141549610..0x141549674` и hex writer `0x1415ad580` исполнились в Unicorn.
Каждое из четырёх uint32 переводится bswap в big-endian bytes и затем в
uppercase hex: итог **32 символа без дефисов**, FString count=33 с NUL.
Пример fixture: `01234567 89ABCDEF FEDCBA98 76543210` →
`0123456789ABCDEFFEDCBA9876543210`. Это формат слов Unreal GUID;
не следует без сверки заменять его стандартным текстом Windows GUID.
CoCreateGuid и настоящий ключ не исполнялись/не получались.

## Значение для бота и границы

Существуют постоянные программные идентификаторы SDK. Их наличие не доказывает
ни отсутствие дополнительных аппаратных/клиентских полей, ни принятие отдельных
профилей сервером, ни обход ограничений входа. Android код этим Windows EXE
не подтверждён. Реальная identity основной почты остаётся незаполненной в
[реестре бота](../../../../../vampir-headless/DEVICES.md).

Далее: исполнить getter/cache/storage ветвления с fixtures, восстановить
platform/environment selection и Save/load; затем определить согласованное
получение реальной identity и source-bound device confirmation challenge.

Проверки: `python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_device_identity.py' -v`.
Сеть, реестр пользователя, файлы профиля, Saved и память процессов не читались.
