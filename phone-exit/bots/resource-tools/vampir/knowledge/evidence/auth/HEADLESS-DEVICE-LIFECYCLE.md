# Device keys: native getter branches

19 октября 2026. Продолжение [статического исследования](HEADLESS-DEVICE-IDENTITY.md).
Тот же клиентский EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

Инструмент: `replay-device-key-lifecycle.py`.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/device-key-lifecycle-replay.json`.
SHA256: `b1c63c292ce95f7eb5a9205da16fa8896f7014e5e796fb8ef8d9b5c4e8c12871`.
Исходные instruction bytes/file offsets и imports переиспользованы из
`headless-device-identity.json`, SHA256
`748e7c99379916d565e73c1873efe740484bd4456a6ce9f7c6b36d1231356ba1`.
Оба отчёта содержат SHA инструмента и ссылки на исходный EXE.

Дополнение: [native setter/compare и getter integration](HEADLESS-DEVICE-SETTER.md)
проверены отдельным replay; первоначальный отчёт ниже сохраняет прежние границы.

## Что исполнено

В Unicorn исполнен полный `GetNMDeviceKey` `0x1444e5ff0` с выключенным verbose
logging, GUID constructor `0x14155a550`, ранее проверенная default format=0
ветвь formatter и native hex writer. Логи не исследованы этим replay.

Для `GetDeviceKey` исполнен диапазон `0x144522904..0x144522aa9`:
выбор источника ключа, вызовы setter/Save и копирование результата.
Входные registers/stack и platform byte заданы fixtures; TLS, console variable
lookup, выбор platform, prologue/epilogue полного getter не исполнялись.

Разбор GUID, StoredValue read/write, CoCreateGuid, store/section getters,
FString allocation/copy/assignment, memcpy/free и security check — явные
fixtures/captures. `SetDeviceKey` обновляет только fixture settings, а `Save`
записывает аргументы/результат в отчёт. **Тело setter, настоящий Save/load и
реестр Windows не исполнялись.**
Граница особенно важна: произвольные строки fixtures не считаются валидными GUID
настоящего parser; его bool/четыре uint32 заданы независимо.

## Восемь NM fixtures и повторный вызов каждого

| Условие fixture | Native caller outcome |
| --- | --- |
| Заполненный cache | Копирует cache, storage/parser/generator не вызывает |
| Parser=true и ненулевые words | Копирует исходный текст сохранённой строки без нормализации |
| Parser=false | Генерирует GUID, форматирует, записывает cache, вызывает StoredValue write |
| Parser=true и нулевые words | Та же ветвь генерации |
| Write=false | Всё равно возвращает созданное значение и оставляет его в cache |
| Read=false и пустая строка, parser=false | Создаёт значение; return read не проверяется |
| Read=false, непустая строка и parser=true | Принимает исходный текст; return read не определяет принятие |
| CoCreateGuid fixture возвращает failure и оставляет zero-init bytes | Caller форматирует 32 нуля и вызывает write; HRESULT не проверяется |

Во всех восьми fixtures второй вызов на том же экземпляре возвращает тот же
текст, не вызывает storage, parser или генератор. В частности, после write=false
нет попытки повторной записи на следующем вызове. Это поведение **в памяти**;
постоянное хранение после рестарта не проверено. Read=false с непустой строкой
проверяет только независимость caller от bool; такой исход реального Windows
helper не доказан. Аналогично отказ CoCreateGuid с неизменёнными bytes — fixture
контракт, не воспроизведённый отказ ОС.

## Двенадцать DeviceKey fixtures

Матрица: platform byte 3/1 × источник stored/settings/new × save flag false/true.
Все Save captures возвращают false, чтобы проверить продолжение caller.

- Platform=3 и непустая storage строка: она имеет приоритет, setter/Save не вызываются.
- Platform=3 без storage строки: используется settings либо создаётся новый GUID.
- Platform=1: storage вообще не читается, даже если fixture содержит строку.
- При использовании settings caller вызывает SetDeviceKey с flag=false, без Save.
- При генерации caller тоже вызывает SetDeviceKey с flag=false; затем только
  при входном save flag=true вызывает Save. Return Save=false не меняет результат.

Нельзя делать вывод «flag=false запрещает запись»: тело SetDeviceKey здесь
capture, его собственная ветвь StoredValue описана пока статически.
Нельзя также считать platform=1 или 3 доказанным активным типом клиента.

## Решение для бота

[Локальный реестр](../../../../../vampir-headless/DEVICES.md) должен сохранять согласованную
пару ключей и provenance. Не копировать fallback клиента так, чтобы после ошибки
диска или обновления игры молча появлялось новое устройство. Наличие значения
в памяти не считать подтверждением сохранения или server binding.
Реальные ключи основной почты пока не заполнены; auth/challenge не выполнялись.

Далее: native SetDeviceKey compare/write branches, platform/environment выбор,
Save/load persistence, затем получение реальной identity и protocol device confirmation.

Проверка: `python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_device_lifecycle.py' -v`.
Три regression tests воспроизводят отчёт и проверяют все двадцать fixtures.
