# Migration allocation: native обёртки не обнуляют tail

19 октября 2026. Продолжение [channelKey migration](HEADLESS-SDK-TOKEN-PAYLOAD.md).
Источник — собранный Windows EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Исходного C++ проекта нет; source-bound instruction evidence из клиента.

Инструмент `replay-sdk-migration-allocation.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-migration-allocation-replay.json`,
SHA256 `1a685e88fe34e855ab6fa53c349d102a852284a70d22fa70370b37ee88cfdd37`.
Сохранены wrapper/leaf bytes, file offsets, SHA и SHA инструмента/предыдущего
NID suffix source report. Прежний искусственный allocation helper заменён
реальными native обёртками; общий allocator backend остаётся fixture.

## Проверенная цепочка

Caller миграции задаёт округлённый count и вызывает `0x141431680` с old count=0.
Native wrapper выбирает capacity, вызывает quantize `0x14148c2a0`, сохраняет
capacity в array+`0xc` и вызывает `0x141431210`.

`0x141431210` вычисляет byte size, получает alignment и передаёт запрос
`0x14148c8d0`. Последний берёт объект global `0x14b27ef48` и вызывает его
virtual slot+`0x38`. Quantize leaf обращается к тому же объекту, slot+`0x60`.
Этот backend object/vtable в replay — явная fixture, активный allocator игры
не установлен. Quantize возвращает запрошенный size; realloc возвращает новую
память с заполнением00 или AA. Настоящая память процессов не читается.

Цепочка wrappers, их ветвления/аргументы/count/capacity исполняются native.
В рассмотренном пути нет дополнительных записей, обнуляющих новые byte buffers.
Позднейший caller пишет только байты channelKey, а остаток rounded size
сохраняет fill backend fixture.

## Десять synthetic scenarios

Длины16/17/31/32/33 × fill00/AA. Quantize и realloc получают округлённые16/32/48
bytes, alignment1. Native byte-minus1/AES-NI/HEX pipeline исполнен как ранее;
результаты совпали с независимым AES-256 ECB с **явно заданными** tail bytes.
Для aligned значений fill не влияет; для unaligned влияние сохраняется.

Это уточняет прежнее неизвестное: **wrapper не гарантирует zero padding**.
Это всё ещё не доказывает, чем настоящий backend заполняет память, и не даёт
оснований объявлять случайность/утечку в живой игре. Actual allocator vtable,
ветви повторного использования памяти, out-of-memory и полный lifecycle не проверены.
Нельзя переносить fixture00 в runtime как якобы доказанный native padding.

## Приоритет следующей работы

Перенос старых сохранений — отдельная зависимость совместимости, а не доказанная
предпосылка нового email входа. Общий runtime suffix helper остаётся ограничен
проверенным aligned subset; готовая миграция произвольных старых файлов не заявлена.
Для первого нового профиля продолжать SDK sign-in response → SDK token/player/
expiry/errors → game Login, сохраняя открытой задачу совместимости миграции.

Активный auth/device context, реальные identity, успешная запись/read-back
SaveGame и подтверждение устройства остаются необходимыми отдельными этапами.
Реальные tokens/keys/Saved/registry/процессы/HTTP не использованы.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_migration_allocation.py' -v`.
Тест воспроизводит report, все десять native scenarios и independent cipher result.
