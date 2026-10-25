# Вложенная запись эффектов NPC текущего клиента

EXE 1.13.16, полный SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это проверка кода собранного клиента; игровой клиент и сеть не запускаются.

В ветви NPC create найден массив записей `PktEffectData`. До подключения всего
NPC create отдельно исполнены полный constructor `14578f6b0`, reader
`145792250`, optional wrapper `1456b7060`, constructor vector `14581fec0`
и reader `145821d00` вместе с настоящим input/archive на одной памяти.
Таблица `149921b58` связана с literal `PktEffectData` и reader через slot +20;
optional table `14991fc10`, vector table `1499203c8` также сверены с PE.
Полные SHA exports и точные leaf bytes — в
[контексте replay](../../native-contexts/npc-effect-11316.json).

Порядок wire / размещение в объекте:

| Wire | Offset объекта |
| --- | --- |
| uint64 | +8 |
| uint32, uint32 | +10, +14 |
| uint16, uint16, uint16 | +18, +1a, +1c |
| uint64, uint64, uint64 | +20, +28, +30 |
| uint32 | +38 |
| bool присутствия | +48 |
| если присутствует: float32 × 3 | +58, +5c, +60 |
| bool | +68 |

Offsets записаны в hex. Тело без vector — 52 байта, с vector — 64 байта.
Назначение scalar fields и vector в игровых эффектах здесь не устанавливается.
Нельзя использовать этот vector как координату NPC по одному совпадению типа.

`replay-npc-effect-11316.py`: 7656 native сценариев. Три набора scalar fields
(нули, максимумы соответствующих беззнаковых ширин, смешанные), bool bytes
0 / 1 / 2 / 255, vector с signed zero, обычными значениями, infinity / NaN.
Для каждого тела проверен каждый префикс: полный принимается, обрезанные
отклоняются без выхода за ввод; guards объекта / archive / input неизменны.
Проверены все scalar offsets, нормализация любого ненулевого bool в 1,
исходные float32 биты и zero initialization отсутствующего vector.
Trailing byte native принимает, не потребляя его; будущий portable decoder
должен отдельно определить strict exact-size policy.

Единственный boundary fixture — проверяемый ограниченный memcpy. Рост массивов,
allocation, string / map callbacks для этой записи не требуются. Archive conversion
flag выключен. Replay не подтверждает внешний NPC create, array callback /
stride / reuse, actor, видимость, действие эффекта или фактический сетевой пакет.
Runtime модель окружения пока не изменена.

Воспроизведение из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-npc-effect-11316.py
python -m unittest discover -s phone-exit/bots -p test_vampir_npc_effect_11316.py
```

Результат вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/npc-effect-11316/89daaf52346e16b382c61b65b99010fa88313f594526a1a8e0edfbd4774b690e/manifest.json`.
SHA256 `89daaf52346e16b382c61b65b99010fa88313f594526a1a8e0edfbd4774b690e`.
Первый explicit request — `5c869cc34a018377b479ee54db6b7368747c5a85c990163bff761930d6124cdf`;
после регистрации проверки — `258df8b56e9e9d099381af4bf7c565b119bfc969fce133206a976c9a686f9290`.
использованы уже готовые exports, без повторного Ghidra или массового EXE export.
Следом — whole NPC create с этой записью, остальными optional fields и массивами,
затем семантическая привязка / удаление / смена мира и проверка в живой сессии.
