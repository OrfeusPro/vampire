# Полное чтение NPC create текущего клиента

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Именованный `PktNpcCreateNotify`: таблица `149921f88`, getter `1456cf0d0`
возвращает ID 324. Constructor `1456c01c0` и reader `1456c5180` исполнены native;
reader читает bool в объект+10 и `PktNpcCreateData` в объект+18.

## Проверенный формат

`PktNpcCreateData`: constructor `14579a5a0`, reader `14579e590`, таблица
`149921f40`. В +8 находится `PktNpc` (таблица `149921ec8`, reader `14579e350`).
Сначала идут uint64 в NPC+8, uint32 в +10, три float32 в widened double +18,
heading byte через `PktYaw` в +30, uint64 в +58 / +60 / +68, bool в +70,
uint32 в +74, uint64 в +78. Затем:

| Поле объекта NPC | Wire |
| --- | --- |
| +80 | uint16 count и массив `PktEffectData` |
| +90 | byte, clamp 22 |
| +98 | bool присутствия и `PktNpcParam`: bool, uint64, uint64 |
| +c8 | bool присутствия и `PktCharacterAppearance` |
| +118 | bool присутствия и map byte → byte clamp 9, три uint32, uint64 |
| +178 | uint16 count и массив `PktStat`: uint32 / uint64 |
| +188 / +190 | два uint64 через archive wrapper |

После NPC следуют поля CreateData: uint32 +1a0, вложенный массив XY move +1a8,
uint64 +1c0, optional ActorOwner +1c8 (byte clamp 9, uint64, UTF-8 string,
uint64), optional QuestVisible +208 (два uint64), byte clamp 22 в +230,
float32 +234 и uint32 +238. Все offsets в этом документе — hex.
Минимальное тело всего ID 324 — 112 байт.

Appearance, map insertion, UTF-8 и input/archive используют уже проверенный
код клиента и общие storage fixtures из прежнего whole CharacterList replay.
Эффекты — [отдельно проверенный reader](HEADLESS-NPC-EFFECT-11316.md),
move — [отдельно проверенные XY records](HEADLESS-NPC-MOVE-11316.md).
Map дубликаты дают последнее значение; стоимость всех wire entries учитывается,
даже если они затем перезаписаны.

Это raw layout. uint32 NPC+10 пока не объявлен семантически доказанным ID таблицы
NPC, поле +8 — подтверждённое uint64 без доказанного связывания с actor lookup.
Само название пакета не устанавливает видимость, мир, тип монстра или его имя.

## Native и portable

`replay-npc-create-11316.py`: 54 явно заданные функции из 20 source-checked
exports исполняются на одной памяти вместе с constructors / optional wrappers /
array callbacks / map insertion / native input и UTF-8 conversion. Новый scope
в harness допускается только для этого SHA, размера и набора опорных NPC readers;
общие лимиты других исследований не увеличены. Полные SHA exports, leaf ranges
и math import descriptors — в [контексте](../../native-contexts/npc-create-11316.json).

323 целых сценария: все 32 комбинации пяти optional blocks с пустыми / непустыми
массивами, все 256 wire heading bytes, 8 effect records, полностью нулевое
минимальное тело. Проверены Unicode `Тест日本😀`, uint64 максимум, bool normalization,
enum clamps, signed zero XYZ и исходные биты float32 в эффектах / пути / +234.
454 префикса одного тела с наполненными blocks отклонены native и portable;
cursor, вход, frame guards и выделенное хранилище проверены. Лишний байт native
не потребляет и принимает; portable требует точного размера.

Yaw reader исполнен с настоящими `14150d330`, `14150b060`, source SSE2 sincos
`1487ea130` и точными leaf wrappers. Импорты `atan2` / `fmod` сверены по PE и
исполняются текущей системной `ucrtbase.dll`; SHA проверяется до / после replay
и включён в ключ knowledge check. Python math не подменяет эти функции.
ISA dispatch задан как SSE2. AVX и исключительные huge / nonfinite math inputs
не проверены; portable сохраняет исходный heading byte без engine canonicalization.

Fixtures ограничены хранилищем: пустые прежние массивы, reserve до 8 записей,
allocation/free строк, map reset/rehash/bit capacity и unseen-key predicate.
Существующие записи и их allocator lifetime / повторное декодирование не проверены.
Неизвестная ветвь, рост зарезервированного массива или неразобранный call завершают
проверку ошибкой, а не считаются успешно обработанными.

`npc_create_event.py` — лёгкий декодер с явным SHA guard, неизменяемыми records,
64 KiB byte limit и общим лимитом 0–4096 nested wire entries (по умолчанию 1024).
Переиспользует `SelectionRecord`, `WireVector3`, `WireHeading` и NPC move decoder.
Строки проходят существующую строгую UTF-8 policy; неизвестные scalar fields
не получают игровых имён. Vector bits требуют отдельного `finite_values()`
перед использованием. Все целые сценарии сверены по каждому decoded field с native.
Отдельные тесты проверяют SHA / byte / count / trailing / nonfinite guards.

## Границы и воспроизведение

Runtime owner ещё не добавляет окружение по ID 324. Не выполнены handler /
actor association, sight leave, смена мира, сопоставление другим игрокам и живой
проверочный вход. Этот результат не подтверждает отображение живых монстров.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-npc-create-11316.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/npc-create-11316.json
python -m unittest discover -s phone-exit/bots -p test_vampir_npc_create_11316.py
```

Результат вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/npc-create-11316/84bf6c0c6c6aa04da12b16f1100e6a2c7cdc906767dc9db6f0430ada87a70f74/manifest.json`.
SHA256 `84bf6c0c6c6aa04da12b16f1100e6a2c7cdc906767dc9db6f0430ada87a70f74`.
Первый explicit request `ee59c80bfb961782373a3891dfab8a2d47c05d96cc3b25dbbf6050ee88fc19f8`,
уточнение unwind roots — `eae063a3a88f4cb646f9faa7e8f13e58b51f9c5642c40a88f448d27a6628130c`.
Итоговый request с зарегистрированным whole check —
`ce198785c559e11c8cf1fa1bb741e4dc1eaa6e59c5721f3bb9d5823287006591`.
Выгружены только пять недостающих functions, остальной код взят из готовых exports.
Следом — source-bound handler ID 324 / sight leave и изолированный lifecycle entities,
затем подключение наблюдателя к живому потоку без разрыва владельца сессии.
