# Текущее чтение движения NPC

Источник EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это код собранного клиента; игровой actor и карта здесь не исполняются.

`PktNpcMoveNotify`: точный literal `1499220d0`, таблица `149922080`.
Leaf constructor `1456c0230` пишет этот vptr; getter `1456cf0f0` возвращает
325. Оба исполнены native. `1456d0c00` — name getter, не getter числового ID.
Внешний reader `1456c5230` читает uint64 в объект+10, две float32 через
`144aaced0` в widened double объекта+18/+20 и массив в объект+28.
Формат body: `<Q key><float32><float32><u16 count><count × 2 float32>`.

Array descriptor `149924cc0` содержит resize `1456ba460` и callback
`1456c68d0`. Callback создаёт временную запись leaf constructor `14581fea0`
(20 байт), table `149920910`, и читает её через thunk `144aad190` / slot+20.
Reader записи `145821cb0` читает две float32 через archive slot+40 в +8/+c.
Callback копирует исходные биты в массив с native stride 16, включая vptr.
`14579e690` — ранее извлечённый nested reader NPC move data: массив в +8,
тот же descriptor/callback/record. Его wire body содержит только u16 и записи.

`replay-npc-move-11316.py` исполняет на одной памяти оба полных reader, generic
array, callback, constructor и reader записи, input/archive. 2375 сценариев:
ключи 0 / 1 / 2^63 / 2^64−1; signed zero, обычные, infinity и NaN float32;
пустой массив, 1 / 3 / 64 записи. Для малых массивов проверен каждый префикс,
для 64 — выбранные границы. Проверены guards объекта / входа / хранилища,
исходные биты записей и расширенные координаты внешнего объекта.

Fixtures: выделение заранее ограниченного массива, пустое прежнее хранилище
и освобождение пустой временной записи. Изменение размера существующего массива,
повторное использование / рост, actor lookup, handler и применение в движке
не проверены. Archive float32 исполняется в обычном режиме без conversion flag.

Portable `npc_move_event.py` требует точный source SHA, bytes, точный размер,
лимит 1024 записи по умолчанию (настраиваемый 0–4096) и 64 KiB body.
Сохраняет исходные float32 биты; `finite_values()` отдельно отклоняет NaN/inf.
Запрет trailing bytes строже native reader. Формат вложенного массива отдельно
доступен как `decode_npc_move_data`, без придуманного сетевого packet ID.

Это не доказательство current actor position, пути, высоты, world ID, вида NPC
или видимости. Runtime owner не добавляет сущности по одному ID 325. Следом —
current NPC create / sight записи, их обработчики и проверка на живом входе.

Материалы вне Git, корень `F:/PhoneExit Resources/Vampir/`:

- Discovery: `code-clues/release-world-packet-discovery/4abcc58ddde5285ecc156b37fe54a5ce00fe070c659781b07e1c68a00c15cebf/manifest.json`.
- Native replay: `code-clues/npc-move-11316/8f70bd3a5f3513e4e89d05e725e3c9e17fa7ac1f18db6573c98c3cc67a139a87/manifest.json`.
- Context: [точные SHA exports и leaf bytes](../../native-contexts/npc-move-11316.json).
- Дополнительные exports: `run-0fccb70d7ac4/details.json`, SHA
  `d89778a74df16a8e5e1a7ca1eb1dc6c46930a3073b277610de4aac1cd477eabd`;
  `run-5e375ca46d62/details.json`, SHA
  `93bfc63ef0a5dec3d1fca1ae43834b7279fd0a174ae9b06038870b7a97c80ca7`.
  Они находятся в `ghidra/request-exports/<полный SHA EXE>/`.

Исследование начато явными requests `13f52cb3…`, `5672b80e…`, `6b11abe3…`.
Дополнительные адреса выбраны по descriptor / native callback; полный EXE
повторно не экспортировался. Native check не выполняет авторизацию или команды.
