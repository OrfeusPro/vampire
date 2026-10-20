# Лобби: Version перед запросом и отправка накопленного буфера

20 октября 2026. Продолжение [handshake лобби](HEADLESS-LOBBY-HANDSHAKE.md).
Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Ghidra 12.1.4: 324 функции, 150 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-51cab8734b5e`.
Manifest SHA256: `b5d57259c7d197264c8f8fd056ece332287a3ca15882076881fa3c10cca71e44`.
functions.json SHA256: `964e612982ec3a33f1cf085b8d3119feaccb22c070c24bd11f04965b79f58969`.
Сначала прочитаны прежние экспорты sender / preparation, затем добавлены
base initialize, constructor, connect, connected recipient и lower send-A.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-send-frames.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-connect-flow.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_send_frames.py -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_connect_flow.py -v
```

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Имя | SHA256 | Сценарии |
| --- | --- | --- |
| lobby-send-frames.json | 7a0c35af35e8266580553c9af5aad040ee3bb72b83378e3e6e593c41e10d1173 | 12 полных кадров |
| lobby-connect-flow.json | ecf6be05298a35f0e534b14c6992f4345ec5055a64132f62c8abdb2b52e0070d | 8 wrapper, 4 connected callback |

Отчёты сохраняют SHA исходника / инструментов / предыдущих результатов,
байты и file offsets участков. Capstone 5.0.6 / Unicorn 2.1.4 остаются
исследовательскими зависимостями вне runtime.

## Псевдокод пропустил отправку Version

Wrapper `0x144aa89b0` читает state через `0x14420a250` у wrapper+0x30.
При raw state 2 он вызывает свой virtual slot +0x40, который создаёт
LobbyVersion. Если packet pointer непуст, call **0x144aa8a06** вызывает
lower sender **0x144aa9da0** с этим пакетом. Затем tail jump
**0x144aa8a9b** передаёт тому же sender исходный запрос.
При других проверенных states 0 / 1 / 3 подготовка Version пропускается.
Это raw значения условий; имена состояний по номерам не угаданы.

Ghidra в `Lobby_SendPacket.c` ошибочно пометила промежуточные blocks как
unreachable и показала в этом файле часть lower sender вместо точного wrapper.
Инструкции и native replay подтверждают **Version, затем исходный запрос**.
Нельзя использовать удалённую decompiler ветвь как доказательство отсутствия
этой отправки. В новом replay state getter, preparation и lower sender —
fixtures / captures. Сам wrapper исполняется целиком; shared control block
у подготовленного пакета равен null, refcount cleanup branches не проверены.

## Настоящие кадры send-A для двух lobby packets

Исполнен прежний проверенный assembly slice `0x144aa9e6a..0x144aa9f45`,
теперь с настоящими таблицами, ID getters и полными writer:
PktLobbyVersion / ID 1 и PktLobbyServerListRead / ID 103.
Формат: LE24 общей длины, затем XOR от CRC32 LE32 + ID LE16 + sequence LE16 + body.
CRC покрывает ID / sequence / body; ключ — fallback `0x9ab378c9d02084a7`.
Счётчик берётся из peer+0x228 и увеличивается с wrap uint16.

Двенадцать native cases: два типа, пустые / Unicode строки, sequence
0 / 255 / 65535. Проверены все байты кадра и следующий sequence.
Архивы заранее выделены, входные поля явные, allocator / string / CRT helpers
используют прежние ограниченные fixtures. Полный lower sender, его cleanup,
connect и syscall этим assembly slice не исполняются.

В runtime добавлены отдельные `encode_lobby_version_frame` и
`encode_lobby_server_list_frame`. Они принимают только соответствующий lobby
тип, явный sequence и byte budget. Игровой VersionPayload отклоняется.
Сокетов и автоматического выбора порядка запросов эти helpers не содержат.

## Connected callback и буфер

Lobby peer constructor `0x144aa8ac0` устанавливает listener table
`0x14961af58` в peer+0x200; её slot +0x18 ведёт на `0x144aa96b0`.
Constructor также обнуляет word peer+0x228. Это статическая проверка
конструктора; он не исполняется в новом harness.

Recipient получает this = peer+0x200 и выполняет:

1. Получает сокет peer и вызывает configuration helper с аргументами 2 / 16 / 1.
2. При специальном флаге меняет bytes peer+0x262 / dword +0x264 и вызывает helper.
3. Проверяет длину pending buffer peer+0x230. Если она положительна,
   передаёт pointer / length в `0x1445eac20` с this = peer, затем очищает буфер.

Четыре native сценария покрывают пустой / непустой буфер и специальный флаг.
Queue capture получает точно заданные bytes, после него вызывается clear.
При пустом буфере нет ни queue, ни clear. Заданный sequence 97 сохраняется:
callback **не обнуляет** его, что отличается от найденного игрового recipient.

Pending buffer здесь — явная конкатенация двух native frame vectors с sequence 0.
Это проверка сохранности байтов, не корректная последовательность сессии.
Buffer accessors / queue / socket configuration / diagnostics — fixtures;
реальная readiness notification, buffer backend и Winsock send не исполнялись.

## Адрес и оставшиеся границы

Экспортированный connect `0x144aa90c0` копирует global FString
`0x14b520cd0` в peer+0x250 и word `0x14b520cb0` в peer+0x260,
создаёт endpoint и вызывает общий lower connect `0x1445ea1b0`.
На этом этапе globals не подменены значениями CDN: применение config к ним
ещё не связано воспроизводимой проверкой. Это остаётся отдельным входом
перед настоящим подключением лобби.

Пять новых тестов, пять прежних send-frame и четыре lobby codecs прошли.
Три проверки экспорта Ghidra также прошли. Новых внешних запросов, запуска
игры и использования auth-данных не было. Далее — native preparation / source
config handoff и lower connect / pending queue вместе, затем ответ списка
серверов ID 104 и игровой endpoint. Реальная сессия ещё не получена.
