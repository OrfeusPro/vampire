# Получен настоящий список игровых серверов

20 октября 2026. На одном соединении через HK выполнено:
SDK SignIn → LobbyVersionResult 0 → LobbyLoginResult 0 → ServerListReadResult 0.
Полный body ID 104 размером 11 338 байт разобран: **55 групп и 98 серверных
записей**. Игровое подключение и получение персонажей ещё впереди.

## Источники и native проверка

Собранный Windows-клиент, не исходный C++ проект. EXE SHA256:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 343 функции, 153 предупреждения. Экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-89645e3bde4a`.
Manifest SHA256: `c188ebd134ca4212e5931bde803f522ef72ec906626655589406d4326af6132d`.
functions.json SHA256: `de4a6cfe875c90d3029286cea1db79796dbc4f742f0e249b9fe570a1edd0ae3f`.

Reader ID 104 — 0x14574ae20. По его descriptor tables экспортированы
array callbacks 0x14574c790 / 0x14574c630, records 0x14574ad20 / 0x14574ab50,
map callbacks 0x14574cec0 / 0x1456c35c0, nested string array / item
0x14570b2c0 / 0x145712790. Переиспользованы прежние archive / UTF-8 / uint32
array / TimeBase routines. Реальные descriptor bytes сохранены отдельно.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-server-list-reader.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_server_list.py -v
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/lobby-server-list-reader-replay.json`.
SHA256: `2ab53cd3aaf2e3d059857bffe6677fe0e5687acb4f950f4b4a8d093d8d435265`.
В нём source/tool/dependency SHA, fragments, descriptors/vtables, десять
полных bodies и 21 короткий префикс минимального body. В replay исполняются
whole reader, record readers, array loop/item append и map lookup с заменой
повторного ключа. Packet zeroed, reserves / map insertion / copy / cleanup /
allocator — bounded fixtures; single-bucket hash topology synthetic.
Constructors, handler и сеть не входят в этот native replay.

## Wire schema и portable decoder

| Поле ID 104 | Содержимое wire |
| --- | --- |
| +0x10 | LE32 result code |
| +0x18 | LE16 count, group records: u32 / string / u32 |
| +0x28 | LE16 count, server records ниже |
| +0x38 | LE16 count, массив LE32 |
| +0x48 | LE16 count, пары LE32 key / LE32 value |
| +0x98 | LE16 count, пары LE32 key / raw LE64 TimeBase value |
| +0xe8 / +0xe9 | bool byte / enum byte с clamp 5 |
| +0xf0 / +0x100 | две строки |
| +0x110 | bool byte |

Server record: два u32 (+8/+0xc), две строки (+0x10/+0x20), два u16
(+0x30/+0x32), enum bytes с clamps 6 / 5 (+0x34/+0x35), строка +0x38,
четыре bool bytes +0x48..+0x4b, u32 +0x4c, массив строк +0x50,
enum byte clamp 22 (+0x60), u32 +0x64 и bool +0x68.
String: LE16 длина UTF-8 в байтах, затем bytes. Vptr/padding не передаются.
Минимальный ID 104 body — 21 байт. Семантика неизвестных полей не назначена
по размеру или имени record; endpoint binding — следующий отдельный шаг.

`vampir_core.lobby_server_list.decode_lobby_server_list` возвращает immutable
группы / записи / maps, скрывает строки из repr. Byte budget и aggregate item
budget обязательны. Все wire entries, включая nested strings и duplicate map
keys, расходуют бюджет до замены повторов. Bool нормализуется, enum clamps
сохраняются. Exact-body и строгий UTF-8 / code point policy — локальные
ограничения runtime, не заявленное поведение сервера на malformed inputs.

Четыре теста сравнили все поля десяти native cases, повторные ключи, бюджеты,
enum / flags и Unicode. Все короткие префиксы этих десяти bodies отклонены
portable decoder; native проверка коротких входов покрывает 21 префикс
минимального body. Непустой native record copy остаётся fixture, не проверкой
полного Unreal ownership / lifetime.

## Подключение запроса к лобби

`exchange_lobby_login` получил необязательный явный `server_list` payload.
После успешного ID 4 отправляет ID 103 / sequence 2 и декодирует ID 104.
Без payload прежний Login-only режим сохраняется. При отказе Login запроса
списка нет. Response сохраняется в скрытом поле результата только в памяти;
CLI выводит code/count/length summary. После результата сокет закрывается.

CLI требует `--read-server-list --server-policy-byte 0` для этой попытки.
Policy byte 0 выбран явно; его смысл пока не доказан. Request использует
source path initial empty player text → NMDeviceKey, отдельный NID, Windows
platform 2 и последний byte 0. Это явный профиль собственного клиента;
серверный ответ подтверждает его работоспособность в этой проверке.

## Реальный обмен через HK

Свежие CDN/GMC2 snapshots получены через тот же личный SOCKS 17948:

| Snapshot | Manifest SHA256 / имя каталога |
| --- | --- |
| public-cdn-snapshots, HTTP 200, 6000 байт | b5f16dbc7583ac801f268055d7e3ca1bf21682cd68996ffdb3a6c0dbd7ec6025 |
| public-gmc2-snapshots, HTTP 200, 13777 байт | e906c01fd140e63baf6e91caea4bdae6b9fcef81677b8ebec5e22bb1c0fa1cd9 |

Каталоги находятся в `F:/PhoneExit Resources/Vampir/`, файл `manifest.json`.
Свежий SDK SignIn принят. Одна попытка дала IDs 2 / 4 / 104, все code 0.
Отправлено 545 байт, получено 11 466; body ID 104 — 11 338 байт.
Результат decoder: 55 групп, 98 server records. Raw response / SDK token /
session strings не сохранялись и не выводились. Игра не запускалась.
Все сокеты закрыты, временный HK-клиент остановлен с exit 0.

Прошли четыре decoder tests, пять lobby exchange tests, четыре lobby codecs,
13 ReceiveStream и три проверки Ghidra — всего 29 целевых проверок.
Далее — source consumer серверной записи → корректный endpoint и выбор
сервера, игровой Version/Login, затем список/выбор персонажа и позиция.
