# Vampir — общий указатель найденных функций и связей

## Игровой Version: подтверждение реальным сервером, 20 октября

Связь record+0x0c / host+0x20 / port+0x30 применена к свежему ID 104.
Игровой endpoint server ID 101 принял Version: ID 2, код 0, обмен 199 / 25
байт. Поля собирает существующий Windows builder; локальный IPv4 берётся
из текущего соединения. Login и персонажи остаются следующим шагом.
[Источники, SHA и реальная проверка](../vampir-headless/LIVE-GAME-VERSION.md).

## ID 104 record → игровой endpoint, 20 октября

Update key source 0x145d4b585 читает record+0x0c; copy slice
0x145d4b625..0x145d4b6cf сохраняет строки / порты в master value.
Затем native BeginGame / ConnectToServer получают host+0x20 / port+0x30.
16 связанных native scenarios, bounded runtime выбор по явному server ID.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-RECORD-ENDPOINT.md).

## ID 104: полный decoder и реальный список серверов, 20 октября

Reader 0x14574ae20, server/group 0x14574ab50 / 0x14574ad20,
arrays 0x14574c790 / 0x14574c630, maps 0x14574cec0 / 0x1456c35c0.
Nested string array 0x14570b2c0 / item 0x145712790. Десять native bodies,
bounded runtime decoder; реальный ID 104 code 0: 55 групп / 98 записей.
[Источники, SHA и границы](../vampir-headless/LIVE-LOBBY-SERVER-LIST.md).

## Настоящий LobbyLoginResult 0 и начальный server ID, 20 октября

GamePeer constructor 0x144aab540 пишет dword peer+0x270 = 0;
явный SDK-only headless context (kind 0, NID UserInfo absent) получил
LobbyVersionResult 0 и LobbyLoginResult 0 через HK. Login body 90 байт.
Индекс сохраняет 49 calls lobby getter / server setter; candidate +0x64
не объявлен kind без идентичности объекта. Игровой вход ещё открыт.
[Источники, SHA и проверка](../vampir-headless/LIVE-LOBBY-LOGIN.md).

## LobbyLogin preparation и constructor, 20 октября

0x1467a9360 → constructor 0x145744fa0 → sender boundary 0x144aa89b0:
16 native scenarios с getter 0x144aaaa10. Constructor на 0x145744fa7
пишет raw byte +0x80 = 7. Дополнительная numeric branch выключена флагом
Version, поле +0x6c остаётся 0; selected-server ID передаётся без замены.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-PREPARATION.md).

## LobbyLogin writer и NID UserInfo, 20 октября

Writer 0x145756e80: 24 native bodies, отдельный runtime payload.
SDK player accessor 0x145606660 → GetPlayerId 0x144524d80.
NID text accessor 0x145604960 → UserInfo loader 0x145604090;
serializer 0x144551060 связывает +0x170 с I_JoinedCountryCode.
Collector 0x145604bf0 / selector 0x1455fb550: 27 compiled key calls.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN-WRITER.md).

## CDN → lobby endpoint и настоящий VersionResult, 20 октября

SetServerList на 0x145662389 / 0x1456623c5 пишет globals 0x14b520cd0 /
0x14b520cb0; connect 0x144aa90c0 использует их для endpoint. 20 native cases
проведены на одной машине. Лобби использует uncompressed offset 0; после
исправления runtime probe реально получил ID 2 / code 0 / body 23 через HK.
[Источники, SHA и ограничения](../vampir-headless/LIVE-LOBBY-VERSION.md).

## Порядок Version и pending flush лобби, 20 октября

Wrapper 0x144aa89b0: call 0x144aa8a06 отправляет подготовленный Version,
tail jump 0x144aa8a9b — исходный запрос. Нижний send-A 0x144aa9da0.
Connected recipient 0x144aa96b0 переносит pending peer+0x230 в queue,
sequence peer+0x228 сохраняется. Connect 0x144aa90c0 читает глобальные host / port.
Восемь wrapper, четыре callback cases и 12 полных native frame vectors.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-CONNECT-FLOW.md).

## Handshake лобби и список серверов, 20 октября

PktLobbyVersion writer 0x145757490, Result reader 0x14574b170;
ServerListRead writer 0x145757260, Result reader 0x14574ae20.
Таблица peer 0x149d84d78: slot +0x40 → 0x1467aae20 (preparation),
установлена construction 0x1467a79e0. Getter 0x1415be7e0 — GetComputerNameW.
Два writer и VersionResult reader проверены native; ID 104 collections открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-HANDSHAKE.md).

## Лобби: Login и загрузка списка серверов, 20 октября

Lobby Login 0x1467a9360 → sender 0x144aa89b0 (send-A).
LobbyLoginResult handler 0x14677ec50 переносит две строки в поля игрового Login.
Reader 0x14574aa80: три LE32, пять строк, LE32; семь полных native cases,
72 коротких префикса. ServerListReadResult handler 0x14677f350 →
master model Update 0x145d4afe0. Connect / список на wire ещё не закрыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOBBY-LOGIN.md).

## Вызов владельца через поле объекта, 20 октября

`0x14430da70`: получатель из `object+0x158` → virtual `+0x7b0`.
Полное тело исполнено с тремя настоящими таблицами владельцев до ID205.
Соседние кандидаты `0x143c1ce70/0x143c1cfd0` используют поле `+0x300`;
идентичность классов по номеру слота не утверждается. Происхождение `+0x158` открыто.
[Источники, проверки и границы](../resource-tools/vampir/HEADLESS-WORLD-OWNER-DISPATCH.md).

## Владелец и отложенная отправка ID205, 20 октября

`0x1468e2aa0` / `0x1468e2a20` / `0x1468e2a60`: таблицы с policy 3 и
slot `+0x7b0` → `0x1468f1e90` → service `+0x80` / `0x14560dc10`.
При наличии мира `0x14561b390` пишет состояние 4; callback `0x143642370`
вызывает service `+0x70`. Источник engine-вызова и movement ещё открыты.
`0x146765c50` — `MoveToSelectCharacterResult`, возврат к выбору персонажа.
[Адреса, SHA и границы](../resource-tools/vampir/HEADLESS-WORLD-FINISH-OWNER.md).

## Полное чтение ID206 до обработчика, 20 октября

Массив `+0xe8`: `0x145771940` → raw u64 через `0x144aa5b90` и optional
`0x1456b2ce0` → вложенный reader `0x1457989f0`. Конструктор вложенного значения
`0x145794d70`. Проверены все непустые массивы и чтение → обработчик ID206.
Общий `decode_world_move_finish_result` не определяет готовность сессии.
[Источники, API и ограничения](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-DECODER.md).

## Чтение ID206, 20 октября

Таблица `0x149919eb8`: reader `0x145844d70`, writer `0x14584d030`.
Подтверждён минимальный профиль размером 81 байт; массивы пусты.
Новый массив `+0xe8`: reader элемента `0x145771940`, вложенный `0x1457989f0`.
Непустые массивы ещё не исполнены, общий декодер остаётся открытым.
[Источники, схема и границы](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-READER.md).

## Запрос завершения перемещения, 20 октября

`0x145dc2930` → условие `0x145619bf0` → конструктор `0x145842880`,
таблица `0x149919e68`, ID 205. Тело пустое; состояние 2, 3 или 4 переходит в 5
перед отправкой. Проверены native writer/framing/очередь через отдельный сценарий.
[Источники, поля, API и границы](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH-SEND.md).

## Завершение перемещения между мирами, 20 октября

Пакет `PktWorldMoveFinishResult`, ID 206, таблица `0x149919eb8`, конструктор
`0x1458428a0`. Обработчик `0x1467a5d30` → `0x145dbef80` → виртуальный
слот сервиса `+0x78` / `0x145dbcbe0` → запись состояния 6.
Привязка проверена по регистрации, таблицам, ID-функции и строкам диагностики.
Wire-тело и промежуточный обмен после выбора ещё не разобраны.
[Источники, поля и ограничения](../resource-tools/vampir/HEADLESS-WORLD-MOVE-FINISH.md).

## Потребитель состояния сервиса, 20 октября

`0x145d7b850`: getter сервиса → беззнаковая проверка `service+0x30 >= 6` →
конструктор `0x1456bb2a0` → handoff с kind `0x13f`. Этот kind не объявляется ID
пакета. `0x14560d7b0` отдельно записывает состояние 6; caller ещё не установлен.
Инициализация `0x145608fb0` записывает 7, очистка `0x145601570` сохраняет байт.
[Источники и проверенные ограничения](../resource-tools/vampir/HEADLESS-SELECTION-STATUS-CONSUMER.md).

## Состояние сервиса после выбора, 20 октября

`0x1456140f0` записывает байт аргумента в `service+0x30`; затем getter
`0x14563d980` → приёмник диагностического текста `0x145636eb0`.
Проверены отдельные записи и полный путь ID110. Рассылка события не доказана;
смысл значения 1 как готовности сессии пока не установлен.
[Источники, SHA и продолжение](../resource-tools/vampir/HEADLESS-SELECTION-STATUS.md).

## Обработчик ID110 и применение данных, 20 октября

`0x14675e9a0` → фильтр `0x1467a8e10` → получение объекта `0x145c8ba50` →
применение `0x145d61e60` → метод сервиса `0x145dbe660`. Подтверждены записи
вектора и флагов в тестовый объект персонажа; внешние подсистемы перехвачены.
Функция `0x145dea660` использует `GetActiveWindow` / `SetWindowTextW` и относится
к заголовку окна. Потребитель мировой позиции пока не установлен.
[Точные поля, исходные диапазоны и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-HANDLER.md).

## ID110: таблицы и общий декодер, 20 октября

Значение таблицы `main+0x98`: функция чтения `0x145796480`, вложенный блок
`0x145796df0`, элемент вложенного массива `0x145796d60`. Проверены непустые
данные, коллизии и замена повторных ключей. Общий декодер читает подтверждённое
тело ответа с ограничениями ресурсов. Обработчик `0x14675e9a0` ещё не проверен.
[Адреса, схемы и подтверждённые границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-DECODER.md).

## ID110 nonempty arrays, 20 октября

Whole reader:34 full/465 short cases, все 11 arrays. Readers main+1c8:
1457f0540; +1f8:14578b840→optional 1456b2ce0→3float reader 145817d60;
+250:145782c40. Vtable slot 20 readers, slot 10 writers; имена исправлены по
dispatch. Array168 resize1456b6000 — reviewed28 byte leaf без unwind.
Map98 value ctor 145793d90→table 1498cf350→reader 145796480 (экспорт ещё нужен).
[Схемы всех callbacks, SHA и продолжение](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-COLLECTIONS.md).

## ID110 reader и raw vector apply, 20 октября

Outer ctor 1456d4a40/reader 1456d8f80→main reader 145780eb0. Минимум 203 bytes:
wire+61 триfloat32→main+188 триdouble; wire+73 heading→reader 145818150→
direction141507880→SSE2 sincos1487969e0/guarded fmod141444d00.
Apply145d61e60: raw24→player+20; direction→1415055b0/guarded atan214143fd00
→player+38 angles. 268 reader+22 apply cases; handler 14675e9a0 и semantic
position consumer ещё не проверены. Непустые коллекции остаются открытыми.
[Источники, SHA, callbacks и продолжение](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-RESULT.md).

## CharacterSelect callers и rawF0, 20 октября

Caller `0x145d43290` читает UI+3f8→leaf `0x145c847c0`: signed bounds,
global `0x14b57f180` records+70/count+78, stride 170. Record+8→service virtual 50.
State getter `0x145c859f0` читает тот же global; setter `0x145c930d0`
получает ID102 packet+40 и пишет state+f0→ID109 raw20. Current state изменяемый.
WaitingEnd/quick helper и indexed caller до native handoff/writer/frame/queue:
61 cases/19 frames; UI emitter и real socket/session остаются открытыми.
[Точные пути, SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-SELECT-SEND.md).

## ID102 nested и handler, 20 октября

Appearance item table `0x1498cff58`→reader `0x145771b40`: `<IBH`, enum clamp 45.
Optional callback `0x1456c3890`→insert `0x1456b99b0`→pair ctor `0x1456b7b90`
→value table `0x1498d1a28`/reader `0x145782b30`: key+value `<BBIIIQ`, clamp 9.
Whole list native проверка 30 bodies/489 short inputs; duplicate last-value-wins.
Handler `0x14675dce0`→gate `0x1467a8e10`/predicate `0x145c85d90`, 45 cases.
Packet+38 сравнивается с record+8, первое совпадение; sentinel0/miss→index 0.
UI+3f8 native store, helper `0x1456140f0` получает DL6; backend actions captured.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-EXTENSIONS.md).

## CharacterList owner и list/select IO, 20 октября

Owner constructor `0x1468e29a0` ставит table `0x149e0e7c8`:
slot 7b0→caller `0x1468f1d70`, slota18→actual AL1 leaf `0x140bb4a10`.
Native caller→RequestA/ID101 без policy fixture; lifecycle hook не установлен.
ID102 reader `0x1456d8d80` → array `0x144aa5c50`/callback `0x1456da1a0`
→ record ctor `0x14577d3d0`/reader `0x145781c80`. Основной профиль проверен;
appearance/optional extensions пока unsupported. ID109 writer `0x1456e53a0`
проверен: raw10/raw18/raw20 → `<QIQ`/20 bytes, 16 vectors.
[Источники, SHA, nested readers и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-CODECS.md).

## CharacterListRead caller, 20 октября

0x1468f1e48 → getter 0x1456048e0; 0x1468f1e53 → service slot 90.
Полный caller 0x1468f1d70 исполнен на 32 fixtures: второе policy value 1
ведёт в actual RequestA/constructor и send capture; первое value 2 отдельно
вызывает slot 98/owner a00. Owner type и enum names неизвестны.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-CALLER.md).

## Selection lifecycle, 20 октября

Slot08 → 0x14560e7d0 регистрирует callbacks 0x14561af60/0x14561b000.
Последний пишет state40 и вызывает dispatch/broadcast captures; первый передаёт
UI callback 0x1455f7bb0 → singleton virtual 38. 8 native cases, emitters неизвестны.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-SELECTION-LIFECYCLE.md).

## World.Id2/LevelPath — selection label

World parser literal LevelPath → FString48, World record vtable 0x1499d28a8
slot 20→getter 0x141482e60. Actual ctor/store/hash/accessor/getter с current
indexed CSV возвращают Lobby/CharacterSelect/CharacterSelect_02 для key 2.
Runtime population/mount priority не доказаны. [Source/SHA](../resource-tools/vampir/HEADLESS-WORLD-STATE-LABEL.md).

## Selection state registry lookup

0x145c5d860 → hash 0x145c60180 → descriptor accessor 0x141482990 →
record virtual 20. Native lookup/accessor проверены на 13 cases; registry и
record contents fixtures. Возврат — inline node+8/stride 150, не stored pointer.
Actual key 2 label/source неизвестны. [Source/SHA](../resource-tools/vampir/HEADLESS-SELECTION-STATE-LOOKUP.md).

## Selection virtual 40/state transition

0x145dbba60 → base 0x14560a6f0 / label 0x145dc3f30 / SetState 0x14560a400.
Guard 0x145609b00/0x14452afb0; schedule callback 0x145600690→0x144328fe0.
10 preparation + 12 independent callback cases. Slot90 dispatch остаётся
неизвестным; schedule/load/lookup backend fixtures.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-STATE-TRANSITION.md).

## Selection service derived slots

Base ctor 0x1455f9ee0 и derived prefix 0x145dc6b20 публикуют service global.
Table 0x1499f11f0: +0x40→0x145dbba60, +0x50→0x145dc05f0,
+0x90→requestA 0x145dbd4b0. Virtual50 actual packet 109→handoff110 проверен;
writer/socket/result и real slot 90 caller остаются открытыми.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-SELECTION-SERVICE.md).

## WaitingEndNotify инициирует CharacterListRead

Handler 0x146768540/table 0x149d811a0, packet table 0x1498d6b50/ID 27.
Predicate 0x145c85d90 и tail jump 0x14676864f → requestB 0x145dbfe50:
24 native branch scenarios, две request send captures. Policy backend и
selection virtual calls fixtures; requestA owner/полный Login lifecycle открыты.
[Source/SHA и границы](../resource-tools/vampir/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## Login continuation и CharacterListRead boundaries

Getter 0x146486a50 → global 0x14b58b930; ctor 0x14647f9f0 ставит derived
vtable 0x149c5f828, slot+0x28→reset 0x1464846c0. Отдельные request entries
0x145dbd4b0/0x145dbfe50 создают PktCharacterListRead/ID 101; writer 0x140bb4a10
не пишет тело. Native reset/request проверены отдельно; edge между ними неизвестен.
[Sources/SHA и границы](../resource-tools/vampir/HEADLESS-CHARACTER-LIST-BOUNDARY.md).

## LoginResult handler, 19 октября

0x146765540 → gate 0x1467a8e10: 38 native scenarios после actual body reader.
Подтверждены state stores, signed+0x48/peer flag early return, controller ID,
raw16 calculation и covered error/SDK branches. Post-state 0x1467259c0
экспортирован в Ghidra, execution capture; CharacterListRead не доказан.
[Отчёт, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-HANDLER.md).

## LoginResult reader и вложенные типы, 19 октября

0x1456d9600 / constructor 0x1456d4da0 / vtable 0x1498d6218: 21 full bodies,
332 truncated bodies. TimeBase reader 0x1457f0a90 и PeriodServerDate reader
0x1457986b0 исполняются через actual tables. Общий decoder добавлен;
handler 0x146765540 пока static-only. Пакет Ghidra расширен до 32 функций.
[Источники, SHA и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-RESULT-READER.md).

## Request handoff → Login send, 19 октября

0x144aa8020 → getter 0x144aaa9d0 → derived table 0x149d84e50+0x38 →
wrapper 0x1467aaa10 → send-B → Login writer → frame/queue. 34 native cases,
29 полных кадров; duplicate lookup и timeout selection подтверждены.
Insert/notify helpers не исполнялись, expiry/socket/session неизвестны.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-SEND-PATH.md).

## PktLogin body writer, 19 октября

0x1456e57c0/vtable 0x1498d6058+0x10: 25 native payload vectors,
40 raw IO failure fixtures. FString errors здесь могут быть проигнорированы;
scalar errors останавливают writer. Порядок 15 strings/4 u32/5 bytes/u64
перенесён в LoginPayload, frame/handoff/socket ещё не объединены.
[Source/offsets/SHA и ограничения](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-WRITER.md).

## Инструменты и пределы автоматического анализа

[Общее правило выбора](../resource-tools/vampir/ANALYSIS-TOOLS.md): Ghidra
для native-кода, CUE4Parse для совместимых ресурсов, Dumper-7 для отдельно
согласованного live reflection. Сборка инструмента не доказывает семантику
функции, работоспособность SDK или полноту протокола.

## Пакетный анализ через Ghidra

22 source-bound functions: Login/Version, reader/writer/handler, SDK getters,
request handoff/send и BeginGame/connect. Общий псевдокод/call graph: ресурсная
библиотека ghidra/INDEX.md. Analyst names и decompiler types не source C++.
[Команды, source/tool SHA и ограничения](../resource-tools/vampir/HEADLESS-GHIDRA.md).

## Login preparation и SDK field consumers

0x1467a9700 → ctor 0x1456d4c80 → handoff0x144aa8020. GetNetmarbleId
0x145604b90/0x144524940 → packet+0x30; module+0x78 accessor0x1456039c0
→ packet+0xa0. Actual server getter 0x144aaaa10 → packet+0xb0.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-LOGIN-PACKET-FIELDS.md).

## VersionResult reader/handler → Login entry

Table0x1498d69f0 ID2 reader 0x1456d9b10, handler 0x146768360 через
registration0x14678ecaf/table 0x149d81170. Native gate0x1467a8e10 covered
code 0 → 0x1467a9700; внутри static call к PktLogin ctor 0x1456d4c80.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-RESULT-HANDLER.md).

## Version send wrapper → send-B

0x1467aaa10 → thunk0x144aab2f0 ([wrapper+0x10]) → 0x144aaccf0
→ Version writer → frame → queue0x1445eac20. Gates global 0x14b520cb4,
raw helper return2, peer+0x2a5. Metadata lookup и failure helper captures.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-SEND-PATH.md).

## PktVersion writer и UTF-8

Writer0x1456e5cf0 → FString0x144aa6a30 → length 0x141446a50/convert0x141440af0/
encoder0x141439820 → archive0x14961a5c0. String uint16-byte-length + UTF-8,
три interleaved uint32; общий VersionPayload без frame/семантических имён.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-VERSION-PACKET-WRITER.md).

## Connected callback → PktVersion/ID1

Game0x1467a9cd0 → ctor 0x1456d53b0 → table 0x1498d6990; name PktVersion,
ID1, writer 0x1456e5cf0. Wrapper send slot 38 → 0x1467aaa10 capture.
Raw field+0x98=207; смысл значения и getter semantics ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECTED-VERSION-PACKET.md).

## Делегат OnTcpPeerConnected → game callback

Tail0x144aaae8d → allocator 0x1414276b0 → table 0x14900a528 slot 60
→ bridge0x14370c510 → action0x1437113ec virtual 48 → game0x1467a9cd0.
P+0x310 содержит units storage, не owner count. Callback body ещё capture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).

## Socket readiness → OnTcpPeerConnected

0x1445de8b0/action virtual+0x10 → interface P+0x50/0x1445e8900 →
peer broadcast/action virtual+0x18 → P+0x200/0x144aac520. Diagnostic name
NnPeerImpl::OnTcpPeerConnected, owner P+0x308 virtual+0x60 остаётся capture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READY-NOTIFICATION.md).

## Socket engine option getter → getsockopt

Vtable 0x149504668 slot+0x60 → 0x1445f0b10 → IAT0x148945b30,
WS2_32 ordinal7 getsockopt. Worker raw selectors0/1 → level65535/option4103.
Actual translation исполняется в readiness replay; syscall fixture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-ERROR-OPTION.md).

## Mode job/select → completion codes

0x1445eab70 → engine ioctl 0x1445f0c60 → job vtable 0x1495042d0.
Run 0x1445e8080, completion 0x1445e7d80: source-backed codes0..4
и state2→6 после option gate. Downstream recipients ещё capture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-READINESS-JOB.md).

## WSAGetLastError mapper

Engine constructor 0x1445ef620 → global 0x14b4f39d0/vtable 0x149504668;
slot+0x68 = mapper 0x1445f0680 → WSAGetLastError ordinal 111.
Native range 10035..10071, default30; accepted mappings в новом report.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-WINSOCK-ERROR-MAPPING.md).

## Endpoint connect lower/wrapper

0x1445e5c60 → 0x1445ecbb0: native sockaddr + Winsock connect boundary.
Wrapper raw errors 22/23/37 даёт true; имена WSA errors ещё не связаны.
Mode/wait branch и state+0x50=2 не доказывают готовое соединение.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SOCKET-CONNECT-RESULT.md).

## Resolved peer recipient и socket creation

Action 0x141423088 → peer+0x38 vtable+0x08 → 0x1445e8400.
Socket peer+0x110 vtable+0x08 → 0x1445e5cb0 → WS2_32 socket ordinal 23.
Constructor stores/import/export source-bound; connect/readiness ещё открыты.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVED-SOCKET-SETUP.md).

## Resolver job results и callback gates

Vtable 0x149503a80: run+0x10 0x1445e7e00, completion+0x18 0x1445e7cf0.
getaddrinfo/inet_ntop imports подтверждены; непустой payload → dispatch
0x1445de9f0/action 0x141423088, empty/error → 0x1445de8b0.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-RESOLVER-JOB-RESULTS.md).

## Lower connect/resolver selector

0x1445ea1b0 копирует endpoint в peer+0x70/+0x90/+0x94/+0xc0, затем
0x1445e6d70 выбирает lexical parse либо job+0x20 owner/+0x28 host.
0x1445db8a0 — enqueue capture; реальное completion ещё открыто.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

## ConnectToServer endpoint consumers

0x144aabcc0 выбирает primary +0x278/+0x288 либо override +0x290/+0x2a0.
0x1445e2a50 реально пишет endpoint port+0x28 и field+0x2c=0.
0x1445ea1b0 ещё capture; word+0x28a consumer остаётся открытым.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-CONNECT-TARGET.md).

## BeginGame server target mapping

0x146425730 → lookup 0x145d39440 (map entry+8) → setters
0x144aab510/500/520/4f0: transport impl+0x270 ID, +0x278 string,
+0x288/+0x28a raw words. Названия портов/протоколов пока не доказаны.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-BEGIN-GAME-SERVER-TARGET.md).

## Title flag и SDK IsSignIn не тождественны

OnSuccess head передаёт GetCountryCode в ConnectCountryCode capture;
tail пишет interface+0x230. BeginGame 0x14641809c → wrapper 0x145609b00 →
IsSignIn 0x14452afb0 читает settings+0x400. Slices разделены skip-middle.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-STATE.md).

## Title success notification: slot+0x08

0x14560f740 → 0x14560eef0 → broadcast 0x1445f5330 → action
0x141423088 → title vtable+0x08 = OnSuccessNetmarbleSDKAuth 0x14641d560.
Router NID channel getter отделён от module+0x88; handler entry capture.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-TITLE-AUTH-NOTIFICATION.md).

## Game success: optional PGS provider

0x1450b11b0 = Google::FPGSIDProvider::GetOrCreate; vtable 0x1496de728
slot+0x10 = SignIn 0x1450c35e0. Windows caller передаёт unsupported args
(400, 30020000, 1), исходный SDK result не подменяется fixture PGS result.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-PGS-BRANCH.md).

## Success action: broadcast → title slot

0x1445f5330 → leaf 0x143b8bf10 → vtable+0x30. Title constructor stores
связывают 0x149c4cda0 с object+0xa18; slot+0x30 равен 0x14641dbc0.
Handler вызывает child+0x598 (2,1) и очищает interface+0x228.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-SUCCESS-BROADCAST.md).

## Silent result до game callback

ExecSignInSilently 0x1444e02e0 → thunk 0x1444d8410 → bridge →
leaf 0x1456007b0 → callback 0x1455fbb80 исполнены вместе. Request callback
0x1444d8610 → response root 0x1444cdb30 связан статически.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SILENT-GAME-DISPATCH.md).

## Channel silent → Auth silent

0x1444fee6b → 0x1444fdd00 подтверждён исполнением caller. GetAuth возвращает
service+0x150; callback в Auth silent хранится по impl+0xa8. Пустой player ID
отклоняется отдельным native gate, ChannelManager AL=1 не доказывает вход.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-CHANNEL-SILENT-HANDOFF.md).

## Game AutoSignIn: callback и route

Diagnostic → logging root 0x1455f7bd0 → caller 0x1455fbb80.
Descriptor приходит через leaf 0x1456007b0 и wrapper 0x1444fea30.
GetChannelManager owner+0x170 → SignInSilently 0x1444feac0 подтверждены
точными diagnostic literals; отделены от GetAuth owner+0x150.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-GAME-AUTO-SIGN-IN.md).

## SDK result dispatch и native delegate

auth+0x98 → dispatcher 0x1444dff20 → queued thunk 0x1444d83b0 → virtual
slot+0x60 0x14423aaf0. Binder и vtable связаны с SignIn. AL=1 после вызова
обработчика не означает успешную авторизацию.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-RESULT-DISPATCH.md).

## SDK sign-in completion

SetSignIn 0x14454c3d0 записывает settings+0x400; idpInfo относится к playerInfo.
Место вызова final dispatcher подтверждено, делегаты ещё не исполнены.
Общий parser использует отдельную строгую локальную политику.
[Источники, SHA и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-COMPLETION.md).

## errorCode variant conversion

[Native converter и vtable dispatch](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-VARIANT.md):
source-bound tag2 string/tag3 number-text →native TryGetString →CRT.
Parser selection и double fallback не доказаны. Это не полный SDK success
contract; далее idpInfo/final callback/session.

## Response predicates/JSON/errorCode

[Native SDK response gates](../resource-tools/vampir/HEADLESS-SDK-RESPONSE-GATES.md)
связаны с player traversal. _wtoi допускает malformed zero strings; общий
response parser не подключён. Numeric JSON variant, full error dispatch
и session acceptance ещё открыты.

## SDK SignIn response: player и token

[Native response field slices](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN-RESPONSE.md):
resultData.accessToken →module+0x78, nested playerInfo/player fields.
Provider token отличается от SDK token. Optional fields не очищаются caller,
full callback/errorCode/session acceptance ещё открыты.

## Migration allocation wrappers

[Native allocator chain](../resource-tools/vampir/HEADLESS-SDK-MIGRATION-ALLOCATION.md):
141431680 → quantize →141431210 →14148c8d0 →backend virtual slot 38.
10 cases не показали zeroing wrapper; backend fill fixture, реальная policy
неизвестна. Далее для нового профиля — SDK sign-in response/session.

## Token payload / channelKey migration

[Native container и migration slices](../resource-tools/vampir/HEADLESS-SDK-TOKEN-PAYLOAD.md):
parser output+0x38 — payload; подпись/claims acceptance не доказаны.
Migration field channelKey отличается от sub; aligned AES primitive reused,
unaligned allocation tail неизвестен, общего migration helper пока нет.

## NID suffix из sub и nmDeviceKey

[Native suffix transform/AES](../resource-tools/vampir/HEADLESS-SDK-NID-SUFFIX.md)
для aligned ASCII совпал с AES-256 ECB. Поле sub и getter nmDeviceKey
подтверждены source anchors; реальные tokens/keys не получены.
Общий nid_storage_path ограничен проверенным subset, без token validation/I/O.

## Auth storage gate и общий state byte

[Native auth path gate](../resource-tools/vampir/HEADLESS-SDK-AUTH-PATH.md):
netmarble context включает extra directory и byte 14b4f13fd. Save/Initialize
читают тот же global; gate false не обнуляет ранее установленный byte.
Активный context, suffix transformation и reset lifecycle неизвестны.

## Load fields и ServiceSetting.bin

[Native field restoration/filename replay](../resource-tools/vampir/HEADLESS-SDK-LOAD-DEVICES.md):
Save object+0x208 → SDK settings+0x618, +0x5a0 → NID settings+0x628.
Load filename default ServiceSetting.bin из +0x2f8, соседний +0x2e8 иной.
Global gate/tag semantics и active path ещё открыты.

## NID deviceKey / OAuth device_key

[Native pair assembly](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md)
подтверждает вызов getter 144522b50 с bool=true для web/code/refresh.
Registry v2 хранит NID key отдельно от SDK key/nmDeviceKey. Полные
web URL/JS context и реальные значения не проверены.

## SDK storage и DeviceKeyForNetmarbleId

[Save/Load index и native directory replay](../resource-tools/vampir/HEADLESS-SDK-STORAGE.md):
каталог NetmarbleSDK под base persistent directory. Отдельный NID key в
settings+0x628/DeviceKeyForNetmarbleId; web context связь ещё не доказана.
Save/load и полный filename не исполнены.

## SetDeviceKey: native body

[Setter compare/write и getter integration](../resource-tools/vampir/HEADLESS-DEVICE-SETTER.md):
force=false пишет различающееся значение, force=true принуждает запись;
write=false не предотвращает обновление settings. 56+12 fixtures.
Save/path экспортированы только статически, active storage ещё открыт.

## Device getters: cache и persistence failure

[Native getter lifecycle fixtures](../resource-tools/vampir/HEADLESS-DEVICE-LIFECYCLE.md):
NM cache/StoredValue/parser-word gate и отдельный DeviceKey stored/settings/new
выбор. Return write/Save игнорируется caller. Реальное хранение/active platform
и server confirmation не подтверждены.

## GetDeviceKey / GetNMDeviceKey: происхождение

[Windows storage, CoCreateGuid и GUID format=0](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).
Getter branches разобраны статически; default formatter/hex writer исполнены
на synthetic words. Отдельные поля, cache и сохранение не смешивать.
Real keys/active platform/confirmation protocol ещё открыты.

## Общие привязки аккаунтов и устройств

[device_registry и локальная SQLite-схема](../vampir-headless/DEVICES.md):
постоянная запись на почту, один основной аккаунт, provenance двух device keys,
ручной статус подтверждения. Это локальная модель бота, не восстановленная
серверная схема. Реальные device keys и автоматизация challenge ещё открыты.

## FAuthImpl SignIn JSON и CreatePost headers, 19 октября

1444fb800 body slices/constructor 1444bc380: 4 fixtures подтвердили 4 base fields,
optional playerId и credential. Key playerId связан service+150 → wrapper ctor
→ leaf+30 → SignIn. CreatePost14451c600 header/method slices: 8 fixtures,
application/json/gameCode/buildCode и optional accessToken/authToken alias.
Общий sdk_sign_in offline plan bind authUrl/v1/sign-in, без auth HTTP/session.
[Источники и границы](../resource-tools/vampir/HEADLESS-SDK-SIGN-IN.md).

## OnResult continuation и credential GetObject, 19 октября

1450ef437 → 14453cdf0 = UNMServiceSettings::Save; return caller игнорирует.
Затем GetChannelManager → RemoveAllCredentials → base ctor с DL=33 →
credential+58=accessToken → SetCredential wrapper/impl, map key из +50=33.
Vtable1496e16f0 slot 1 →1450e50d0 → base1444e6570: channelAccessToken/channelCode.
Четыре native fixtures с Save false/true и двумя tokens; storage/JSON/map —
явные captures. [Source/SHA](../resource-tools/vampir/HEADLESS-NID-CREDENTIAL.md).

## Query getter и percent byte loop, 19 октября

GetQuery 1445255e0 читает owner+58/+60 → decoder 141c13390; OnResult вызывает
map builder 144591880. Decoder byte loop 141c13495..141c13764 исполнен на
147 fixtures, UTF conversion и growth вне исполнения. Whole-query decode
предшествует &/= split по static caller chain; native duplicate policy открыта.
Общий sdk_percent + parse_nid_email_callback вводят strict ASCII/route policy,
не заменяют проверку токенов сервером или активного sign-in context.
[Источники и SHA](../resource-tools/vampir/HEADLESS-SDK-PERCENT.md).

## NID parser/channel: actual helpers вместо return fixtures, 19 октября

Integer 1415dea40 → verified CRT imports _wtoi/_finite/iswspace → local ucrtbase.
Channel 14452b060 + actual compare 1414596e0 + 13 native initializers: email20,
ASCII folding, unknown0. 28 numeric/45 channel/6 caller fixtures.
Общий nid_result: bounded ASCII channel mapper и decoded email result validator,
canonical0 policy строже native prefix parsing. Нет URL/I/O/storage/session.
[Источники и SHA](../resource-tools/vampir/HEADLESS-NID-PRIMITIVES.md).

## OnResult validation/adoption caller, 19 октября

Native slice 1450ee94a..1450ef437 и copy 141420cc0: 22 fixtures.
resultCode presence/length → parser ok+zero → mode bit gate → fields/channel
→ settings captures. Access 14454a480, ID 14454ba20, channel 14454a870,
refresh 14454c470; country assignment receiver settings+b0.
Missing versus empty проверены отдельно. Integer/channel returns — fixtures,
setters/persistence/callback не исполнены.
[Подробности и SHA](../resource-tools/vampir/HEADLESS-NID-VALIDATION.md).

## NID email result и native dispatcher, 19 октября

Web W → doneSignInDeepLink → nmidprovider/result; channelKey=mailUserKey,
accessToken/refreshToken/netmarbleId/joinedCountryCode. Profile gate обязателен
в обычной ветке. 12 JS fixtures, profile/policy/delivery заменены явными captures.
Native OnDeepLink 1450ed4f0: result global 14b564508 → call 1450ed92b →
OnResult 1450ee6b0; signin отдельно → OnSignIn 1450f08a0. 14 initializer
bindings подтверждены статически; native handlers не исполнялись.
[Byte offsets/SHA/ограничения](../resource-tools/vampir/HEADLESS-NID-RESULT.md).

## NID email и отдельная legacy EmailAuth, 19 октября

EXE index: 19 symbols, 20 проверенных LEA, 18 roots; native execution здесь нет.
Публичный web snapshot: doSignInByEmail → RSA PKCS1v1.5 → POST
/api/signin/netmarble; request interceptor добавляет /api и context headers.
Девять padding fixtures и три interceptor fixtures исполнены из выбранных
JS helpers с явными заглушками. Общий nid_email повторяет CESU-8 encoding,
шифрует поля и требует явные context/reCAPTCHA token, без I/O.
[Адреса, SHA256 и ограничения](../resource-tools/vampir/HEADLESS-NID-EMAIL.md).
Ответ, callback и активный провайдер остаются открыты.

## Public GMC2 response и source serviceCode, 19 октября

Ctor manager+190=netmarbles → Refresh 1444f3f54 R8 → Request 1444f534d stack+60.
Public constructor-default profile build 0/A + production/nmp/thered: GET 200,
DECKEY в HTTP headers, normal93/secret1/merged 94. Общий gmc2_response decoder
переиспользует bounded JSON/XOR/secret/map. Реальный key — PKCS8 RSA 3072;
backend DER поддерживает canonical PKCS1/PKCS8. Никакой account auth не было.
[Source/SHA/snapshot](../resource-tools/vampir/HEADLESS-PUBLIC-GMC2.md).

## SDK constants pipeline: actual append вместо raw capture, 19 октября

Общий decode_sdk_constants_string повторно использует existing unescape 1444f2670
и canonical xor_gmc2_utf16_units. Zero outcomes теперь пропускаются; старые
4096/1024 bytes budgets сохранены, empty key отклоняется. xor_sdk_utf16le
остаётся pre-append mathematical/capture transform. 18 actual-output vectors
проверены через JSON escape/unescape/composed decoder.
[Подробности](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).

## GMC2 DecryptXOR и actual FString append, 19 октября

1444ddf50: source descriptor R8 count, key FString R9 period=count-1,
word XOR 1444de015 → actual append 1414242a0. DX=0 пропускается; high units
сохраняются. 18 native fixtures, growth shim/logging-disabled fixture,
guards/terminator checks. Общий xor_gmc2_utf16_units, empty key reject.
[Источник и границы](../resource-tools/vampir/HEADLESS-GMC2-XOR.md).
Base64/DECKEY/key acquisition и вся response chain ещё открыты.

## RequestGMC2 header gates, 19 октября

Native 1444f5560..1444f57b1: URL slot 68/header slotb0/method slot 60 captures,
constructor prefix 1444bd970..bda2e header names, build getter native. 16 fixtures:
eTag count>1 и accessToken count>1 gates. Device 1444e5ff0 / player 144524d80
return fixtures. Общий plan_gmc2_get_request, frozen headers/repr redaction.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-GMC2-HEADERS.md).

## GMC2 URL assembly slice, 19 октября

1444f3a68..1444f3d7d: manager+1e8/base,+1c8/group, version getter 144524390,
settings+48/build getter 14452b820, settings+28/market. Native ASCII-view
append14175be40 исполнен; allocation/copy/free/growth/singleton — shims.
26 fixtures, общий assemble_gmc2_config_url_ascii, без escaping/URI validation/IO.
[Источник и границы](../resource-tools/vampir/HEADLESS-GMC2-URL.md).

## SDK bootstrap getters и build labels, 19 октября

144524390 → compiled SDK version 5.2.11. Initializers 1411b3220/3250/3280
задают globals 14b4f1658/1668/1678 = A/B/C. Native 14452b820: DL1→B,
DL2→C, остальные→A; 256 fixtures/guards. Refresh1444f3c70 и RequestGMC2
1444f5675 получают settings+48 BuildCode. Общий select_sdk_build_code,
без active settings/I/O. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-BOOTSTRAP-VALUES.md).

## Публичный CDN body и module descriptors, 19 октября

Base-profile HTTPS GET: 200, 6000 bytes, body SHA 15a9b8d4…62e5d.
Общий decoder -> Zone real -> SDK mode 2; select_cdn_server -> index 6/REAL,
lobbyPort=12000. Это реальный публичный документ, не account/session response.
[SHA/provenance/offline replay](../resource-tools/vampir/HEADLESS-PUBLIC-CDN.md).
ProjectRED.uproject/NkPatch.uplugin побайтно совпали base/patch; обе runtime
декларации LoadingPhase=Default, порядок не установлен.
[Descriptors и JSON pointers](../resource-tools/vampir/HEADLESS-MODULE-DESCRIPTORS.md).

## NetworkVar registration и немедленный config load, 19 октября

Factory 144aa5810 → vtable 14961a318 slot+8 → owner 144aa4810 →
144aa6e70/FNnNetworkVar → helper 1445cd6c0. Native slice 1445cd6f9..739
вызывает callback до map insert 1445bb590. Actual context getter 141408910,
thunk 144aa7500 → loader 144aa6f20. Восемь fixtures inline/external;
loader/map insertion capture, TLS и полный startup не исполнены.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CONFIG-STARTUP.md).
PAK mounting/GConfig cache/active layer остаются неизвестными.

## Base/patch Game config: расхождение источников, 19 октября

Generated callback подтвердил main/full directory и основного
ProjectRED-Windows.pak (SHA c10228ec…525b), 12425 путей. Base DefaultGame.ini:
1.12.14/real/CdnConfig=True; patch pakchunk0: 0.1.1/dev/False.
WindowsGame.ini совпал. Snapshot хранит полные SHA/offsets/сравнение;
runtime precedence/GConfig cache/late overrides неизвестны.
[Общий источник и воспроизведение](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).

## Generated PAK key callback и Game config recovery, 19 октября

Static initializer 141291600 → binder 14155fd00 → getter 141553580; zero-GUID
consumer 142518910 использует этот delegate. Actual callback 1468e62d0 исполнен
на 4 guard/offset fixtures; AES-ECB output дал точные main/full directory SHA1.
7067 directory paths, 593 directories; extracted DefaultGame.ini/WindowsGame.ini
source-bound. Native crypto core не исполнялся; decoder small config profile.
Record header SHA1 проверяет ciphertext, не trial plaintext: старый record probe
не исключает ключ. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-PAK-CONFIG-RECOVERY.md).
Packed NetworkSetting defaults найдены; active overrides/scheme/startup неизвестны.

## CDN settings source: key trial и name clues, 19 октября

Fresh pakchunk0/index full hashes проверены. Один compiled CDN-derived key
не дал directory SHA1 match (trims 0–15). Record plaintext comparisons не
проверяют ключ: encrypted headers хешируют ciphertext.
8 plain SHA1 controls passed; 23 bounds-skipped и 34 compressed не проверялись.
Этот прежний probe key/config не получил; recovery generated callback описан выше.
EncryptionKey UTF16 literal 1491b7690 имеет три проверенные LEA: 143945735/
144fddc73/145045f04. Roots 143944d90/144fdd9c0/1450457c0 содержат AssetRegistry/
EOS context; связь с PAK key не доказана. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SOURCE-PROBE.md).

## CDN _SetServerList и lobby details, 19 октября: H04b partial

ReadJson 14565a6b8..a753: select_server/type → config+28. Whole 145661a70
_SetServerList: server_list → first ASCII-fold type match → detail fields.
Lookups lobbyAddress 145661ded / lobbyPort 145661fa7 / patchURL 145662105 /
dataURL 14566225f → FString config+d0/e0/f0/100. Comparator 1414596e0 и fold
table native; actual CRT _wtoi at 1456623bf. 31 replays, 30 whole SetServerList;
JSON/FString/diag shims,
zero refcount-control fixtures. Missing fields preserve synthetic old strings.
Shared CdnServerSelection/select_cdn_server: isolated raw plan, missing=None,
no globals/port coercion/readiness. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SERVER-LIST.md).
Actual config/endpoint validity/connection и полный ReadJson ещё открыты.

## CDN JSON result/ReadJson branches, 19 октября: H04b partial

145642c79..2c88: native parser-return + object-pointer branch, 4 fixtures.
145643107..3146: ReadJson call 14565a5d0 → copy object+1a1 byte → validator
145661a70 → error/next branch145643213, 8 fixtures. Calls имеют return shims;
whole parser/ReadJson/validation не исполнялись. Next не означает callback ready.
Shared decode_cdn_config_document: plain text JSON object, raw AES fallback,
strict local JSON/resource policy. read_cdn_sdk_environment: exact NetmarbleS/
Zone string → existing explicit SDK selector; missing не подменяется dev.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-JSON-FLOW.md).
Full config acceptance/actual values/TLS/startup order ещё открыты.

## CDN fallback decrypt, 19 октября: H04b partial

Native 145653dd0 whole orchestration: compiled 28-byte seed → SHA256 call
1483f9cd0 → IV first16/ciphertext rest → getter 14840a8b0 → EVP calls.
Descriptors 14a723e80/14a723e20, nid 427 связаны с compiled AES-256-CBC name record.
21 replay: 17 обычных +3 forced crypto failure +1 second CPU descriptor.
SHA/EVP primitives — backend shims, actual native crypto core не исполнен.
Shared decrypt_cdn_fallback: strict bounded envelope/PKCS7, optional crypto,
raw bytes; ошибки не превращаются в пустой plaintext. Android не проверен.
Callback branch145642c82→145643110 или fallback call 145642d52 — static only.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-FALLBACK.md).
JSON/ReadJson acceptance/actual settings/TLS/HTTP compression остаются открытыми.

## CDN body/BOM и status gate, 19 октября: H04b partial

Native body 1445e6fc0 + wide ctor 144416f20 + converters 1445eb700/eb7f0:
31 fixture replay. Raw bytes/один UTF-8 BOM; FF FE branch передаёт byte count
как wide units, читает synthetic guard; результат зависит от guard. Per-unit
UTF-8 не объединяет surrogate pairs. Bounded CRT memory/search/allocator shims.
CDN callback prefix 145642a30..2a7b: 9 status cases, body branch только 200–299.
Call 145642aad→body и NUL scan 145642ae0..ae7 — static only после prefix.
Shared decode_cdn_body_text/LengthResponse.decode_text: local strict Unicode,
UTF-16LE bounded to body/correct surrogate pairs/NUL rejection, 2 МиБ.
[Source/SHA/отличия](../resource-tools/vampir/HEADLESS-CDN-BODY.md).
Decompression/chunked/EOF/JSON acceptance/settings/TLS ещё открыты.

## CDN Content-Length и receive comparison, 19 октября: H04b partial

Prefix 1445edb30..1445edc9b → lookup 1445ea4a0 → trim 1445dbe60/dc0f0/dbef0;
slice 1445edf20..edf46 → actual CRT atoi → signed length owner+4d0.
Receive slice 1445e968c..e96dd сравнивает младшие uint32 length с available body.
30 complete native cases, один folded fixture bounded abort; range validation/
diagnostics middle и целый receive loop не исполнялись. Initial length fixture,
не lifecycle proof. _strnicmp/atoi actual Windows CRT, прочие bounded shims.
Shared take_cdn_length_response: strict local fixed-length/uncompressed/status 200,
2 МиБ, один length, без TE/range; не JSON/config acceptance.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-LENGTH.md).

## CDN response boundary/status, 19 октября: H04b partial

Native 1445e74f0/1445e75e0/1445e7440: 52 сценария boundary/status/available body.
Getter 1445da5d0/1445da610, scan wrapper 1418732e0/options 141872810 исполнены.
Первые 12 байт → actual Windows __stdio_common_vsscanf %*s %d; strstr bounded
shim, fixtures явно NUL-terminated. Доступные байты не доказывают полное тело.
Shared probe_cdn_response_head: strict local HTTP/1.x head policy, 16 КиБ/64 поля,
дубликаты сохранены; body/Content-Length/decode/JSON не реализованы.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-RESPONSE-HEAD.md).
Receive 1445e95f0/header parser 1445edb30/CDN callback 145642a30 — static only.

## CDN full default GET header, 19 октября: H04b partial

EXE SHA прежний. Header builder 1445e4b20 + URI/request-line и field builders
1445ec230/1445ebbc0/1445eb970/1445ebed0/1445ec3d0 исполнены: 7 default+4 overrides.
Native default GET/1.0 + Host:host:port + User-Agent:Aqua/1.0 + CRLFCRLF,
empty body/query/cookie/range. Content-Type/Length/Connection default отсутствуют.
Formatter 1445da240/options getter 141435030 исполнены; __stdio_common_vsprintf
вызван в actual recorded Windows CRT с переводом одного pointer argument.
Allocator/CRT memory/search/compare/cookie bounded shims, сами headers native.
Общие encode_cdn_get_headers/Draft.header_bytes совпали с 7 native blocks.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-HEADERS.md).
Nonempty body/query/cookie/range/raw headers, поздние overrides, transport/TLS/
response/status/decode/actual values остаются открытыми.

## CDN URL→URI→GET-line, 19 октября: H04b partial

EXE SHA прежний. URI ctor 1445e2d80 call 1445e2dfd→parser 1445e6460,
string ctor 1421e1620/copy и request-line 1445ec6f0 исполнены: 22 cases.
Fields+8scheme/+28host/+48uint16 port/+50path; ровно один path slash удалён.
Explicit port atoi импорт подтверждён, вызван actual ucrtbase на artificial ASCII,
DLL path/SHA в отчёте; allocator/CRT memory/search/compare/cookie bounded shims.
Native quirks HTTPS defaultport0, invalid/wrapped port0, query/fragment in path
не разрешаются общим parse_cdn_uri_ascii. 16 supported/6 rejected cases.
Draft parsed URI/request_line bytes; complete headers/body/TLS/network не готовы.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-URI.md).

## CDN HTTP request defaults, 19 октября: H04b partial

EXE SHA прежний. Ctor 1445e21f0 вызывает context ctor 1445e25d0 на owner+320;
constructor prefix 1445e25d0..26ac задаёт method 1/version 1.0/UA field Aqua/1.0.
Native request-line 1445ec6f0 + append 1445ddc80/growth 1445d8310: 16 cases,
empty query collection/explicit parsed path; method 1→GET /… HTTP/1.0 CRLF.
Allocator/CRT/cookie bounded shims. CDN call 14563fd0d→1445ea140 R8/R9=0→
AddPendingRequest 1445e4870; headers builder 1445e4b20→request-line 1445ec6f0.
Общий cdn_request.py: frozen offline draft URL/GET/1.0, strict local HTTPS policy,
base validation до concat и authority preservation; без HTTP/headers serializer.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-HTTP.md).
URI parser/late overrides/full headers/body/TLS/status/response/callback order открыты.

## CDN version preprocessing и compiled platform, 19 октября: H04b partial

EXE SHA прежний. Caller14563f287 → replace1445daf80/copy1445d8e60/
string-replace1445de490: 15 native ASCII cases dot→underscore, input unchanged.
Allocator/CRT search/compare/copy/cookie bounded shims. Initializer1445eae1b..42
создаёт platform object/global 14b4f39c8/vtable1495045d0; getter 1445e75b0
→slot 149504608→141484e40 возвращает 2; native caller выбирает window.
Ещё 7 явных return-tag cases подтверждают 1→ios/2→window/other→android, не другие builds.
Общие prepare_cdn_version_ascii/select_cdn_platform_label/prepare_cdn_config_url_ascii;
интеграция с native URL tail offline. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-PREPARATION.md).
Реальные Game config values/late overrides/HTTP request semantics/startup открыты.

## Завершающая сборка CDN URL, 19 октября: H04b partial

EXE SHA прежний. Initialize slice14563f758..f9d8, concat145630d40 и append/growth
1445d8310 исполнены в 16 сценариях с explicit ASCII fragments/SSO/heap capacity.
Allocator/free/memcpy/memmove — bounded shims, сама concat настоящая.
Форма base+platform+'/'+prefix+'/'+version_fragment+'/config.json'; между base и
platform слеш не вставляется. Pointer14b149ba0 → literal 1498b9eb8 подтверждён.
Общий assemble_cdn_config_url_ascii; реальные values/preprocessing/HTTP открыты.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-URL.md).
Следом version helper 1445daf80 и platform getter 1445e75b0, Game config/overrides.

## CDN base selector и Game config, 19 октября: H04b partial

EXE SHA прежний. Find141428640 и comparator1414599a0 исполнены без shims;
Initialize call 14563f3d3 и branch14563f3e9..424: ConfigPrefix содержит real
(ASCII ignore-case) → global 14b520cf0, иначе 14b520d00. 16 cases incl unreal/
Unicode/space; общий select_cdn_config_base с явными строками. Не SDK Zone equality.
File-global 14b2743f8 из loader 1445bc080 связан с literal Game/initialization
14152ca91..cac4. Callback map registration1445bb3a0 сохранена статически.
Новый pak0 проверен по fullSHA: 6912 decoded/75 encrypted skipped/10 size skipped,
4 exact config markers ASCII/UTF16 не найдены, decode errors0; scope ограничен.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-SELECTION.md).
Physical config/actual values/late overrides/full URL builder/startup order открыты.

## CDN config → SDK environment, 19 октября: H04b partial

EXE SHA прежний. Ctor145631210/global 14b575630/vtable1498bacd0 slot 8 →
145647da0 задаёт+48 dev; FNnCdnConfig::Initialize14563f080, HTTP callback
145642a30 call 145643110 → ReadJson14565a5d0. Lookup14563da10 получает section
NetmarbleS/keyZone, conversion1415e48f0 → copy141421d80 в object+48.
7 native cases с JSON/string/copy/free capture shims, missing branch14565f540;
весь parser/error/HTTP не исполнены. Caller145618910 → InitSetting14561a930.
NetworkSetting root 144aa6f20 загружает CdnConfigUrl/QA/AppVersion/ConfigPrefix
в globals14b520cf0/d00/d10/d20; реальные значения/файл и startup order неизвестны.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-CDN-CONFIG.md).

## NMSDKSettings и game override, 19 октября: H04b partial

Общий EXE SHA ниже. Accessor1444ab740 → ctor thunk1444ac680 → ctor 1444ac9f0;
registration1444ab7f0 → params1494c5e60 → property array1494c5cd0, 9 дескрипторов.
Constructor prefix: 4 native replays, market empty/game thered/build0/zone1.
Game InitSetting14561a930 копирует globals14b5740c0/4080/4090 из initializers
141258b10/8ae0/8ab0 (nmp/thered/client ID); сравнивает environment с real через
141459730 и пишет settings+49. 13 native cases, общий select_game_sdk_zone;
base/string/growth/copy/free/environment/singleton shims явно ограничены.
Getter 14563d960 → global 14b575630; объект+48 передаётся 141433970.
Ctor145631210 устанавливает singleton и обнуляет+48; реальное заполнение
environment, порядок вызовов и active values ещё неизвестны.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md).

## Свежие record indexes и CSV, 19 октября: U02 partial

35 архивов проверены по полному SHA256 и заново проиндексированы: 127375
записей, 125122 decoded/75 encrypted skipped/2178 size skipped, decode errors 0.
Каталог PAK и промежутки не разобраны; пути — наблюдения, не доказанные bindings.
Pakchunk1: 1565 CSV, 1267 exact historical content matches, 298 без совпадения.
Уникальные схемы кандидатов Quest/QuestTask/QuestTaskAction: соответственно
11/144/91 строк с изменением только ServerServiceGroupId; игровая идентичность
по схеме не заявляется. Tutorial/Step/UI и WorldSpot совпали по SHA256.
[Инструменты, отчёты и источники](../resource-tools/vampir/CLIENT-RELEASE-INDEX.md).
Производные графы и актуальные UI/map bindings ещё требуют обновления.

## Обновление источников клиента, 19 октября: U01 partial

EXE сохранил общий SHA256 ниже; 34 PAK изменились, один добавлен.
Для 34 старых индексов зафиксирован stale; offsets и связи с текущими ресурсами
требуют повторной проверки. 72 других UE-индекса только sample_only_unverified.
[audit-client-release.py и immutable манифест](../resource-tools/vampir/CLIENT-RELEASE-AUDIT.md)
сохраняют происхождение без перезаписи старой библиотеки. Полные SHA256 новых/
изменённых архивов сохранены; совместимость и версия игры неизвестны.

## Auth path append и offline binding, 19 октября: H04 partial

Общий SHA Windows EXE ниже. Code `0x1450e2b01` и refresh `0x1450e3451`
вызывают `0x14142c9d0` с v2/access-token длиной 15. 70 native path scenarios:
separator rules/empty FString/Unicode, preallocated buffer, memcpy shim.
Общие append_sdk_path / BoundTokenRequestPlan / bind_token_request;
явные SDK constants, без HTTP. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-PATH.md).
Статически уточнены ветви value conversion `0x144476940`; числа/virtual values
ещё не исполнены. Активные settings/GMC2/DECKEY и весь SDK map flow открыты.

## Normal/secret map и auth URL getter, 19 октября: H04b partial

Общий SHA Windows EXE ниже. Parser normal `0x1444f1250` → secret `0x1444f162f`
используют insertion `0x14150df70`: existing-key slice заменяет key/value.
Auth `0x1450e2895` → SDK getter `0x144553700` → map+`0x310` → `0x144502730`.
Native hash `0x141420380`, lookup `0x141437e50`, URL prefix `0x144584280`
→ `0x141432f20/0x1414599a0`. 24 lookup / 3 replacement / 5 hash сценариев;
string/memory shims, без полного insertion/growth/callback. Общий sdk_config.py.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-MAP.md).
Stringify `0x144476940` и path append `0x14142c9d0` — следующие зависимости.

## Список secret constants, 19 октября: H04b-secret partial

Общий SHA Windows EXE ниже. `0x1444ddc10`: Mid(2,length−4), split `","`,
chunk helper `0x14451d5c0`, append фрагментов и запятых, замена последней на `}`.
Пустой chunk прерывает сборку; 9 основных и 4 граничных native сценария.
String/RSA/UTF-8 helpers shimmed; native JSON parser/cleanup не исполнялись.
Общий decode_sdk_secret_constants, шесть тестов; один trailing NUL снимается
по связи `0x14451d9ce..0x14451d9dd`. Полная GMC2-конфигурация не получена.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SECRET-LIST.md).
Дальше normal/secret merge и lookup `0x1450e2895` → `0x144553700` для authTokenUrl.

## OAEP checker и один secret chunk, 19 октября: H04b-secret partial

Общий SHA Windows EXE ниже. `0x148405020` исполнен: 24 корректных и 69 ошибочных
входов, SHA/MGF1/memory/error/stack shims, без клиентского RSA arithmetic.
Caller `0x14451d6f2` → формат `0x1494e2540`: BEGIN RSA PRIVATE KEY, тело `%s`.
Диагностики caller подтверждают названия PEM_read_bio_RSAPrivateKey,
RSA_private_decrypt и RSA_padding_check_PKCS1_OAEP_mgf1.
Общий sdk_secret.py: один chunk, optional cryptography backend, Windows synthetic
RSA 2048/3072/4096; полный список/Android не проверены.
[Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-OAEP.md).

## Секретные константы GMC2, 19 октября: H04b partial

Общий SHA Windows EXE ниже. Root `0x14451d5c0`: Base64 wrapper `0x141523200`
→ core `0x14150cd70`; private-key reader chain `0x148405720/0x148433880`;
RSA wrapper `0x148404190`, OAEP `0x148405020`, digest getter `0x148404110`.
Descriptor `0x14a722610` сопоставлен с SHA-256 в OpenSSL 1.1.1t.
26 корректных и 8 граничных native Base64 входов, 16 подготовок аргументов OAEP.
Вызов OAEP перехвачен; RSA/OAEP не исполнены. Общий bounded Base64 decoder,
пять тестов. [Source/SHA/границы](../resource-tools/vampir/HEADLESS-SDK-SECRET.md).

## Строка GMC2 и передача DECKEY, 18 октября: H04b partial

Общий SHA Windows EXE ниже. Constructor связывает manager+`0xB0` с именем
DECKEY. Root `0x1444c8c60`: lookup через virtual slot `0x28` → локальная строка
ключа → parser `0x1444f0e80` на `0x1444c9587`. Метод lookup ещё не идентифицирован.
Extractor `0x1444e3bc0` → unescape `0x1444f2670` → DecryptXOR `0x1444ddf50`.
43 корректных и 7 граничных native входов, три составных искусственных JSON;
общий sdk_constants.py, пять тестов. Secret constants требуют отдельной обработки.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-UNESCAPE.md).

## Параметры SDK и XOR GMC2, 18 октября: H04b partial

Для общего SHA Windows EXE ниже getter `0x144524390` возвращает литерал
`5.2.11`; RefreshSDKConstants вызывает его на `0x1444f3bb3`. Getter
`0x14452b820` получает settings+`0x48` для build, выбирает глобальные строки,
инициализированные `A/B/C` функциями `0x1411b3220/3250/3280`.
Это другое поле, чем окружение GMC2 settings+`0x49`; активные значения неизвестны.
Цикл DecryptXOR `0x1444ddf50` проверен на 42 искусственных входах:
16-битные единицы, повторяющийся ключ, ограниченный захват append.
Общий `sdk_constants.py`, пять тестов; получение ключа и внешняя упаковка открыты.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).

## SDK configuration GMC2, 18 октября: H04b partial

Для общего SHA Windows EXE ниже связаны constructor `0x1444bd970`,
Start `0x144501970`, RefreshSDKConstants `0x1444f38e0`, RequestGMC2 `0x1444f5320`,
callback `0x1444edbb0`, parser `0x1444f0e80`, DecryptXOR `0x1444ddf50`.
7 literals / 8 LEA / 7 roots / 48 constants. Native selector
`0x144501a11..0x144501a46` проверен для всех 256 byte values: settings+0x49
выбирает manager+0x150/160/170/180; unknown values ведут на dev.
[Source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Активный mode, template/build/market values и response→auth bases ещё неизвестны.

## SDK auth, 18 октября: H04 partial

Общий SHA Windows EXE ниже. FAuthImpl SignIn root 1444fb800 использует
`authUrl/v1/sign-in`; NetmarbleID code/refresh roots1450e2640/1450e2f50 —
`authTokenUrl/v2/access-token`, form client_id/device_key/code или refresh_token.
POST helper 14451c570→14451c600, form builder144586a30; native whitelist141c06750
и uppercase hex1415ad670 исполнены 512 раз.24 SDK literals/34 LEA/24 roots.
[Полные source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-AUTH.md).
Общий auth_request.py — offline plan, не login. Config bases/browser code и
SDK→game handoff ещё unknown; пароль не подставлять в PktLogin по догадке.

## Уточнение 18 октября: queue drain → send

Для общего SHA Windows EXE ниже constructor `0x1445e2b7f/0x1445e2b86`
связывает peer+50 с vtable `0x149503b58`, slot 20 → `0x1445e8b70`.
Drain вызывает ordinal WS2_32 import на `0x1445e8c0d`, имя send подтверждено
export table локальной DLL (её SHA в JSON). Consume `0x1445e5ef0`, partial
memmove; errors22/23/37 сохраняют очередь. 61 native cases/5 tests.
[Source/offsets и границы](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
Socket/error/close fixtures; real loopback TCP проверяет только portable pump.

## Уточнение 18 октября: send-B и очередь копии

Общий SHA Windows EXE ниже. Slice `0x144aace6d..0x144aacf89`: ID/sequence/body,
CRC/XOR key=peer+248, sequence=peer+240. Queue call `0x144aacf7d` → `0x1445eac20`
→ append `0x1445e4a90` для peer+170: отдельная копия ciphertext до возврата.
40 native cases/5 tests, preallocated capacities/CRT shims/wake capture;
source overwrite и key variant не меняют queue. Shared send-B encoders/OutboundFrames.
[Source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-SEND-B.md).
Drain/socket и весь Notify→wire не проверены.

## Уточнение 18 октября: receive-B и ID bookkeeping

Общий SHA Windows EXE ниже. Wrapper `0x144aacb50`, key=subobject+0x48,
XOR frame+3, IDword+3 → getter `0x144aa7c40` → lookup `0x144aa8120` →
remove `0x144aa7f40` → sparse free `0x14142eff0`; empty-table notify `0x144aa7870`.
39 native cases/4 tests, manager/listener/registry fixtures, notification list empty;
OnHandler entry capture. Remove идёт до reader, даже для short body. CRC в
исполненном B route не найден; не вывод обо всём транспорте.
[Отчёт, source/SHA/offsets и границы](../resource-tools/vampir/HEADLESS-RECEIVE-B.md).

## Уточнение 18 октября: Dispatch и wrapper OnHandler

Общий SHA Windows EXE ниже: `0x14679f510` исполняет ID lookup/body reader и
handler+8 → `0x141535f20` (`488b0148ff6010`) → handler+0x10.
Для PingResult vtable `0x149d810f8` это OnHandler `0x1467670c0`; вход перехвачен,
побочные действия не исполнены. 24 native cases/4 tests, synthetic registry,
native TLS setter `0x144aa6240` и archive destructor chain. Shared receive_packet.py.
[Отчёт, source/SHA/offsets и ограничения](../resource-tools/vampir/HEADLESS-DISPATCH.md).

## Уточнение 18 октября: native второй receive loop

Для общего SHA Windows EXE ниже исполнен slice `0x1445ed572..0x1445ed730`:
helper `0x1445dede0`, thunks `0x1415f6848`/`0x1437113e4`, length probe
`0x144aa9a90`, receive-A `0x144aa9c00`/XOR `0x144aa6ca0` и compaction.
44 cases/5 tests; final callback capture, snapshot/cleanup/free/expired-cleanup
заданы fixtures, не native lifecycle. Shared receive_frame.py: take_receive_a_frame.
[Происхождение, отчёт и пределы](../resource-tools/vampir/HEADLESS-LISTENER-LOOP.md).

## Уточнение 18 октября: block decoder и listener linkage

Источник/SHA — общий Windows EXE, указанный ниже. Native decoder `0x14141ba60`:
166 valid / 86 invalid executions, literal/match/LE16 offset/extended lengths;
copy tables `0x14898cd78`. Общий код block_decode.py, explicit bounded output.
Второй stage root `0x1445ed3e0`: call `0x1445ed723` → thunk `0x1415f6848`
→ slot+0x38 length probe; LEA `0x1445ed65a` → thunk `0x1437113e4` → helper
`0x1445dede0` / indirect call `0x1445def22` → slot+0x40 receive wrapper.
Связь статическая; полный listener loop не replayed. [Provenance и границы](../resource-tools/vampir/HEADLESS-BLOCK-DECODE.md).

Обновлено 18 октября 2026. Начинать с [README.md](README.md).
Общий для экранного бота, [самостоятельного сетевого бота](../vampir-headless/README.md)
и исследования карты. Это навигационный указатель, не полный список функций EXE.
Подробные доказательства и инструменты остаются у соответствующего направления.

Общие данные и исполняемые компоненты: [vampir-shared/README.md](../vampir-shared/README.md).

## Как пользоваться и обновлять

Перед новым исследованием искать здесь и в подробном отчёте. Добавлять найденные
функции сюда, а шаги и историю — в TASKS/WORKLOG соответствующего направления.
Запись должна содержать назначение, адрес/тип адреса, источник и SHA, уровень
подтверждения, ограничения, путь отчёта и способ воспроизведения. Большие таблицы
и дизассемблирование здесь не дублировать. Не заменять старые подтверждения новой
гипотезой; при обновлении клиента хранить результаты отдельно по версии/SHA.

Уровни: **байты/строка** → **ссылка из инструкций** → **связь/vtable** →
**изолированное исполнение** → **живая проверка**. Верхний уровень не следует
автоматически из нижнего. В частности, имя пакета не доказывает ID, wire-format
или пригодность его отправки серверу.

## Источник текущих адресов

Windows `ProjectRED-Win64-Shipping.exe`, собранный клиент, не исходный C++ проект.
Путь: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса ниже — VA с image base `0x140000000`, не файловые смещения.
Версия Windows не объявлена равной Android 1.0.14. При другом SHA адреса
не применять без повторной проверки. Полные provenance — в указанных JSON.

## Вход, обмен и состояние персонажа

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Повторение: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-network-index.py`.
27 точных строк, 31 проверенная LEA-ссылка, 27 unwind roots, 32 фрагмента,
1020 инструкций; missing/rejected=0. Для строк подтверждены bytes/offset/SHA,
для ссылок — границы инструкций и chained unwind root. Root со строкой не
объявляется реализацией одноимённого метода. Getter/serializer/ID ещё связать.

| Найденная строка / назначение | Root VA со ссылкой | Подтверждение / следующий пробел |
|---|---|---|
| UTitleUI::OnSuccessNetmarbleSDKAuth() | 0x14641d560 | Строка/ссылки; не восстановлен обмен почты/пароля на сессию |
| UTitleUI::ProcessNetmarbleSDK() | 0x14641ee20 | Строка/ссылки; вызовы SDK и токены ещё исследовать |
| PacketDispatcher::Dispatch | 0x14679f510 | Строка/ссылки; весь путь receive→decode→dispatch не доказан |
| PacketDispatcher::GetPacketHandler | 0x14679f7b0 | Строка/ссылка; семантику lookup ещё проверить |
| PacketDispatcher::_AddPacketHandler | 0x1467a7250 | Регистрация двух пар дополнительно подтверждена, см. ниже |
| PktLobbyLogin / Result | 0x145754ff0 / 0x145755020 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktLogin / Result | 0x1456e3410 / 0x1456e3440 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktCharacterListRead / Result | 0x1456e2f90 / 0x1456e2fc0 | Строки/ссылки; wire-schema неизвестна |
| PktCharacterSelect / Result | 0x1456e30e0 / 0x1456e3140 | Строки/ссылки; отдельно найден result-handler |
| PktCharacterPosition | 0x1456cd420 | Строка/ссылка; поля позиции ещё не восстановлены |
| PktCharacterMove / Result / Notify | 0x1456cd2d0 / 0x1456cd390 / 0x1456cd360 | Строки/ссылки; отправка движения не реализована |
| PktWorldInfo / UpdateNotify | 0x14581bc60 / 0x14584bef0 | Строки/ссылки; live zone/world ещё не получены |
| PktPing / Result | 0x1456e36b0 / 0x1456e36e0 | Строки/ссылки; частота/формат игрового heartbeat неизвестны |
| PktSkillCastingStart / Result | 0x14583e7a0 / 0x14583e800 | Строки/ссылки; боевые команды не реализованы |
| PktSkillStart / Result / Notify | 0x14583eb00 / 0x14583eb90 / 0x14583eb60 | Строки/ссылки; серверный боевой цикл неизвестен |
| PktActorCombatStateChangeNotify | 0x1456b5940 | Строка/ссылка; поля и применение ещё исследовать |

## Сетевые пакеты: H02, 18 октября

Подтверждены name→vtable→constructor/ID/reader/writer targets для 10 типов
и registration для пяти ответов. Подробная таблица, доказательства, SHA и
команды: [HEADLESS-PACKET-BINDINGS.md](../resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md).
Данные: `code-clues/headless-packet-bindings.json` в общей библиотеке.
ID: Login/LobbyLogin=3, их Result=4; CharacterListRead/Result=101/102,
CharacterSelect/Result=109/110, Ping/Result=16/17.
**ID3/4 совпадают у разных типов**: использовать контекст, не единый глобальный
ID→schema. Доказаны разные фабрики/registration targets; runtime selection ещё unknown.
Name slot+0x38, ID+0x28; writer+0x10/reader+0x20 — targets, не wire-schema.
10 native ID сценариев/4 audit tests прошли, сеть/игра не запускались.

Новые handler targets: LoginResult146765540, LobbyLoginResult14677ec50,
CharacterListReadResult14675dce0, CharacterSelectResult14675e9a0,
PingResult1467670c0 (VA, префикс 0x). Getter/constructor/read/write VA и
registration callsites см. в подробной таблице, не выводить их из ID.

## Primitive IO и Ping payload: H03a, 18 октября

[HEADLESS-PING-CODEC.md](../resource-tools/vampir/HEADLESS-PING-CODEC.md) содержит
полную цепочку, provenance и `code-clues/headless-ping-codec.json`.
Receive Dispatch14679f510 → reader ctor 144aa6260 → vtable14961a520 →
u64 reader 144aa5bc0/u32 reader 144aa59c0 → raw read 144aa5ce0.
Dispatch явно передаёт swap=0; тела little-endian16 байт Ping/12 байт Result.
Writer ctor 144aa62f0 → vtable14961a5c0 → u64 writer 144aa61e0/u32 writer 144aa6090
→ raw write144aa6120. Counter helpers144aa68c0/1445ead30; bswap64/32
1445d9f60/1445d9f30. Все адреса VA, префикс 0x; полные source SHA выше.

Primitive IO исполнен настоящими инструкциями, только CRT memcpy подменён
bounded shim. 126 native cases/5 tests, 6 дополнительных replays прошли.
Переносимый stdlib codec: `vampir-shared/vampir_core/ping.py`.
H03 остаётся частичным: output callers144aa9da0/144aaccf0, helpers1445f1230/
144aa6ca0 и framing требуют разбора. Размер 5 до body относится к dispatcher
input, не ко всему wire frame. Handler dispatch вызывает slot+8; связь с
OnHandler+10 ещё проследить. Signedness/field timing semantics не установлены.

## Более глубокие подтверждения

Первый receive transport: `UxTcpPeer::_HandleRecvBuffer`, root 0x1445ed3e0,
диагностическая LEA0x1445ed4cc. Native slice0x1445ed403..0x1445ed562:
length 23/compressed bit 23 → copy/decompress0x14141ba60 → второй буфер,
append0x1445e4a90/resize0x1445de6e0/memmove. 62 native cases / 5 tests.
[HEADLESS-TRANSPORT-STAGE.md](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md),
report `code-clues/headless-transport-stage.json`, shared transport_header.py.
Общий decompressor/listener loop/CRC и send queue ещё не готовы.
Length probe0x144aa9a90 — второй уровень, не raw compressed framing.

H03b.2b keyflow: бывший candidate0x144aab330 подтверждён как setter peer+248.
PktKeyChangeNotifyHandler0x146765050 строит PktKeyChanged, вызывает send+38,
затем setter+40. IDs Notify11/ack12, тела raw64LE8 байт; 20 native flow cases
подтвердили old key во время send и update после него, даже при send false.
[HEADLESS-KEY-CHANGE.md](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md),
`code-clues/headless-key-change.json`; shared `vampir_core/key_change.py`.
Полные packet/vtable/IO/registration адреса в таблице отчёта. Server key generation,
initialauth/receive integrity/send queue всё ещё неизвестны.

H03b.2b partial: length probe0x144aa9a90 подтверждён 156 native cases;
wrapperA0x144aa9c00 —13 native cases до callback. Vtables0x14961af58/0x14961b8f0
у main+200 имеют length+38/receive+40. Factory0x14678ec40 через setter 0x144aab300
назначается в peer+238; wrapperBcallback из того же поля вызывает Dispatch0x14679f510.
Статическая linkage доказана, end-to-end replay нет. Candidate keysetter0x144aab330
ещё без caller/source семантики. [HEADLESS-RECEIVE-ENVELOPE.md](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md),
`code-clues/headless-receive-envelope.json`; shared receive_frame.py имеет
дополнительную local bounds policy. CRC/incoming layout/keyflow ещё unknown.

H03b.2a: native send-A slice0x144aa9e6a..0x144aa9f45 подтверждён 20 сценариями;
length 24+CRC32+(ID16+sequence16+body), XOR от offset 3. Ping frame 27 байт.
Sequence connection+228 обновляется native16bit с wrap 65535→0.
Stream append0x144aa6330, buffer getter 0x144aa5f80, word writer 0x144aa6060;
подробный provenance/[HEADLESS-SEND-FRAME.md](../resource-tools/vampir/HEADLESS-SEND-FRAME.md).
Общий `vampir_core/send_frame.py`, `code-clues/headless-send-frame.json`.
Receive/context/key ещё unknown; layout перед Dispatch не отождествлять с send frame.

H03b.1: CRC initializer0x1418ba360/update0x1445f1230/table 0x1495046f0,
XOR0x144aa6ca0. Подтверждены 252 native executions/5 tests; общий модуль
`vampir-shared/vampir_core/frame_primitives.py`. Send roots0x144aa9da0/0x144aaccf0,
receive0x144aa9c00/0x144aacb50; XOR пропускает 3 байта. Session key source,
полный frame и receive validation ещё unknown.
[HEADLESS-FRAME-PRIMITIVES.md](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md),
`code-clues/headless-frame-primitives.json` в общей библиотеке.

| Функция/структура | Адреса VA | Подтверждение и подробный источник |
|---|---|---|
| ContentsUnlockListReadResult / RequestResult | handlers 0x146763cd0 / 0x146763da0, registration 0x1467a7250 | Пары handler/packet, vtable и getters ID1007/1009; не сетевой API. [UNLOCK-REGISTRATION.md](../resource-tools/vampir/UNLOCK-REGISTRATION.md), `code-clues/lock-registration-events.json` |
| PktCharacterSelectResultHandler::OnHandler | 0x14675e9a0 (LEA имени 0x14675e9d3) | Имя и отдельные readiness-вызовы; весь state initialization не доказан. Тот же отчёт |
| Guard результата пакета | 0x1467a8e10 | Статические ветви результата/ошибок. [PACKET-RESULT-GUARD.md](../resource-tools/vampir/PACKET-RESULT-GUARD.md) |
| PktStat reader / writer | 0x1457f0540 / 0x1457f4360 | key 32/raw64 и native исполнения с synthetic primitive IO, wire неизвестен. [ATTRIBUTES.md](../resource-tools/vampir/ATTRIBUTES.md), `code-clues/stat-packet-evidence.json` |
| PktStatCategoryData reader / writer | 0x1457f0590 / 0x145784940 | category8/raw64, read clamp≤29; реальные категории не установлены. Тот же отчёт |
| Форматирование значения характеристики | 0x145dda3a0 | Native ветви scaling/display; не формулы урона. ATTRIBUTES.md, `code-clues/stat-format-routes.json` |
| Проекция координат на navmesh | 0x1452451b0 | Изолированное исполнение с explicit inputs; не live position. [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md) |
| Polygon query | 0x1452457b0 | Native offline query; active mesh/permissions отдельно. MAP-ATLAS.md |
| Straight path/funnel | 0x145248b20 | Native offline corridors; не подтверждение движения персонажа. MAP-ATLAS.md |
| Базовая инициализация nav-фильтра | 0x1452b7120 | Native explicit SupportedArea/CDO scenarios; live selection отдельно. MAP-ATLAS.md |

## Другие общие индексы

- [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md): CSV, архивы, карты, изображения.
- [NATIVE-UI-LINKS.md](../resource-tools/vampir/NATIVE-UI-LINKS.md): код→окна; `query-native-ui.py` ищет с проверкой источника.
- [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md): окна, контролы, контейнеры и геометрия.
- [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md): квест→задача→действие/обучение.
- [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md): полная история карты и специализированные native отчёты.

## Автобой — пока отдельные зацепки

В `native-enums.json`: EAICombatMode Auto=0/Target=1;
ESupportModeBehaviorAutoCombatType CombatStatsRecord=0/LocationMemory=1/Area=2.
В CSV: Skill. SyncAutoCombat (pakchunk1 entry1505), OnEntryAutoCombat/
AutoCombatLeaveWorld/movePacketIntervalTime (entry1574). Источники и SHA CSV —
`table-study/index-pakchunk1-Windows.json`. Это данные/enum, не найденные
реализации функций и не доказательство серверного автономного фарма.
