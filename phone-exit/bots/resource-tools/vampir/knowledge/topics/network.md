# Сеть, протокол и runtime

## Установлено

Есть отдельные schemas для лобби и игрового обмена, bounded framing / codecs,
приём TCP порциями, очередь отправки, partial send, смена ключа и состояния
GameConnection. Локальные/native-сценарии не заменяют проверку всей сессии.
[Send drain](../evidence/network/HEADLESS-SEND-DRAIN.md),
[key change](../evidence/network/HEADLESS-KEY-CHANGE.md),
[GameConnection](../../../../vampir-headless/GAME-CONNECTION.md).

В реальном тесте через JP: SDK принят, список серверов получен, выбранный ID
передан в lobby Login, код лобби 0; лобби остаётся открытым при игровом входе.
Game Version 0, Game Login 16. Franz2 — строка сервера 256, группа Franz 253;
прежний 251 — Monty1. [Проверка](../evidence/network/HEADLESS-FRANZ2-LOGIN.md).

Новый явный launcher flow принят SDK и лобби, но Game Login на ID 256 через
два других JP-телефона и HK вернул 58 / BlockedIp. Изменились также выходы;
смена кода не доказывает причину прежнего InvalidState.
После последней замены телефонов launcher flow на новом JP снова дал
16 / InvalidState; со вторым новым JP прямой транспорт не установился.
21 октября пользователь создал Okly и вошёл в мир официальным клиентом через JP.
После его закрытия бот на том же выбранном телефоне снова получил 16;
список персонажей не запрашивался.
[Проверка launcher flow](../evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

## Открыто

Успешный Game Login и вся последующая длительная сессия, reconnect,
серверные таймауты / readiness и нагрузка. Не запускать прежний probe повторно
без доказанного изменения входа. Не смешивать ID3/4 лобби и игры:
числа одинаковые, schemas и context различаются.

Код общего runtime: `phone-exit/bots/vampir-shared/vampir_core/`.
Диагностические runners: `phone-exit/bots/vampir-headless/`.
Это пока не законченный автономный клиент.

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [BeginGameImpl: ID сервера, поиск записи и цель транспорта](../evidence/network/HEADLESS-BEGIN-GAME-SERVER-TARGET.md)
- [Vampir — распаковка транспортных блоков и второй слой приёма](../evidence/network/HEADLESS-BLOCK-DECODE.md)
- [Входящие события движения текущей сборки](../evidence/network/HEADLESS-CHARACTER-MOVE-EVENTS.md)
- [Нижний connect: параметры peer и передача resolver-задания](../evidence/network/HEADLESS-CONNECT-RESOLVER-HANDOFF.md)
- [Локальный адрес соединения в Version и граница SOCKS](../evidence/network/HEADLESS-CONNECTED-LOCAL-ADDRESS.md)
- [Первый пакет connected callback — PktVersion](../evidence/network/HEADLESS-CONNECTED-VERSION-PACKET.md)
- [Vampir — Dispatch до входа в OnHandler](../evidence/network/HEADLESS-DISPATCH.md)
- [Vampir — CRC32 и XOR внешнего слоя, H03b.1](../evidence/network/HEADLESS-FRAME-PRIMITIVES.md)
- [Franz 2: связь имени с ID и отдельная попытка входа](../evidence/network/HEADLESS-FRANZ2-LOGIN.md)
- [ConnectToServer: адрес, игровой порт и дополнительная пара](../evidence/network/HEADLESS-GAME-CONNECT-TARGET.md)
- [Источники оставшихся полей Version / Login](../evidence/network/HEADLESS-GAME-LOGIN-INPUTS.md)
- [Прямой маршрут и переход к Global](../evidence/network/HEADLESS-GLOBAL-DIRECT.md)
- [Региональное лобби в текущем клиенте](../evidence/network/HEADLESS-GLOBAL-LOBBY-REGIONS.md)
- [Vampir — уведомление и подтверждение смены ключа](../evidence/network/HEADLESS-KEY-CHANGE.md)
- [Vampir — исполнение второго цикла приёма](../evidence/network/HEADLESS-LISTENER-LOOP.md)
- [Прямой вход на EU / Prelude 2 и отказ 59](../evidence/network/HEADLESS-LIVE-GLOBAL-EU.md)
- [Живая сессия через новый HONOR JP](../evidence/network/HEADLESS-LIVE-HONOR-SESSION.md)
- [Проверка канала через Google Pixel 5](../evidence/network/HEADLESS-LIVE-PIXEL-CHANNEL.md)
- [Средство записи официального TCP для сравнения с ботом](../evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md)
- [Лобби: Version перед запросом и отправка накопленного буфера](../evidence/network/HEADLESS-LOBBY-CONNECT-FLOW.md)
- [Лобби: отдельный Version и запрос списка серверов](../evidence/network/HEADLESS-LOBBY-HANDSHAKE.md)
- [LobbyLogin: preparation до отправителя и последний байт 7](../evidence/network/HEADLESS-LOBBY-LOGIN-PREPARATION.md)
- [LobbyLogin: полный writer и источники SDK / NID](../evidence/network/HEADLESS-LOBBY-LOGIN-WRITER.md)
- [Лобби: отдельный LoginResult и источник игровых серверов](../evidence/network/HEADLESS-LOBBY-LOGIN.md)
- [Запись ID 104 → игровой endpoint](../evidence/network/HEADLESS-LOBBY-RECORD-ENDPOINT.md)
- [Windows: продолжение после успешного входа в лобби](../evidence/network/HEADLESS-LOBBY-WINDOWS-CONTINUATION.md)
- [Начальный контекст игрового Login для Windows](../evidence/network/HEADLESS-LOGIN-INITIAL-CONTEXT.md)
- [Язык в Login и ветвь metadata с DeviceKey](../evidence/network/HEADLESS-LOGIN-LANGUAGE.md)
- [PktLogin: constructor, SDK getters и заполнение полей](../evidence/network/HEADLESS-LOGIN-PACKET-FIELDS.md)
- [PktLogin: проверенный writer и переносимое тело](../evidence/network/HEADLESS-LOGIN-PACKET-WRITER.md)
- [Login: поля настроек, режима и SDK-объекта](../evidence/network/HEADLESS-LOGIN-POLICY-INPUTS.md)
- [LoginResult: native handler, result gate и записи состояния](../evidence/network/HEADLESS-LOGIN-RESULT-HANDLER.md)
- [LoginResult: вложенные readers и переносимый декодер](../evidence/network/HEADLESS-LOGIN-RESULT-READER.md)
- [Числовой вход Login из patch-контекста](../evidence/network/HEADLESS-LOGIN-REVISION-INPUT.md)
- [Login: request handoff → кадр и очередь](../evidence/network/HEADLESS-LOGIN-SEND-PATH.md)
- [Проверка официального клиента через JP](../evidence/network/HEADLESS-OFFICIAL-CLIENT-JP.md)
- [Vampir: пакеты входа, персонажа и heartbeat — H02](../evidence/network/HEADLESS-PACKET-BINDINGS.md)
- [Vampir — реальные байты тела Ping, H03a](../evidence/network/HEADLESS-PING-CODEC.md)
- [Эталон записи запуска и квестового автопрохождения](../evidence/network/HEADLESS-QUEST-REFERENCE-CAPTURE.md)
- [Vampir — receive-B, ключ и таблица уведомлений](../evidence/network/HEADLESS-RECEIVE-B.md)
- [Vampir — длина входящего кадра и связь с dispatcher](../evidence/network/HEADLESS-RECEIVE-ENVELOPE.md)
- [Resolver result → peer recipient → socket creation](../evidence/network/HEADLESS-RESOLVED-SOCKET-SETUP.md)
- [Resolver job: Winsock results, порядок адресов и completion](../evidence/network/HEADLESS-RESOLVER-JOB-RESULTS.md)
- [После замены телефонов: игровой LoginResult 16 / InvalidState](../evidence/network/HEADLESS-RESULT-ERROR-16.md)
- [Игровой LoginResult 58: BlockedIp](../evidence/network/HEADLESS-RESULT-ERROR-58.md)
- [Login в лобби после выбора игрового сервера](../evidence/network/HEADLESS-SELECTED-LOBBY-LOGIN.md)
- [Серверная XY-цель собственного персонажа](../evidence/network/HEADLESS-SELF-TARGET-STREAM.md)
- [Vampir — send-B и владение байтами очереди](../evidence/network/HEADLESS-SEND-B.md)
- [Vampir — очередь → Winsock send и частичная отправка](../evidence/network/HEADLESS-SEND-DRAIN.md)
- [Vampir — полный исходящий Ping frame, H03b.2a](../evidence/network/HEADLESS-SEND-FRAME.md)
- [Страна регистрации SDK и список стран сервера](../evidence/network/HEADLESS-SERVER-COUNTRY-POLICY.md)
- [Проверка состояния сервера перед входом](../evidence/network/HEADLESS-SERVER-ENTRY-STATE.md)
- [Выбор игрового сервера с учётом региона](../evidence/network/HEADLESS-SERVER-REGION-SELECTION.md)
- [Vampir: периодический Ping и короткая живая сессия](../evidence/network/HEADLESS-SESSION-KEEPALIVE.md)
- [Socket endpoint connect: sockaddr, syscall result и wrapper acceptance](../evidence/network/HEADLESS-SOCKET-CONNECT-RESULT.md)
- [Проверка ошибки сокета внутри задания готовности](../evidence/network/HEADLESS-SOCKET-ERROR-OPTION.md)
- [Socket mode job: select, state flags и completion codes](../evidence/network/HEADLESS-SOCKET-READINESS-JOB.md)
- [Готовность сокета → NnPeerImpl::OnTcpPeerConnected](../evidence/network/HEADLESS-SOCKET-READY-NOTIFICATION.md)
- [Делегат подключения транспорта → игровой получатель](../evidence/network/HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md)
- [Vampir — первый транспортный этап приёма](../evidence/network/HEADLESS-TRANSPORT-STAGE.md)
- [Version: полная CPU-строка и source enum form](../evidence/network/HEADLESS-VERSION-CPU-STRING.md)
- [Version и Login: общий NMDeviceKey и контекст SDK](../evidence/network/HEADLESS-VERSION-DEVICE-INPUT.md)
- [PktVersion: native writer и переносимое тело запроса](../evidence/network/HEADLESS-VERSION-PACKET-WRITER.md)
- [VersionResult: reader, Dispatch и переход к Login routine](../evidence/network/HEADLESS-VERSION-RESULT-HANDLER.md)
- [PktVersion: wrapper → send-B → полная копия кадра в очереди](../evidence/network/HEADLESS-VERSION-SEND-PATH.md)
- [Windows suffix и platform context для игрового входа](../evidence/network/HEADLESS-VERSION-WINDOWS-CONTEXT.md)
- [Winsock error → engine error → connect wrapper acceptance](../evidence/network/HEADLESS-WINSOCK-ERROR-MAPPING.md)
