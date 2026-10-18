# Vampir — очередь → Winsock send и частичная отправка

18 октября 2026. Продолжение [send-B/ownership](HEADLESS-SEND-B.md).
Общий [реестр](../../vampir/FUNCTION-INDEX.md), [задачи](../../vampir-headless/TASKS.md).

## Источник и воспроизведение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA при image base `0x140000000`; версия Windows/Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-send-drain.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_send_drain.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-send-drain.json`,
SHA256 `61f5072331f239b46bbd00f648040d803721fece554156dccba80691a991a251`.
Содержит source/tool hashes, native instructions/file offsets/fragment hashes,
PE import descriptor/thunk, проверку export системной DLL, wake vtable и 61 case.

## Связь с очередью и импортом

Constructor `0x1445e2af0` на `0x1445e2b7f` загружает vtable `0x149503b58`,
на `0x1445e2b86` записывает её в peer+0x50. Slot+0x20 содержит `0x1445e8b70`:
это реальный target wake-вызова очереди `0x1445eac7c`.

`0x1445e8b70` получает RCX=peer+0x50 и использует relative+0x128/0x130:
это те же peer+0x178/0x180 begin/end, ранее подтверждённые при append.
Размер вычисляется end−begin−1, поэтому NUL sentinel не передаётся по сети.
Socket handle читается из peer+0x148. Call `0x1445e8c0d` использует IAT,
четыре аргумента соответствуют socket, pointer, size, flags0.

Импорт ordinal, а не именованный. Builder читает PE import descriptor,
устанавливает DLL/ordinal и сверяет с export table установленной
`%SystemRoot%/System32/WS2_32.dll`: ordinal действительно соответствует `send`.
Путь/SHA системной DLL, export directory/name/ordinal bytes сохранены отдельно.
Это подтверждение по локальным данным, не догадка по сигнатуре вызова.
При обновлении системной DLL export evidence нужно пересоздать.

## Native ветки отправки

При непустой очереди и handle!=0 native вызывает send(pointer, available, 0).
Неотрицательный результат передаётся слушателям через helper `0x1445dede0`,
после чего `0x1445e5ef0` потребляет ровно указанное число байтов. Partial consume
использует memmove с остатком и sentinel, обновляет end pointer; непереданная
часть остаётся. Полная отправка оставляет только sentinel. Zero send оставляет
байты без изменений; автоматическое закрытие в этой ветке не найдено.

При отрицательном результате error-query вызывается через slot+0x68 runtime
socket manager. Значения 22,23,37 возвращают управление без consume/close.
Имена этих engine enum values не доказаны: не называть их напрямую Winsock
кодами. Для других значений выполняются diagnostic `0x1445de8b0` и close
`0x1445e5a50`. Пустая очередь или handle0 не вызывают системный send.

Builder исполняет настоящий drain и consume/memmove. Send/error-query заменены
результатами fixtures, listeners отсутствуют (snapshot fixtures предыдущего
harness). Fatal diagnostic/close перехвачены с проверкой owner, весь shutdown
не исполняется. Поэтому remaining_hex fatal cases — очередь при запросе close,
не обещание сохранить эти данные после настоящего закрытия. Constructor/vtable
связь подтверждена статически, сам constructor не исполняется.

61 сценарий покрывает sizes1/8/27/46/127/256, partial/full/zero returns,
шесть значений error query, empty/no-socket. Все send arguments/payload/flags
проверены; native emulator не вызывает системный сокет и не выходит в интернет.
Наличие send API не доказывает отсутствие шифрования на всех других этапах,
готовый connect flow, серверные адреса или совместимость с сервером игры.

## Переносимый код и настоящий локальный TCP

`outbound.py` дополнен read-only `peek_frame` и `consume_sent`: очередь хранит
immutable ciphertext и offset головы, отбрасывает только успешно переданные
байты. Byte budget считает pending bytes; удержанный префикс частично отправленной
головы занимает дополнительно до 26 байт для текущих packets19/27. Количество
frames ограничено отдельно; никаких неограниченных history/copies в ядре нет.
`pop_frame` после partial отправки возвращает только остаток; без partial сохраняет
прежний контракт возврата исходного bytes без копии. Один session owner.

`socket_send.py:drain_outbound(sock, queue, *, max_send_calls)` работает с уже
подключённым неблокирующим socket. Call budget ограничивает работу за проход.
Partial writes сдвигают offset; BlockingIOError/InterruptedError оставляют хвост
и возвращают blocked=True. Иные OSError передаются владельцу сессии, без reconnect
или replay. Zero send вызывает ConnectionError — явная локальная политика строже
найденной native zero branch. Это не реализация readiness scheduler/таймаутов.

Пять тестов: source/import/export provenance, все native cases и дополнительные
replays; fake socket partial→blocked→resume, fatal/zero/work budget; настоящий
IPv4 TCP через 127.0.0.1 с ephemeral port. Через реальные socket.send/recv
переданы ack под старым ключом и Ping под новым, проверены все bytes и queue budget.
После теста sockets закрыты. Это local transport test, не связь с игровой сессией.

Далее: connection setup/endpoints/auth H04, receive accumulation и полноценный
bounded session lifecycle/readiness/таймауты/reconnect. Notify→wire вместе и
native shutdown/error/lifetime paths остаются отдельными пробелами.
Игра/аккаунты не использовались. `network_ready=false` означает отсутствие
проверки протокола с сервером игры, несмотря на прошедший loopback TCP test.
