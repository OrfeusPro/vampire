# Готовность сокета → NnPeerImpl::OnTcpPeerConnected

Уточнение следующего исследования: поля P+0x308/+0x310 оказались storage
делегата и числом 16-байтовых единиц. Условное имя owner/count ниже относится
к прежним fixtures; [actual binding/bridge и игровой target](HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md)
теперь проверены отдельно.

19 октября 2026. Продолжение [option translation](HEADLESS-SOCKET-ERROR-OPTION.md)
и [readiness job](HEADLESS-SOCKET-READINESS-JOB.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-socket-ready-notification.py](../../../replay-socket-ready-notification.py) →
`F:/PhoneExit Resources/Vampir/code-clues/socket-ready-notification-replay.json`.
SHA256: `d9f6d5bbaff26ab5f97ecc0f9613773313ce1b86182c7de0dfba42a87f6812f8`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-socket-ready-notification.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report содержит SHA источника, инструмента
и двух upstream reports; fragments, leaf bytes, file offsets, vtables,
пятнадцать проверяемых constructor/registration bindings и diagnostic strings.
Worker ограничен одной итерацией, completion вручную запускается после неё.

## Подписчики связаны с источником

Обозначим начало peer как P. Base constructor **0x1445e2af0** вызывает
shared-interface constructor **0x1445d91c0** с P+0x50. Тот записывает
interface pointer в this+8, следовательно pointer pair начинается в P+0x58.
Derived constructor **0x144aab540** устанавливает vtable **0x14961b8c0**
в P+0x50. Его инструкция 0x144aab5b4 загружает адрес таблицы, 0x144aab5bb
сохраняет его. Lower connect **0x1445ea1b0** берёт pair P+0x58 и вставляет
в очередь P+0x118 = socket+8. Native inserts ранее исполнялись в
[lower-connect replay](HEADLESS-CONNECT-RESOLVER-HANDOFF.md).

Derived constructor аналогично создаёт interface P+0x200, pair P+0x208
и вставляет его в очередь P+8. Vtable **0x14961b8f0** загружается на
0x144aab5bf и записывается на 0x144aab5c6. В новом replay сами constructor,
registration и snapshot acquisition не исполняются: подписчики и queues
воссозданы fixtures с отдельно проверенными source offsets/targets.
Это не доказательство полного startup/lifetime клиента.

## Две реальные native рассылки

После fixture write-ready/успешного getsockopt с output 0 worker получает
state2→6 и completion code 1. Actual completion вызывает **0x1445de8b0**
с socket owner и action **0x14370ae90**. Этот bounded leaf — virtual+0x10.
Dispatcher читает snapshot socket+8, проверяет weak reference/strong count
и вызывает action для живого ненулевого listener.

Таблица 0x14961b8c0 slot+0x10 → **0x1445e8900**. Этот leaf исполняется:

1. Записывает DWORD1 в interface+0xb8 = **P+0x108**.
2. Вычитает 0x50 из this, получая P.
3. Вызывает тот же dispatcher с owner P и action **0x1445c018c**.

Новый action — virtual+0x18. Очередь теперь P+8; её listener P+0x200
имеет vtable0x14961b8f0, slot+0x18 → **0x144aac520**.
ASCII diagnostic по 0x14961bcb0 и UTF-16 string по 0x14961bcf0
называют функцию **NnPeerImpl::OnTcpPeerConnected()**. Bytes/encoding/refs
сохранены в report. Это source name, не вывод из совпадения адресов.

Один action pointer применяется к разным интерфейсам: первый code 1
сам по себе не определяет смысл virtual+0x10 во всех остальных рассылках.

## Что делает transport recipient

Тело 0x144aac520 теперь исполняется, diagnostic formatting/logging — fixtures.
Actual getter **0x143231f80** возвращает P+0x110, то есть socket object.
Затем вызывается **0x1445ead40** с raw args EDX2/R8D16/R9B1.
Этот helper capture: системная семантика этих параметров пока не установлена.

Далее recipient обнуляет word **P+0x240** и qword **P+0x248**.
Если byte P+0x2a5 ненулевой, пишет word0x100 в P+0x2a5,
обнуляет DWORD P+0x2a8 и вызывает отдельный helper path. Getter/helper
в этом path — captures, их продуктовый смысл не присвоен по raw offsets.

Recipient создаёт endpoint, вызывает socket endpoint getter **0x1445e7680**.
В новом replay тот явно возвращает false. Следовательно native ветвь
преобразования полученного адреса не покрыта; FString для owner остаётся пустым.

При DWORD **P+0x310 != 0** и pointer **P+0x308 != null** выполняется
**owner virtual+0x60** (call site **0x144aac7c2**), RDX указывает FString.
Вызов захвачен на явно synthetic owner vtable. Источник actual owner,
его table/target, endpoint text и переход к packet Login ещё не доказаны.
Оба условия независимы: owner_count0 и null_owner по отдельности подавляют call.

## Проверки и границы

10 native scenarios: ready-owner, no-owner-count, null-owner, empty-socket,
empty-peer, expired-socket, expired-peer, null-socket-listener,
null-peer-listener, special-flag.
[Три regression tests](../../../../../test_vampir_headless_socket_ready_notification.py)
проверяют воспроизводимость/source bindings, порядок двух recipients,
изменения fields, callback gates и exact boundary для пустых/expired/null
подписчиков. Dispatcher делает native weak pin/unpin, итоговые strong counts
не меняются; удаление expired/null listener — prune capture.
Три новых и шесть смежных tests option/readiness прошли.

При отсутствии socket listener state socket всё равно 6, но P+0x108 остаётся 2.
Если socket listener жив, а peer listener отсутствует, P+0x108 становится 1,
но transport fields и owner callback не затрагиваются. Ни один из этих
client flags не доказывает серверную авторизацию.

Snapshot allocation/release/prune/free, formatting, socket configuration,
endpoint getter и owner callback остаются fixtures/captures. Syscalls,
scheduler и platform inputs сохраняют границы предыдущего replay.
Гонки, scheduler threads/lifetime, real sockets, Android parity и server
session не проверялись. Runtime не менялся, полный runtime suite не повторялся.
Игра не запускалась; profile/process memory/credentials/network не использованы.

Следующее звено: кто устанавливает P+0x308/+0x310, actual owner vtable+0x60
и путь от OnTcpPeerConnected к Login. Отдельно остаются настоящий endpoint
getter, configuration helper и error/retry recipients.
