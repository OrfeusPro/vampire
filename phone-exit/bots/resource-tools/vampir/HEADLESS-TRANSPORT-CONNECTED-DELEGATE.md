# Делегат подключения транспорта → игровой получатель

19 октября 2026. Продолжение [OnTcpPeerConnected](HEADLESS-SOCKET-READY-NOTIFICATION.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-transport-connected-delegate.py](replay-transport-connected-delegate.py) →
`F:/PhoneExit Resources/Vampir/code-clues/transport-connected-delegate-replay.json`.
SHA256: `4f16ba248f907b4b61ea3822390fde5ae1b07aaf8934a2b3dded7e01544b8dd6`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-transport-connected-delegate.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report хранит SHA источника, инструмента,
upstream report, bounded leaves, fragments/file offsets/bytes, три vtable
slot bindings и одиннадцать проверяемых constructor/call/store инструкций.

## Уточнение прежнего названия полей

В предыдущем replay P+0x308/P+0x310 условно назывались owner pointer/count.
Raw offsets и два условия были верны, но новый allocator source уточняет
семантику: это **pointer на storage делегата и число 16-байтовых единиц**,
а не число владельцев или refcount. P — начало NnPeerImpl.
Объект-цель находится в самом delegate storage по offset0x18.
Прежние fixture names owner_present/owner_count сохранены для сравнения gates;
они не являются именами восстановленных полей клиента.

## Откуда приходит делегат

Root **0x1467aa0e0** вызывает **0x144aaadb0** на **0x1467aa108**.
Последний создаёт NnPeerImpl, кладёт его pointer в wrapper+0x10 и в tail
связывает notification delegate. Новый replay начинает с **0x144aaae8d**
и останавливается перед epilogue на **0x144aaaf05**. Полный constructor,
allocation/initialization peer и startup не исполнялись; wrapper/peer fixtures.

В этом slice native код:

1. Читает P из wrapper+0x10, пишет wrapper в **P+0x230**.
2. Готовит размер0x30 и descriptor **P+0x308** для **0x1414276b0**.
3. Этот actual allocator wrapper округляет размер к 16-байтовым единицам,
   получает3, вызывает resize backend и записывает3 в descriptor+8 = P+0x310.
4. При ненулевом allocation устанавливает delegate vtable **0x14900a528**,
   target wrapper в delegate+0x18 и method pair в +0x20/+0x28.

Resize backend **0x1414311c0** — ограниченный fixture, получает units3/unit16.
Instance identity getter **0x141429520** тоже fixture (значение17); identity
не используется проверяемым invoke path. Native allocator wrapper и все
stores delegate реально исполняются. Alloc-fail — намеренно synthetic backend
response: storage pointer0, units всё равно3 в данном source body.
Это не утверждение о политике реального allocator при нехватке памяти.

## Native invoke и игровой target

OnTcpPeerConnected проверяет units != 0 и storage != null; его virtual+0x60
теперь ведёт к source delegate table slot+0x60 → **0x14370c510**.
Этот bridge реально исполняется: берёт target+0x18, через actual bounded
leaf **0x14141cbc0** получает исходный pointer, прибавляет signed adjust
из delegate+0x28 и вызывает method pointer из delegate+0x20.

Binding записал adjust0 и method **0x1437113ec**, bytes `488b01ff6048`:
это virtual+0x48 для target wrapper. Game construction root **0x1467a79e0**
на 0x1467a7ac4/0x1467a7acb загружает/сохраняет wrapper vtable
**0x149d84e50**. Её slot+8 = root0x1467aa0e0, slot+0x48 =
**0x1467a9cd0**. Так source связывает initializer, binder и получателя;
это не выбор адреса по похожему имени.

В replay actual table0x149d84e50 установлена synthetic wrapper. Делегат
доходит до **0x1467a9cd0**, проверяются this == wrapper и RDX FString.
**Тело игрового получателя ещё capture на входе**, packet/Login не исполнялись.
Его code fragment сохранён для следующего исследования. Из предыдущего
endpoint-getter fixture приходит пустой FString; непустой адрес пока не покрыт.

После method bridge безусловно пишет **AL=1**. Fixtures callback false/true
дают одинаковый AL1. Это признак выполнения delegate bridge, не подтверждение
авторизации, корректного пакета или server session. Recipient не должен
интерпретироваться как успешный Login по одному return value.

## Проверки и границы

12 native scenarios: десять inherited listener/owner gate scenarios плюс
allocation-fail и callback-true. После native binding два gate fixtures
преднамеренно обнуляют units либо storage, чтобы отдельно проверить оба условия.
Это искусственные изменения после binding, не выходы constructor.

[Три regression tests](../../test_vampir_headless_transport_connected_delegate.py)
повторно строят report; проверяют source/table/action bindings, units3,
method/adjust/target, backpointer, gates и независимость AL1 от callback result.
Три новых и шесть смежных tests notification/option прошли.

Полный constructor, real allocator backend, identity getter, game recipient
body, endpoint getter и остальные inherited syscall/scheduler/snapshot helpers
остаются за пределами проверки. Worker ограничен одной итерацией, completion
вручную запускается после неё. Полный lifetime/races/OS readiness/Android parity
и server-compatible session не проверены. Runtime не менялся, полный suite
не повторялся. Игра/profile/process memory/credentials/network не использованы.

Далее **0x1467a9cd0**: packet constructor, источники полей, virtual send+0x38
и его связь с Login. До проверки constructor/serializer не присваивать имя
пакета только по месту в последовательности подключения.
