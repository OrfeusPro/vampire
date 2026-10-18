# Vampir — исполнение второго цикла приёма

18 октября 2026. Продолжение [block decoder](HEADLESS-BLOCK-DECODE.md) и
[receive envelope](HEADLESS-RECEIVE-ENVELOPE.md). Общий [реестр](../../vampir/FUNCTION-INDEX.md).

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это код клиента, не исходный C++ проект. VA при image base `0x140000000`.
Версия выпуска и Android parity неизвестны; при другом SHA повторять исследование.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-listener-loop.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_listener_loop.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-listener-loop.json`,
SHA256 `d89a0da84def91cbd57b567c821f0cf883531ed172fcc97b91bdbe9ddbaffeb1`.
Сохранены source/tool hashes, fragment/instruction bytes с file offsets,
SHA leaf functions, исходная receive-A vtable, 44 входа и выхода.

## Исполненная цепочка

Slice `0x1445ed572..0x1445ed730` из `UxTcpPeer::_HandleRecvBuffer` теперь
исполняется вместе с helper `0x1445dede0`, настоящими virtual thunks и
receive-A wrapper `0x144aa9c00`. Это продолжение первого этапа, не повтор
статического поиска. Owner, stack, byte vector и один listener заданы явно.

1. Число доступных байтов вычисляется из owner+0x198/0x1a0 минус NUL sentinel.
2. Thunk `0x1415f6848`, вызванный на `0x1445ed723`, использует slot+0x38:
   настоящий length probe `0x144aa9a90` возвращает размер полного кадра либо 0.
3. Положительный размер передаётся через `0x1445dede0` и thunk `0x1437113e4`
   в slot+0x40 исходной vtable `0x14961af58`: receive-A wrapper.
4. Wrapper вызывает настоящий XOR `0x144aa6ca0` для байтов после первых трёх.
   Fallback key закреплён предыдущим исследованием; первые три байта сохраняются.
5. Финальный callback получает прежний pointer, полный размер и context
   listener+0x18. Здесь установлен capture shim: сохраняет bytes/проверяет args.
6. Native loop вызывает memmove на `0x1445ed6b7`, сдвигает остаток вместе
   с sentinel, обновляет end pointer и повторяет разбор.

Таким образом теперь исполнен возврат из wrapper обратно в цикл, включая
несколько кадров. Dispatch приложения и реальный handler в эту цепочку не входят.

## Явные подстановки и ограничения

Snapshot helper `0x1445e2010`, cleanup `0x1445ddb70`, free `0x14142c480` и
expired-listener cleanup `0x1445dae30` заменены проверяемыми fixtures.
Snapshot задаёт один живой listener, истёкшую ссылку или пустой список.
Все выделения заранее сделаны в scratch; размеры/адреса аргументов проверяются.
Баланс snapshot/cleanup/free и native reference count проверяется на каждом входе.
Реальные atomic increment/decrement в цикле и broadcast helper исполняются;
destructor/allocator paths, concurrent lifetime changes и несколько listeners
этим не проверены. CRT memory функции — ограниченные shims прежнего harness.

Проверка не использует socket, процесс игры, аккаунт или сеть. Native bounds:
до 2048 входных байтов, заранее выделенные vectors. CRC во всём входном пути,
receive-B до конечного handler и live transport остаются неизвестными.
Не объявлять весь native listener lifecycle или полноценный сетевой клиент готовым.

## Проверки и общий код

44 native случая: разрезы заголовка/body, размеры body 2/3/8/16/64/255,
три полных кадра с неполным хвостом, отсутствие listener и expired reference.
При отсутствии доступного listener данные остаются в буфере.

Пять тестов проверяют provenance, все vectors, повторное native исполнение
с продолжением неполного кадра, отсутствие mutation входа/явные локальные лимиты.
Дополнительный связанный replay разбивает один внутренний кадр между тремя
сжатыми транспортными блоками (в том числе внутри его заголовка): native первый
stage→decompress→append, затем native второй stage→probe→wrapper→capture.
Во входе также есть второй склеенный кадр; оба выходят без потери/дублирования.

`vampir-shared/vampir_core/receive_frame.py` дополнен
`take_receive_a_frame(buffer, *, max_frame_size)` → (plain_frame, consumed)
или None. Header сохраняется; возвращается opaque frame, не модель пакета.
Только receive-A/fallback XOR, без предположения о ключе B, CRC и семантике body.
Local policy size>=5 строже native probe; вход не меняется, extra frames остаются
непотреблёнными. Raw socket bytes сначала требуют transport_header.py.

Далее: фактический Dispatch/handler wrapper, входная целостность/layout,
очередь отправки и lifetime/error paths. `network_ready=false`.
