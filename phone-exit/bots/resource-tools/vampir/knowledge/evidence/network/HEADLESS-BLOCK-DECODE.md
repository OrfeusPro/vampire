# Vampir — распаковка транспортных блоков и второй слой приёма

18 октября 2026. Продолжение [первого transport stage](HEADLESS-TRANSPORT-STAGE.md).
Общий [реестр](../../../../../vampir/FUNCTION-INDEX.md), [задачи](../../../../../vampir-headless/TASKS.md).

## Источник и воспроизведение

Собранный клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA при image base `0x140000000`. Версия Windows и соответствие Android неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-block-decode.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_block_decode.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-block-decode.json`:
SHA256 `591c7ecb60d0fa70c5c7e4c85b190409bd4651bb7659b983ba226d825b765d21`.
Содержит source/tool hashes, исходные инструкции/смещения/fragment hashes,
copy table bytes, thunks и все входы/выходы проверок. Зависимости анализа
закреплены в requirements-native.txt; runtime использует только stdlib.

## Подтверждённая грамматика блока

Нативная функция `0x14141ba60` получает RCX=source, RDX=destination,
R8D=input size, R9D=output capacity. Возвращает число распакованных байтов
или отрицательный результат ошибки. Это независимый блок без внешнего словаря;
идентичность сторонней библиотеке или конкретная версия алгоритма не заявляется.

- Старшая половина token задаёт длину литералов, младшая — длину match минус 4.
- Значение 15 продолжает длину следующими байтами: 255 означает продолжение.
- Литералы копируются непосредственно; match содержит LE16 смещение назад.
- Повторы могут перекрываться: offset=1 воспроизводит один байт много раз.
- Блок заканчивается литералами. Для последовательностей с match проверяется
  финальный хвост; malformed lengths/offsets и выход за capacity отклоняются.

Прямые anchors: token split `0x14141bafd` / mask `0x14141bbcb`, offset word
`0x14141bbbd`, extended match `0x14141bbe0`, minimum match +4 `0x14141bc2d`,
проверка истории `0x14141bc42`, обработка tail `0x14141c069`, error `0x14141c0b0`.
Small-offset copy tables по VA `0x14898cd78..0x14898cdb7` сохранены с bytes/SHA.
Они используются настоящим native decoder, не подменяются Python результатом.

166 успешных native executions включают литералы 0–1024 байта, offsets
1/2/3/4/5/7/8/15/16/31/255/512, match lengths 7/18/19/20/270/540,
несколько matches, extended lengths, точную и запасную output capacity.
86 отрицательных случаев: повреждённые длины/история и capacity на байт меньше
необходимой. Каждый результат сравнивается с общим Python decoder.
Это покрытие выбранных ветвей, не доказательство идентичности на всех входах.

Native replay изолирован: заранее выделенные scratch buffers, максимум
2048 input / 4096 output, настоящий код клиента и copy tables, только внешние
CRT memory функции заменены ограниченными shims. Несколько блоков дополнительно
пропущены через весь ранее исследованный первый stage: decompress→append→compact.
Ошибка самого decoder исполнена; диагностическая ветка peer после ошибки ещё нет.

## Общий переносимый код

`vampir-shared/vampir_core/block_decode.py`:
`decode_transport_block(block, *, max_output_size)`.
Обязательный бюджет 1..1048576 соответствует верхней capacity исследованного
native stage. Выход растёт ограниченно, перекрывающиеся matches копируются
порциями. Повреждённые данные вызывают ValueError. Offset=0 отклоняется локально;
случайные записи native decoder для такого некорректного входа не копируются.
Native parity для всего диапазона 1 MiB и всех malformed inputs не заявляется.

В `transport_header.py` добавлен `take_transport_frame(buffer, *, max_frame_size,
max_output_size)`: возвращает один body и consumed либо None для неполного кадра.
Принимает compressed и uncompressed ветки skip=3, сохраняет границу первого кадра,
ограничивает оба размера, отклоняет пустой compressed output как native stage.
Старый явно uncompressed helper сохранён с прежним контрактом.
Это не socket loop, не сборщик всех внутренних пакетов и не обработчик сессии.

## Связь второго слоя — статическое доказательство

В root `0x1445ed3e0` второй byte vector находится в owner+0x198/0x1a0.
На `0x1445ed723` вызывается thunk `0x1415f6848`:
`mov rax,[rcx]; jmp [rax+0x38]`. Ему переданы listener, owner, buffer и available
(последний не включает NUL sentinel). Для известных vtables A/B слот +0x38
указывает на length probe `0x144aa9a90` из HEADLESS-RECEIVE-ENVELOPE.md.
Результат записывается в R14D; при нескольких живых listeners его перезаписывает
последний вызванный listener. Универсальность порядка для иных listeners неизвестна.

Если результат положительный, LEA `0x1445ed65a` выбирает thunk `0x1437113e4`
со слотом +0x40. Вызов `0x1445ed677` передаёт thunk в helper `0x1445dede0`.
Тот сохраняет указатель и вызывает его на `0x1445def22` с listener/owner/buffer/size.
Для A/B +0x40 ведёт в wrappers `0x144aa9c00` / `0x144aacb50`, уже исследованные
отдельно. Затем исходный цикл сдвигает обработанные байты через memmove
`0x1445ed6b7` и повторяет разбор оставшегося внутреннего буфера.

Это связывает первый stage, length probe и receive wrappers по инструкциям.
Snapshot/deque/refcounts/cleanup всего listener loop ещё не исполнены вместе.
CRC всего входного пути, конечный handler slot+8→OnHandler+10, send queue,
первичная авторизация и live transport остаются следующими зависимостями.
`network_ready=false`; игра, аккаунты и сеть в этих проверках не использовались.
