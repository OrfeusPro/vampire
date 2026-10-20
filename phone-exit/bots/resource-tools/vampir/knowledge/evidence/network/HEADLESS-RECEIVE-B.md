# Vampir — receive-B, ключ и таблица уведомлений

18 октября 2026. Продолжение [Dispatch](HEADLESS-DISPATCH.md).
Общий [реестр](../../../../../vampir/FUNCTION-INDEX.md), [задачи](../../../../../vampir-headless/TASKS.md).

## Источник и повторение

Собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса VA при image base `0x140000000`; версия Windows/Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-receive-b.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_receive_b.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-receive-b.json`,
SHA256 `b27499eb764c50e6bf1ceb87546c5777b1c55e084d048e81aad44f918b050ef0`.
Сохранены source/tool hashes, fragments/instructions/file offsets, singleton getter
и исходная receive-B vtable, все 39 входов/выходов. Только stdlib в runtime;
Unicorn/Capstone нужны инструментам анализа и не входят в бот.

## Исполненный путь

В проверенном втором listener loop vtable заменена на исходную B `0x14961b8f0`.
Slot+0x38 сохраняет length probe; slot+0x40 вызывает wrapper `0x144aacb50`.
Вместо старого callback capture исполняется настоящий Dispatch до входа в
PingResult OnHandler, как в предыдущем этапе. Указатель manager, registry,
listener lifetime и значения ключа заданы явными fixtures.

1. Wrapper берёт key 64 из subobject+0x48 на `0x144aacb74` и вызывает
   XOR `0x144aa6ca0` на `0x144aacb83` для frame+3, length−3. Key0 выбирает
   ранее доказанный fallback. Первые три байта сохраняются.
2. На `0x144aacb88` читается word frame+3 — тот же ID, который затем читает
   Dispatch. Это не дополнительный checksum или sequence header.
3. Getter `0x144aa7c40` возвращает runtime singleton pointer. Его переменная
   находится в zero-initialized virtual data; тест задаёт pointer сам, не
   выдавая нулевое поле EXE за работающий runtime manager.
4. `0x144aa8120` получает manager и ID16. Проверяет таблицу manager+0x38,
   сравнивает word keys и при совпадении вызывает remove `0x144aa7f40`.
5. Настоящий sparse-free helper `0x14142eff0` обновляет allocation bit,
   free chain/count и bucket links. При удалении единственной записи таблица
   становится пустой; тогда `0x144aa7870` обходит список уведомлений manager+8.
6. Wrapper всегда продолжает callback: context=subobject+0x30,
   dispatcher=subobject+0x38, прежний pointer/size. Dispatch читает body с +5.

Семантика владельца таблицы и подписчиков полностью не установлена. Название
«таблица уведомлений» описывает только наблюдаемые lookup/remove/notify; не
объявляется восстановленным механизмом ACK, таймаутов или повторной отправки.
Удаление происходит **раньше** packet reader: короткое тело не отменяет
уже выполненный remove. Это зафиксировано 12 failure cases.

## Проверки и ограничения

39 native cases: 4 фиксированных тестовых ключа × 3 состояния manager
(empty/match/miss) × 2 payloads, все short body lengths0..11 и 3 unknown IDs.
Значения ключей синтетические, не получены из игры. Для match проверяются
free_count=1, bucket=-1, allocation bit=0, first_free=0, а также порядок
remove перед OnHandler. Для empty/miss пакет всё равно доходит до Dispatch.

Notification list в fixtures пуст. Native notify loop исполняет пустую ветку;
его array cleanup `0x1445bb240` заменён shim, который допускает только
pointer 0/count 0. Подписчики, nonempty notification allocation/callbacks,
collision chains/multi-entry removal/concurrency остаются непроверенными.
Native manager lookup/remove/sparse free не подменены.

Унаследованы ограничения предыдущих replay: synthetic registry ID17,
snapshot lifetime fixtures, CRT memory shims, checked security cookie shim,
пропуск reader-failure diagnostic formatting. PingResult OnHandler перехвачен
на входе, игровые побочные действия не выполняются. После возврата native
Dispatch очищает current packet/TLS; внутренний кадр потреблён loop.

В исполненном B пути нет CRC helper/сравнения checksum. Входной layout для
этого пути: length 3, после XOR ID2, затем body. Исходящий send-A CRC/sequence
layout применять сюда нельзя. Это не доказательство отсутствия integrity во
всём socket/library/server пути и не разрешение принимать повреждённые данные.
Live server compatibility и смена ключа между реальными кадрами ещё не проверены.

## Общий код и следующий этап

`receive_frame.py:take_receive_b_frame(buffer, key_bits, *, max_frame_size)`
возвращает один plain frame/consumed либо None, не меняет вход. Key обязателен,
проверяется unsigned64; zero использует fallback. Локальный minimum5 и explicit
maximum сохранены. Это второй уровень; raw bytes сначала проходят transport header.

`receive_packet.py:decode_game_ping_result_b` возвращает типизированный
PingResultPayload. Политика exact body 12/один кадр, как у A helper; ID17 относится
к game context. Общее ядро не выполняет session bookkeeping и не обновляет мир.
Четыре теста сверяют source/provenance, все native vectors, partial/coalesced
input, explicit keys, повторные native replays с изменением тестового ключа.

Далее: send-B/очередь отправки, первичная авторизация, полный session lifecycle.
Оставшиеся transport/library integrity и native error/lifetime ветки сохраняются
открытыми. Сеть, игра и аккаунты не использовались. `network_ready=false`.
