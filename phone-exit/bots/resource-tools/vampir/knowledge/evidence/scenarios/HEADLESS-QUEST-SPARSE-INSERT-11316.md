# Выбор ячейки задачи и нулевой service group

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [CSV projection](HEADLESS-QUEST-CSV-PROJECTION-11316.md).
Native replay не обращается к сети, процессу игры или онлайн-owner.

Целые `145b4a420` (primary nodes stride 200) и `145b48b50` (group nodes stride 32)
проверены в 96 комбинациях: primary/group, initial count 1/2, append/free-slot,
inline/external buckets, key 0/110120005/UINT64_MAX, hash 0/1.
Capacity заранее выделена; максимум три живые записи, без growth/rehash.
Bit-array append, primary record constructor и duplicate-check — fixtures.
Настоящий код выбирает slot, меняет occupancy, создаёт group header, связывает
hash-chain и возвращает index. Проверены точные bytes nodes/map, guards и порядок
вызовов. Без free slots выбирается прежний count; иначе free-head slot.

Первая тестовая конфигурация initial count 3 + append достигла rehash `145b72e70`:
строгий harness остановился. Ветка не объявляется проверенной; текущий replay
явно ограничен preallocated no-rehash случаями. Этот результат не доказывает
порядок полной таблицы из 5944 строк и не заменяет проверку роста / rehash.

Фильтр `145a4d2f0` проверен для column=-1 и column 0/16/32767 с parsed value 0:
во всех четырёх случаях AL=0 (не пропускать строку), runtime service policy не
вызывается. Parser возвращает 0 как fixture; его обработка пустой CSV ячейки
ещё не доказана. Nonnzero service group идёт в `145c022b0`; её policy не исполнялась.
В current CSV 4317 строк с пустым group, 1627 с 10000; все шесть строк 110120
имеют пустое поле. Это позволяет выделить нужную ветку для следующей проверки,
но само по себе не допускает живой active step.

Первый collect остановился: E9 `145a4d322→145c022b0` выводил decompiler blocks
за исходный список roots. Новое задание добавило точный tail root; штатная
CALL_RETURN metadata сохраняет границы. Успешный export `run-ad5876ba33cb`, SHA
`b269cb2cbd38d2b4f56d20de65759281e1386379cf567ebd4005f44fca45a2aa`.
Первый отчёт без completion receipt не используется как доказательство.

Контекст `knowledge/native-contexts/quest-sparse-insert-11316.json`, инструмент
`replay-quest-sparse-insert-11316.py`, тест `test_vampir_quest_sparse_insert_11316.py`.
Offline check `native-quest-sparse-insert-11316` закрепляет зависимости / экспорт.
Артефакт:
`code-clues/quest-sparse-insert-11316/43240c76a53989d2c8a6574c1b40458676a0f5b44ddf136c615a5affa3214614/manifest.json`.

Далее parser пустого service group, append при росте/rehash, полный порядок sparse
iteration после fresh load и overrides. `order_admitted=false`; runtime actions
и reconnect не включались. Существующая сессия сохраняется.
