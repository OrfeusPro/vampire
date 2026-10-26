# Текущая CSV задач и нативная проекция типа

EXE 1.13.16 SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
PAK SHA256:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
CSV entry 2983, полный decoded SHA256:
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.

Проверены текущий PAK, record index, reader / Oodle и декодированное тело записи.
17 колонок, 5944 уникальных task IDs, 1353 quest groups. Полный CSV и созданный
каталог хранятся в библиотеке ресурсов вне Git. Это не исторический QuestTask CSV:
его прежний SHA `51564c41...` не совпадает с текущим.

## Подтверждённая связь полей

Getter `145b547a0` возвращает manager `14b1c4bf0`. В статических данных по +0
находится table `1499f6948`, по +8 — secondary interface `1499f69e8`.
Её slot +0x38 указывает на CSV loader `145b5f270`, получающий secondary this.
Его +0x10 / +0x60 соответствуют manager +0x18 / +0x68.

Loader содержит ссылки на все 16 основных имён колонок, включая Id / QuestInfoId /
Type. Source-checked stores: Id → record+0x40; QuestInfoId → +0x48;
Type → byte +0x8c. Group-building loop читает quest key по row-node+0x50,
вызывает `145b4ad00` для массива группы и добавляет pointer row-node+8 в конец.
Node stride первичной таблицы — 200 байт, record начинается после qword key.

`145b4ab90` ищет / создаёт первичную запись, `145b4ad00` — group array;
`145b53b10` очищает первичную таблицу. Сама аллокация sparse slots в этих двух
FindOrAdd ещё делегирована `145b4a420` / `145b48b50`, порядок не объявляется доказанным.
После группировки primary virtual +0x30 указывает на exact leaf `140bb4a10`
(`b001c3`): возврат true без сортировки. Это не доказывает отсутствие внешних overrides.

У data table `1499f67f8` virtual +0x30 равен `145b55aa0`.
Его точные 8 байт `0fb6818c000000c3` читают byte record+0x8c и возвращают его.
Leaf без unwind root проверен по полному SHA и исполняется как отдельная leaf.

## Что исполняет новая проверка

`replay-quest-csv-projection-11316.py` строит синтетические task records / arrays
из текущих CSV значений. Исполняются целые native lookup `145b4be70`, progress
`145de4610`, pointer getter и настоящий Type getter. Прежней подстановки kind нет.
Manager getter и hash dispatch — fixtures; CSV loader / map clear / insertion
проверены статически, их исполнение не заявляется.

Все 5944 записи прошли: ID, Type и исходный index в результате, low32 counters,
zero tail, сохранение padding и output guards. Task records / arrays / manager
сохраняются. Ни одна группа не превысила диапазон неотрицательного signed index.
Тест `test_vampir_quest_csv_projection_11316.py` прошёл; зарегистрирован
`native-quest-csv-projection-11316` с source-bound PAK dependency до обращения к cache.

Exports с полными SHA закреплены в `knowledge/native-contexts/quest-csv-projection-11316.json`:
`run-bc83e3fb45a2` (явная семья manager methods), `run-1fa2db2b2606` (3 helpers),
`run-b865a737d979` (progress), `run-6978cfe0cd9d` (lookup).
Артефакт каталога и результата:
`code-clues/quest-csv-projection-11316/790c25cedf3ed929bd2dfb14d0a2ef4ba0d66948c4c241feadb9af431b4c74f8/manifest.json`.

## Квест 110120 и допуск

В CSV перечислены 110120005 / 010 / 020 / 030 / 040 / 070 с одним prefix 110120:
Time 0.1, перемещение, Dialog group 11012002, перемещение, LevelSequence, Time 1.
Param и QuestActionPos — данные определения, не полученная реплика / текущая
позиция и не разрешение пропуска. TargetSpotInfoId нельзя подставлять в packet
TargetId как ID живого NPC.

В отчёте явно `csv_order_admitted=false` и `active_step_admitted=false`.
CSV file order — кандидатный порядок каталога. Не исполнены sparse insertion,
service-group row filter `145a4d2f0`, data override и реальная загрузка manager.
Нельзя считать первую строку активной только по raw progress 0.
Следующий шаг — проверить эти границы и связать индекс живого персонажа с данными;
игровых команд, runtime contract admission и переподключения в этой проверке нет.
