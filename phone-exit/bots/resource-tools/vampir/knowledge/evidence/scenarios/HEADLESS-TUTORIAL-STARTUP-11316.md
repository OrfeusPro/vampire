# Начальное применение обучения 1.13.16

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [current dispatch / defer](HEADLESS-TUTORIAL-DISPATCH-11316.md).
Повторно использован [прежний fresh-startup сценарий](HEADLESS-TUTORIAL-STARTUP.md),
но адреса, getters, exports и инструкции проверены для текущего EXE.

## Native цепочка

| Роль в проверяемом пути | Текущий root |
| --- | --- |
| Применение ID 9905 | `1464c35d0` |
| Копирование записи / hash linking | `14649fe90` |
| Pruning после снимка | `1464c5210` |
| Bootstrap | `1464ce8e0` |
| Построение локальных статусов | `1464cef40` |
| Продвижение локального selector | `1464cc120` |
| Gate следующего шага | `1464c41a0` |
| Lookup временного набора | `14142e6f0` |

Текущие Ghidra exports: `run-c3a2887c3d9b`, `run-b0302e52cb24`,
`run-774fa227622a` под полным SHA выше. Context
`knowledge/native-contexts/tutorial-startup-11316.json` закрепляет их SHA и
два явных getter leaf: `141488490` читает pointer +8, `141500410` — pointer +0.
Другие cached accessors не подменяются ими по похожему имени.

`replay-tutorial-startup-11316.py` исполняет целые перечисленные функции
с current bytes и всеми принадлежащими им unwind ranges. Для fresh сценариев
pruning проходит без удаления, а gate — только ранние ветви возврата.
Вызовы невалидных / неподтверждённых целей останавливают harness.

## 192 комбинации

Покрыты count 0 / 1 / 16, наличие / отсутствие fixture-строки таблицы,
synthetic policy row+0x50 = 0 / 1, первый state 0 / 1 / 2 / 3,
selector 0 / 1 и оба значения data flag. Остальные записи имеют state 0.
Использованы свежие уникальные ключи из прежней bounded матрицы; реальный аккаунт
или действующее состояние персонажа не являются входными данными.

Подтверждено в этих границах:

- отсутствующая fixture-строка не даёт серверную запись;
- native копирование сохраняет raw08 / raw0c / raw10 / state в server map;
- при state 1 и доступной строке создаётся локальная задача;
- при заданном descriptor+8 = 2 и selector 0 / 1 ранний gate возвращает AL=0;
  native advance увеличивает локальный selector и передаёт его task-launch fixture;
- серверный selector при этом не увеличивается вместе с локальным;
- остальные проверенные состояния не запускают локальную задачу;
- data flag не используется здесь как команда завершения обучения.

Все 192 сценария прошли, 16 дошли до launch fixture. Guards context, server /
local nodes, buckets, input records, row, descriptor и status storage сохранены.
Native копирование, hash linking, итерация, формирование статусов и ранние gate
не заменены Python-моделью.

Отчёт вне Git:
`code-clues/tutorial-startup-11316/c19223189b83e99520caf61702f0e21666e33a68e15a0708f36e77d850ec1003/manifest.json`.

## Явные fixtures и ограничения

Lookup `145c24be0` и descriptor lookup `145c24d40` выдают подготовленные
синтетические строки. Выдача map slots / status storage, cleanup временных
структур, cookie check и task launch `1464ce5b0` — fixtures.
Buffers / buckets имеют готовую ёмкость; рост и освобождение реального heap
этими проверками не подтверждаются.

Нет проверки duplicate replacement, populated maps / existing local tasks,
удаления отсутствующих ключей, rehash, completion gate, queue drain и эффектов
реального запуска задачи. Готовность native клиента не связывается автоматически
с headless ID 206. Данные runtime остаются last_received_message; разрешение
отправлять tutorial / quest команды не добавлено.

Смысл row+0x50 и timer row+0x60 не выведен из похожих названий CSV колонок.
Серверный raw0c и локальный selector остаются раздельными. Проверенные selector
0 / 1 при fixture descriptor 2 не доказывают допустимость команды для реальной
записи с raw0c = 2 или другого активного шага.

Следующий участок — populated application / queue consumer и цепочка loader →
row fields / callbacks → условия готовности и запуска. Затем новое живое
сообщение обучения владельцем с current decoder, без слепого повтора старого ack.
