# Обновление существующих записей обучения 1.13.16

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [fresh-startup](HEADLESS-TUTORIAL-STARTUP-11316.md).

Текущий builder `1464cef40` вызывает `1464d01a0`; его целый root со всеми
chained-unwind ranges выгружен в `run-9d8a01b69502/details.json` под полным
текущим SHA. SHA экспорта и адрес закреплены в
`knowledge/native-contexts/tutorial-populated-11316.json`.

`replay-tutorial-populated-11316.py` исполняет whole `1464d01a0`, включая
native lookup, обход коллизий и stores существующих server / local записей.
Матрица: наличие / отсутствие server и local записи, inline / external bucket,
selector 0 / 2 / 0xffffffff, incoming state 0 / 1 / 2 / 3, keep 0 / 1,
gate AL 0 / 1. Все 384 комбинации прошли; guards сохранены.

Подтверждено в этих границах:

- server map context+0xa8 сохраняет все четыре поля входящей записи;
- local map context+0x1c8 при наличии ключа получает raw08 / raw0c / state,
  сохраняя прежний raw10;
- gate AL=1 останавливает дальнейшее продвижение, но не предшествующее копирование;
- gate AL=0 и keep=0 увеличивают локальный selector с uint32 переполнением;
- при gate AL=0 входящий state 0 переводится локально в 1;
- при gate AL=0 вызывается launch с локальным selector;
- без local записи gate / launch не вызываются, server запись обновляется;
- посторонние записи коллизионной цепочки не меняются.

Отсутствующая server запись выделяется ограниченным insertion fixture
`1464a0950`; gate `1464c41a0` и launch `1464ce5b0` также fixtures.
Эта проверка не исполняет полный native allocator / rehash, completion gate,
consumer очереди и запуск задачи. Вызовы gate проверяют аргументы и заданный
результат; они не доказывают условие допуска реального персонажа.
Не проверяется повторное применение целого ID 9905 или replacement в общем
map helper `14649fe90`: здесь исследуется отдельный helper `1464d01a0`.

Source-bound отчёт вне Git:
`code-clues/tutorial-populated-11316/87bcd1c65f886efad2bd5233909d32fed0d91442b69f25380270a6e2bfd50767/manifest.json`.
Сценарии синтетические, игровых запросов и входов нет. Runtime по-прежнему
публикует last_received_message; этот эксперимент не добавляет команду ack.

Следом — текущий consumer очереди, missing-key pruning / replacement и цепочка
loader → policy row+0x50 / timer row+0x60 → callbacks → реальный task launch.
