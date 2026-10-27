# Переход pending очереди к пакету QuestUpdate

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Current final request:
`5b24d1f3cf489f974f0ea0e65682f04d6cad5af66a67c86df310f2a04bc65279`.
Источник двух Time pending records:
[предыдущее native доказательство](HEADLESS-QUEST-PENDING-TIME-11316.md).

## Источники и связывание

Исполняются whole roots secondary update `1455cd260`, concrete consumer
`145d853f0` и named producer `145d6f9b0`. Полные SHA256 exports:

- run-e9cf36d161f7 — `7f3f0c1ad6bc2ff9912a604b7a89adebe9ac1b18b3b596692c645c51531c25e4`.
- run-6f0a0e3fe661 — `50cb400c0991cf46a9f98a6e84668fa90e17795cedb9457634e6105c95164132`.
- run-22845de261d6 — `6d9f884d134d8472ef621b1c674a6385c7016962511c7db2d37c396b6b6eda73`.

Старый producer export имеет block coverage, но не новый direct-flow flag.
Только для этого явного root/context допускается отсутствие флага: существующая
`knowledge-index.missing_conditional_fallthroughs` независимо проверяет короткие /
длинные Jcc. Missing или явно false coverage отклоняется. Все исполняемые
инструкции/leaf bytes дополнительно сверяются с EXE строгим harness. Это не
формальное доказательство всех x86 paths и не разрешение остальных producer kinds.

Secondary table 149903E50 / 149A3CF18 указывает на update. Receiver — model+28.
После prelude(model+100) и внешнего boolean gate update проверяет pending count
по receiver+60 (=model+88) и вызывает primary virtual +40 с model receiver.
Base table 149903DE8 имеет там no-op 141403B70; candidate network table 149A3CEB0
имеет 145D853F0. У неё также source-checked shared slot +48 =1455B4D40.
Это доказывает совместимость вызова/таблиц; фактическое конструирование live subtype
и его factory здесь не доказаны. Прежние кандидаты регистрации callback и сброса
flags не объявляются consumer по одному расположению в таблице.

## Native consumer и producer

Consumer требует environment byte+30 >5, затем вызывает producer на каждой
pending записи. Return 0 сохраняет запись; return 1 вызывает групповое разрушение.
Сохраняемые группы сдвигаются вниз через source thunk memmove 1487F5ABF;
его PE import проверен как vcruntime140.dll/memmove. Итоговый count сохраняется
в model+88. Аллокация не меняется.

Для kind=1 producer проверяет busy с аргументом 0x713 (1811), получает owner /
actor reference, требует найденную quest model record. Actual packet constructor
145828B00 создаёт table 149965670; её ID getter 145834490 возвращает 1810.
Native MOV копируют три double координаты из component+1F0 либо исходных globals
14B0C0298 / 2A0 / 2A8 при null component. Записываются TargetId, QuestInfoId и
QuestTaskIndex, затем вызывается 144AAE900(provider, packet, 0x713, quest, 0).
Role аргумента 1811 и его reply reader ещё требуют отдельного доказательства.
Packet cleanup 1456B66C0 остаётся проверяющей fixture.

Return 1 **не равен отправке**: при missing owner/actor/model этот путь тоже
завершается 1, и consumer удаляет запись без созданного пакета. Busy возвращает 0,
поэтому запись сохраняется. Нельзя подтверждать действие по исчезновению pending.

## 24 сценария и локальный wire

Две native Time pending записи (индексы 0/5) × 12 режимов: ready, busy,
missing owner/actor/model, component null, environment blocked, update gate blocked,
base no-op vtable, empty queue, mixed busy и one-inflight.
Time→pending replay вызывается заново с current source/PAK checks; его результаты
передаются как структурированные records в новый harness. Общей памяти между
двумя replay нет, внутренний layout opaque property bags остаётся fixture.

При ready / component-null формируется по одному пакету. В первых трёх missing
режимах очередь опустошается без packet sink. При blocked gates / base table /
busy запись сохраняется. Mixed-busy сохраняет tags [0,2], удаляет [1] и сдвигает
последнюю запись в slot 1. One-inflight fixture выставляет busy после первого
packet sink: сохраняются tags [1,3], удаляются [0,2], выполняются два сдвига.
Неизвестный kind 255 используется лишь для conformance группировки, не допускается
как runtime команда. Вызовы native producer наблюдаются read-only code hook.

Сверены actual packet fields, pending count/identity, grouping, exact move ranges,
cleanup count, guards и неизменность остальных model/actor данных. Отсутствующий
TargetId задаётся numeric-getter fixture как 0; native default variant conversion
не заявляется проверенным. Native getter модели, packet constructor и ID leaf
исполняются/сверяются по точным исходным байтам.

`test_vampir_quest_consumer_11316.py` дополнительно передаёт captured native fields
в portable QuestUpdate и новый GameConnection на настоящем локальном socketpair.
Synthetic world entry проходит wire цепочку, затем peer получает 1810 / sequence 4
и тот же encoded body. Это проверяет совместимость с ранее доказанным
[wire codec](HEADLESS-QUEST-UPDATE-WIRE-11316.md), не правильность live actor position
или принятие команды сервером.

## Fixtures, ограничения и следующий шаг

Quest map во время secondary update намеренно пуст: ветвь обновления активных
records не покрыта. Prelude/readiness, model lookup, JSON property conversion,
provider, actor/reference, busy/send/cleanup, destruction и memmove — bounded
fixtures. Состояние busy после первого sink в одном режиме моделируется явно;
native provider/result tracker не исполняется. Engine-corrected live position
и active subtype пока не доказаны. `network_used=false` относится к replay tool;
unit wire использует только локальные синтетические сокеты, игровой сервер не вызывается.
`action_admitted=false`, сохранённая сессия не менялась.

Далее — current обработчик/структура 1811 и корреляция с quest progress 1854;
после этого подготовить ограниченный одноразовый Time тест через owner channel.
Движение, диалоги, обучение и несколько реальных аккаунтов остаются отдельными
требованиями общей цели, этим этапом они не закрываются.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_consumer_11316.py
```

Context `knowledge/native-contexts/quest-consumer-11316.json`, check
`native-quest-consumer-11316`, tool `replay-quest-consumer-11316.py`.
Артефакт: `code-clues/quest-consumer-11316/a7dd0c83e004f55feff0b450e15d0227c21e2f7a8b6dd753b21a70c9138d3454/manifest.json`.
