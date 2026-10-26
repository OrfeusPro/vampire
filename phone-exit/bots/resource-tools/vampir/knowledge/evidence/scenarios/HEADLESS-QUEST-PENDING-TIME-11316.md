# Time завершение попадает в локальную pending очередь

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Исходные PAK/CSV/Time rows и пять roots:
[предыдущее доказательство Time](HEADLESS-QUEST-TIME-11316.md).
Current final request:
`526411f0d734ae512013f8ae8fa83bd6b6fbf6bd0bed2c6518d632b737a7eee7`.
Новый export run-d21d44654762 SHA256:
`1dc4b111993f2d9f0e19e55ffe8ad6c262d764654ac2586a13b186c1d1a25dd9`.
Root `1455ca010` исполняется целиком вместо прежнего sink fixture.
Остальные exports закреплены полными SHA в
`knowledge/native-contexts/quest-pending-time-11316.json`.

## Подтверждённый переход

Time callback/start/tick/timer/completion выполняются как прежде, затем native
1455ca010 получает фактически построенные named properties. Функция извлекает
QuestInfoId, требует успешный model lookup и копирует свойства во временный bag.
Она обходит pending array: model+80 pointer, +88 count, +8C capacity, stride 58 hex
(88 байт). Для записи с byte kind=1 сравнивает только QuestInfoId. Совпадение
завершает обработку до вызова внешнего guard; TaskIndex при этом не сравнивается.

Если совпадения нет, вызываются provider 144aae520 и guard 144aae5a0 с ushort
model+E6 и record+20. Смысл category/predicate пока не установлен. True guard
подавляет постановку; false добавляет запись kind=1 и копию named properties.
Count увеличивается native кодом, превышение capacity вызывает 1415397a0.
Реального сетевого send или вызова producer внутри этого root не найдено.
Потребитель этой локальной очереди ещё не связан с конкретным packet sender.

## 34 совместных сценария

Две source Time строки × 17 режимов. Сохранены 24 прежних сценария, дополнены:
existing kind1/same quest/same index, same quest/different index, different kind,
different quest и guard rejection. Model lookup, named property read/copy/uint64
conversion, allocation и guard — bounded fixtures. Сам цикл, comparison, branch,
count/slot/type stores и решение о resize native.

В open режиме Time дважды входит в wrapper, но pending counts по пяти ticks
равны `[0,0,1,1,1]`. Поле report `requests` теперь в этом mode означает число
**входов в native wrapper**, не send, постановку или серверное подтверждение.
Вход наблюдается дополнительным code hook, который не меняет RIP/регистры/память;
wrapper полностью исполняется обычным harness.

Existing same quest с другим index не заменяется и не дополняется. Existing
kind2 того же quest или kind1 другого quest сохраняется, затем добавляется
новая kind1 запись: counts `[1,1,2,2,2]`. Новый bag содержит QuestInfoId 110120
и исходный QuestTaskIndex 0 / 5. Guard true оставляет очередь пустой, несмотря
на два срабатывания Time. При same quest guard вообще не вызывается.

Проверены точные arguments guard (explicit category 7), вызовы resize, pending
count и type/properties, неизменность существующей записи/свойств, guards всей
bounded storage (8 slots), прежние owner/control/data/string guards. Capacity
8 и её выделение — fixture; реальный allocator/relocation не исполняются.

## Границы и следующий шаг

Opaque property bags представлены словарями fixture; нативный layout/copy/hash
их внутренностей не доказан. Старые JSON/engine/readiness fixtures остаются.
Прежний standalone Time mode сохранён отдельным тестом. Source rows и установленный
PAK проверяются до и после выполнения; source file resolver остаётся неизвестным.
`action_admitted=false`, `network_used=false`; не было игровых команд или
перезапуска сохранённой сессии.

Нельзя трактовать named completion как немедленный QuestUpdate или переносить
период Time в сетевой retry. Далее найти потребителя model+80 pending array,
связать kind1 с producer и обработкой результата; отдельно проверить guard и
live selected-state/позицию. Native дедупликация не заменяет изоляцию аккаунтов
и не подтверждает реальную многопользовательскую работу.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_pending_time_11316.py
```

Tool `replay-quest-time-11316.py`, новый context native_pending,
check `native-quest-pending-time-11316`.
Артефакт: `code-clues/quest-pending-time-11316/3cbd6557f3fff96f921050cebe88dfba3643054318ec410cf55728de5aeff2f9/manifest.json`.
