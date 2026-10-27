# Current QuestUpdateResult: полная структура ответа

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `51148205139832f84442ae09be97e22e96f33206dda83507af2e6bdf0c321ede`.
Предыдущий request b611961c дал outer constructor/reader/writer, следующий
добавил writer вложенного объекта. Полные SHA exports закреплены в
`knowledge/native-contexts/quest-update-result-11316.json`.

## Source binding и native выполнение

Именованный current packet 1811 — PktQuestUpdateResult, table 149965728,
ID getter 1458344B0 (`b813070000c3`). Constructor 145828B50, writer 1458370B0,
reader 14582BCE0. Вложенный объект по packet+28 имеет table 149948B40,
constructor leaf 1457A2A90, writer 1457AB0A0 и reader 1457A6750.
Оба outer/nested reader и writer и оба constructor исполняются целиком.
Nested dispatch wrappers 144AAD190/144AAD570 проверены точными 15 байтами,
их tail jumps вызывают настоящие nested virtual methods. Table slots сверены.

Порядок wire: `<IQBBQQ`, ровно 30 байт:

| Wire offset | Размер | Поле объекта | Подтверждённая интерпретация |
| --- | --- | --- | --- |
| 0 | 4 | packet+10 | число результата; success semantics отдельно |
| 4 | 8 | packet+18 | raw qword, смысл ещё не закреплён receiver |
| 12 | 1 | packet+20 | byte, reader ограничивает до 6 |
| 13 | 1 | nested+8 = packet+30 | raw byte без ограничения |
| 14 | 8 | nested+10 = packet+38 | raw qword |
| 22 | 8 | nested+18 = packet+40 | raw qword |

Это не complete QuestRecord на 39 байт. Вложенный объект похож на progress,
но совпадение структуры само по себе не разрешает обновлять модель или
подтверждать действие. Meaning key/state/counters требует current receiver.
Reader может частично изменить object перед отказом; runtime должен принимать
только полный успешный decode, не применять частично записанный объект.

## Проверки

900 полных сочетаний: result 0/10/FFFFFFFF, qword 0/110120/UINT64_MAX,
outer byte 0/2/6/7/255, nested byte 0/5/31/32/255, qword 0/UINT64_MAX и 0/123.
Проверены все stores, outer clamp, неизменность nested byte, exact write bytes,
порядок примитивов 4/8/1/1/8/8, constructor defaults и object guards.
Каждый короткий prefix 0..29 отвергнут; отдельно 6 ошибок чтения и 6 записи
останавливают обработку сразу после отказавшего примитива.

Primitive archive operations — bounded fixtures с явным cursor и byte budgets.
Реальные archive helpers/transport, result handler/provider correlation и сервер
не запускаются. Это whole outer/nested native wire logic, не whole archive IO.
Контекст/инструмент фиксируют fixtures; `action_confirmation_admitted=false`,
`network_used=false`. Существующий codec/owner/живая сессия не изменены.

Exports:

- run-ff6fe83514c3 — outer constructor/reader/writer.
- run-4c6885815290 — nested writer.
- run-47f1d0c509ca — уже существующий nested reader.

Каждый полный SHA и exact leaf bytes есть в контексте и воспроизводимом отчёте.
Артефакт: `code-clues/quest-update-result-11316/7a31909249203441f538034da1f1238ab14275adeffcd7e6f283b32d6bf62015/manifest.json`.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_update_result_11316.py
```

Check `native-quest-update-result-11316`, tool `replay-quest-update-result-11316.py`.
Далее current receive registration/handler 1811 и связь с применением модели,
затем source-bound runtime decoder и подтверждение одного owner action.
Русское представление квестов остаётся выбранным; сетевой locale из него
не выводится. Мультиаккаунтные реальные тесты общей цели пока открыты.
