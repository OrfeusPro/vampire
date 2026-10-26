# От серверного квеста к модели и объекту задачи

Источник — EXE 1.13.16 SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Статическая проверка, без выполнения native функций, чтения памяти процесса или
команд в игру. Онлайн-сессия Infinix сохраняется без перезапуска.

## Проверенная связь

Точный 8-байтовый leaf getter `1455be4b0` читает global `14b5e4d60`.
Прежний helper rip_candidates ищет LEA; отсутствие его результатов не доказывает
отсутствие MOV stores. Новый ограниченный поиск RIP-relative qword MOV / LEA
для одного точного global нашёл три подтверждённые записи и 31 read candidate.
Последние только посчитаны; это не полный анализ всех способов доступа к global.

- `1455ab3c0`: constructor записывает RCX в global и после base initialization
  устанавливает таблицу `149903de8` в начало объекта.
- `1455ac490`: cleanup очищает global после освобождения полей объекта.
- `1455b2ce0`: deleting cleanup также очищает global; при flag bit 0 освобождает
  объект размером `0x1a0`.

У таблицы `149903de8` qword по `+0x48` равен `1455b4d40`. Это связывает
ранее извлечённый incoming receiver `145d81aa0`, который вызывает model virtual
`+0x48`, с конкретной реализацией текущей модели. Полученный wrapper содержит
record pointer; реализация использует record key по `+0x20`, обновляет map модели
по `model+0x30`, затем вызывает `1455f4a80(record, state, progress)` и notification.
Map модели не следует путать с task pointer по `record+0x30`.

`1455f4a80` сначала вызывает `1455fd350`, затем сохраняет state byte в
`record+0x28`. При существующем task pointer по `record+0x30` функция `1455fd350`
сравнивает task qword `+0x20` с progress qword `+0`.
При совпадении вызывает virtual task `+0x10` с progress; переход состояния к 2
и остальные обновления выбирают callbacks `+0x28` / `+0x30`.
При несовпадении возможен callback `+0x38`, старый shared pointer очищается,
factory `1455b8ff0` создаёт замену, а `1455b5450` передаёт контекст владельца.
Операции reference count / cleanup присутствуют в полном экспорте.

Это не доказывает копирование progress index в task `+0x29`: нужен virtual copy
конкретного типа, создаваемого factory. Порядок массива QuestTask / CSV, native
factory, lifecycle callbacks, HUD route, диалоги / skip / equip и серверное
подтверждение действий остаются открытыми. Имена callbacks здесь не приписываются.
Runtime не получает новые разрешённые команды из одной статической связи.

## Воспроизведение

`inspect-quest-model-singleton-11316.py` проверяет полный SHA EXE, границы
инструкций в unwind fragments, точный getter, все инструкции шести exported roots,
constructor store, vtable slot и state store. Проверка
`test_vampir_quest_model_singleton_11316.py` выполняется offline.

Exports: `run-55e835912cda` (3 roots), `run-d9e2c6d1988d` (virtual handler),
`run-dee1f2864d6e` (2 application roots), внутри
`F:/PhoneExit Resources/Vampir/ghidra/request-exports/<полный SHA>/`.
Полные SHA exports включены в проверяемый content-addressed отчёт:
`code-clues/quest-model-singleton-11316/f21498d792785d07a98755c2a2a9616d7b6e2d7161c32ff525a0020118c8a183/manifest.json`.

Первоначальный поиск всех load/store candidates превысил бюджет 32; он не
запускался повторно без изменения. Поиск сужен до writers / address references
и одного известного getter; read candidates только посчитаны.

Следующий шаг: явный unwind root factory `1455b8ff0`, её конкретные task tables
и virtual `+0x10`, затем bounded replay применения progress и lifecycle.
