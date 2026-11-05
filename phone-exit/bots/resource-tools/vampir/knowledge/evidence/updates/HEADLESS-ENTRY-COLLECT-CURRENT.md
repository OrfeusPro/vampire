# Готовые экспорты CharacterList и clock / lobby / world

Target EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Последняя проверенная база этих пакетов — 1.13.18:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Машинная квитанция](AUTO-ENTRY-COLLECT-CURRENT.json) сохраняет source-checked
планы, успешные collections и диагностические границы.

## CharacterList

Сохранённый discovery сопоставил 39 из 40 whole roots. Resize выбран отдельной
проверкой точной vector table `+8` и всех 18 инструкций пары; общий discovery
не повторялся. Из 40 roots 18 уже имели готовые current exports.

Первый collect 22 отсутствующих roots остановился на строгой проверке границ.
Native `0x1456d2280` содержит два E9 tail: `0x1456d19e0` и `0x1456c72a0`.
Они добавлены в следующий явный request. Пакет 24 roots собран успешно:
`run-acc24c5196b9`. Остальные 18 готовых exports сохранены.
Строгие unwind / whole instruction проверки не отключались.

Генератор шести contexts был начат субагентом, но dedicated harness / runner
не был завершён до лимита. Незавершённый исходник сохранён с полным SHA
в библиотеке `knowledge/entry-current-wip/`; он не зарегистрирован и не исполняется.
Дальше нужны текущие source-bound сценарии WaitingEnd / CharacterList,
включая проверку leaves, таблиц и регистрации. Исторические матрицы не повторялись.

## Clock / Ping / ограниченный world

Сохранённый поиск сопоставил 23 из 24 whole roots и нашёл изменённый lobby
VersionResult handler `0x1467aeb30`: 47 инструкций вместо прежних 26.
После прежнего clock обновления он использует дополнительные поля пакета
`+0x40`, `+0x50`, `+0x54` и новые metadata calls.

Source-linked ID 2 table `0x1499438e0` указывает на reader `0x14574f5d0`.
У него 60 инструкций вместо 43: после прежнего префикса добавлены строковый
helper и два u32, с проверкой результата каждого чтения. Constructor
`0x145749a50` и поле FString также найдены по source bytes.
Точный wire contract и новые ветви ещё требуют ограниченного native исполнения.
Существующий lobby decoder принимает ровно 23 байта; его нужно обновить по
новому доказанному layout перед живым входом.

Первый collect остановился на E9 к leaf `0x144ab11e0`. Точная модель
MOV / XOR / E9 проверяет 11 исходных байт и конечную цель `0x144ab2db0`.
Она соответствует прежнему source-specific peer tail; рекурсивного поиска
или разрешения произвольных функций модель не добавляет.
Модель проверена Python тестом и фактическим Ghidra collect.

Следующий пакет 27 roots, включая lobby constructor / reader / string helper
и явный manager tail, собран успешно: `run-4496e2332dcf`.
Созданы готовые материалы для последующего текущего исполнения clock / Ping /
bounded world. Полный engine/world-session и online admission не подтверждены.

Оба успешных collect использовали существующий source-specific Ghidra project.
Два первоначальных отказа и их логи сохранены; неизменные failed requests
не запускались повторно. Новые requests фиксируют конкретную причину и inputs.
Игровые команды и сетевой вход не выполнялись.
