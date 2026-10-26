# Поиск массива задач вместе с проекцией прогресса

Источник 1.13.16 SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Root `145b4be70` получен явным отдельным collect, экспорт
`run-6978cfe0cd9d/details.json`, SHA256
`604ae3be1bba4bc7c87a9183f94017bdade41ebae0fbd632ebc5244944cc3cbe`.
Полные 201 байт, все блоки и инструкции сверены с текущим EXE.

Функция получает manager через `145b547a0`, вызывает hash dispatch из
`14b0c2b00` с адресом 8-байтового quest key / длиной 8 / seed 0.
При size `manager+0x70` == free count `+0x9c` возвращается пустой wrapper.
Иначе используются inline buckets `+0xa0` либо external pointer `+0xa8`,
bucket count `+0xb0`, nodes pointer `+0x68`, stride 32, next index `node+0x18`.
Поиск сравнивает qword ключ, обходит коллизии до -1.
Найденный wrapper получает **адрес value `node+8`**, а не копию массива.
Progress helper `145de4610` затем трактует этот value как TArray header:
data pointer / count. Это уточняет проверенную связь ключа и массива задач.

`replay-quest-progress-11316.py` сохраняет прежний standalone режим и
добавляет `run(native_lookup=True)`. В новом режиме исполняются обе целые
функции и настоящий pointer getter; lookup больше не Python fixture.
Manager getter, hash callback, task virtual kind и diagnostic lifecycle — fixtures.
Native hash algorithm / реальная загрузка manager здесь не доказываются.

324 сценария покрывают ключи 0 / 110120 / UINT64_MAX, индексы
0 / 1 / 2 / 127 / 128 / 255, count 0 / 2 / 128, отсутствующий key,
null task / найденный task. Вариант heap diagnostics одновременно выбирает
external buckets, второй вариант — inline: это две совместные конфигурации,
а не полный независимый Cartesian product этих двух свойств.
Перед совпавшим узлом размещена настоящая коллизия; missing проходит цепочку.
Проверены оба вида empty (size 0 и size == free count 2), immutable manager /
nodes / buckets / task / progress и guards, точные поля результата, порядок
hash / kind / диагностики. Отрицательные slots выделены явно, как в прежней
[проверке progress](HEADLESS-QUEST-PROGRESS-11316.md); runtime их не принимает.

Тест `test_vampir_quest_task_lookup_11316.py` прошёл, прежний progress тест
тоже прошёл. Новый артефакт:
`code-clues/quest-task-lookup-11316/18d260d28833d156d2fe25d2bd696141d6c4a26a289f98f228737bdf44177732/manifest.json`.
Контекст `knowledge/native-contexts/quest-task-lookup-11316.json` закрепляет
оба exports и прямой getter leaf. Реальная игровая сессия не использовалась.

Открыты происхождение / порядок записей manager, привязка к current QuestTask
CSV, применение результата в selected state модели, HUD callbacks и команды.
Даже с raw08 0 нельзя пока считать строку 110120005 активной.
Следующий явный root — `145b547a0` / caller применения результата.

Запрос пользователя расширен: клик должен запускать задачу, квестовые реплики
должны выбираться, нужна кнопка пропуска и действия обучения, включая экипировку.
В уже запущенном owner API есть только Stop / trace / observational analysis;
канала игровых действий в нём нет. Analysis не превращать в отправку команд,
не внедрять код в процесс и не разрывать текущую сессию для неподготовленной замены.
Отдельно нужны подтверждённые contracts диалогов / skip / inventory и action
adapter с owner-side очередью / проверкой session / отсутствием слепого retry.
