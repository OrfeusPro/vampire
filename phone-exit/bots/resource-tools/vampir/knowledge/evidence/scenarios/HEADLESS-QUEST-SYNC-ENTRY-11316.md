# Входящий источник списка заданий 1.13.16

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [живого наблюдения](HEADLESS-LIVE-TUTORIAL-11316.md).
Пользователь просит показывать полученные задания в правой панели прототипа.

## Реальное наблюдение и существующее представление

Та же Itel-сессия остаётся connected: на uptime 1592 секунды heartbeat 309 / 309.
По одному разу посчитаны ID 1827 / 1840 / 1854. Тела этих ранних пакетов не
сохранялись; получить их из счётчика нельзя. Текущий owner публикует vitals /
stats / tutorial, но не coverage.quests. Перезапуска, Stop, запроса списка и
игровых команд в этой проверке нет.

Правая панель уже использует общий адаптер: coverage.quests=received и
quests[].id / title. Кнопка открывает карточку, действие следования отключено.
Неизвестный список отличается от пустого. До подключения подтверждённого decoder
и модели панель продолжает показывать отсутствие полученных данных, а не
исторический список / каталог всех квестов как текущие задания персонажа.
[Контракт UI](../../../../../vampir/UI-PROTOTYPE-LIVE.md).

Прежний ID 1802 decoder относится к другому SHA и имеет
[исправление вложенного объекта](HEADLESS-QUEST-LIST-CORRECTION.md).
Живые ответы того запроса имели code 100, успешного списка ими не доказано.
Нельзя переносить прежний суффикс или повторять reset-field запрос ради панели.

## Проверенные текущие связи

inspect-initial-quest-notifications-11316.py проверяет immutable EXE по полному
SHA, использует Capstone 5.0.6, три явных ID getter MOV EAX,imm / RET,
восемь code slots, полный name method с единственным Pkt-литералом и ссылки LEA.
Для ID 1854 отдельно закреплены фактический constructor, его вызов вложенного
constructor и полный leaf до RET. Имена не заменяют проверку wire / handler.

| ID | Имя клиента | Таблица | Reader slot +0x20 |
| --- | --- | --- | --- |
| 1827 | PktQuestActListReadResult | 149964948 | 14582b0e0 |
| 1840 | PktQuestLimitTimeNotify | 149964fb0 | 14582b6d0 |
| 1854 | PktQuestSyncNotify | 1499654c0 | 1456b70d0 |

1854: constructor 145828a10 устанавливает packet vptr и вызывает 1457a2a70
для packet+0x10. Вложенный constructor устанавливает table 149948c10 и обнуляет
+0x08 / +0x10 / +0x18. Его reader — 1457a66b0. Общий outer reader 1456b70d0
диспетчеризует вложенный объект, как в проверенном
[ID 9905](HEADLESS-TUTORIAL-UPDATE-11316.md), но vptr вложенных данных другой.
Это не повод декодировать 1854 форматом tutorial или ошибочным suffix ID 1802.

Whole Ghidra exports constructor / nested reader завершены, block coverage
полная; инструкции сверены с EXE. Reader очищает прежнюю коллекцию, передаёт
descriptor 149949cf8 в archive slot +0x18, затем читает uint64 через slot +0x50
и сохраняет его в nested+0x18. Descriptor содержит resize 1457a9aa0 и callback
1457a8b00. Static callback использует table 149948bc8, reader 1457a67b0;
текущие guards / layout проверяются отдельно до portable decoder.

Для 1827 / 1840 metadata и ссылки сохраняются кандидатами: leaf sites не
выдаются за начала unwind functions. Wire-поля, успешный результат 1827,
смысл таймера и применение handler пока не установлены.

## Материалы и следующий шаг

Отчёт в библиотеке ресурсов, полный SHA равен имени каталога:
`code-clues/initial-quest-notifications-11316/aa4e1ee1a604236a4cb6905d9286aed568603bd51919176a940de946ccd4f084/manifest.json`.
Ghidra export:
`ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-b6b0576b96ef/details.json`.
SHA export записан в результате исследования. Воспроизведение из корня:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-initial-quest-notifications-11316.py
```

Исходящие действия и native replay в этой проверке не выполнялись. Старые
quest checks требуют порта на текущий SHA; metadata не разрешают runtime decoder.
Далее нужны целый 1854 reader с настоящим constructor, группы / Quest / Progress,
callbacks / copies / cleanup, bounded portable decoder и изолированная модель.
После этого — поступившие сообщения в правую панель через общий адаптер.
Существующую игровую сессию ради получения начального списка не разрывать.
