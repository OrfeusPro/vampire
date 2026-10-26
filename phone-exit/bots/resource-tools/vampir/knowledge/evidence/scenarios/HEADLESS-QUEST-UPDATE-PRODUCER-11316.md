# Текущие параметры отправки QuestUpdate

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [исторического wire codec](HEADLESS-QUEST-UPDATE-WIRE.md).
Пользователь просит запускать выполнение нажатием на квест в правой панели.
В этом этапе игровых команд, движения и входа в аккаунт не выполнялось.

## Привязка текущего пакета

Current PktQuestUpdate: ID 1810 / getter 145834490, table 149965670,
constructor entry 145828b00, writer 145837030, mirror reader 14582bc60.
Whole Ghidra export writer / reader и двух явных constructor callers завершён:
run-22845de261d6 под текущим SHA. Блоки покрыты полностью; bytes сверены с EXE.
Старый codec другого SHA автоматически не разрешён в runtime.

Найденные проверенные прямые E8 callers constructor:
145d6fce6 в root 145d6f9b0 и 145d8538d в root 145d85360.
Первый читает именованные параметры и имеет несколько ветвей запросов;
он не объявляется обработчиком клика игрового HUD только по соседству кода.

## Поля именованного запроса

145d6f9b0 получает значения по точным UTF-16LE ключам. Native stack packet
начинается с RBP+0x07. Отсюда подтверждена связь входных имён с полями объекта:

| Имя | Literal VA | Поле packet | Инструкция store |
| --- | --- | --- | --- |
| QuestInfoId | 1499038d8 | +0x30 | 145d6fd4b, RDI |
| QuestTaskIndex | 149903ee8 | +0x38 | 145d6fd4f, R14B |
| TargetId | 149903f08 | +0x28 | 145d6fd60, RAX |

Getter вызовы и перенос регистров в export прослежены. Это названия входных
параметров конкретного producer, не доказательство, что raw08 входящего
PktQuest совпадает с Quest.Id или что выбранная запись уже активна.
Вектор в этой ветви копируется из runtime объекта, а при его отсутствии —
из глобального значения. Нули вместо текущего вектора автоматически не задаются.

## Отправка по текущей модели

145d85360 сохраняет второй аргумент и ищет его через 1455bbcb0 в объекте,
полученном от 1455be4b0. Нулевой lookup завершает функцию без отправки.
При успехе создаётся ID 1810, копируются три qword от 145517d40 в packet+0x10,
сохранённый ключ — в +0x30. 1455e7510 получает найденный объект и возвращает
byte через object+0x30 → pointer+0x29, либо FF при null pointer; этот byte
попадает в packet+0x38. Затем virtual +0x38 сетевого объекта получает пакет.

1455bbcb0 — leaf без unwind с hash lookup по полному 64-битному ключу,
коллизиями и возвращаемым указателем значения. 1455e7510 также leaf без unwind:
17 байт включают обе ветви и оба RET. Эти входы не выдаются за unwind roots.
Отсутствие прямых E8 callers 145d85360 не означает неиспользуемость:
найден его qword pointer в 149a3cee8. Граница класса / slot и путь игрового
делегата по этой записи ещё не доказаны.

## Воспроизводимая проверка и границы

inspect-quest-update-producer-11316.py сверяет полный SHA EXE, законченный
Ghidra export, инструкции трёх roots с EXE, точные property literals, stores,
getter / state leaf и packet slots. Успешный отчёт:
`code-clues/quest-update-producer-11316/00a73e6b2b851616bb2d495d26da43fa582369c66cdbb5f7b7180023c77ce737/manifest.json`.
Полный SHA manifest равен имени каталога. Отчёт хранит export SHA и точные bytes.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-quest-update-producer-11316.py
```

Это static proof. Whole native writer / producer, engine state / position,
UI delegate, маршрут, движение, серверное принятие и продвижение задания здесь
не проверены. Сам вызов QuestUpdate не доказан как универсальный запуск
автопрохождения. Текущий AutoStart candidate имеет ID 1806; его имя не заменяет
проверку и не переносится на официальный эталон, где такого запроса не было.

Следующий шаг — связать current модель / полученный Quest с именованным ID и
TaskIndex, проверить caller / delegate вокруг table pointer 149a3cee8 и локальный
route executor. Затем current wire / producer native checks и действие выбранной
сессии с подтверждением результата. Произвольный индекс или повтор пакета
официального capture не использовать для запуска персонажа.
