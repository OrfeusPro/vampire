# NkTileView.Refresh: передача блока и границы обновления

25 октября 2026. EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [таблицы native функций](NKTILEVIEW-CLASS-FUNCTIONS-11316.md).
Только чтение файла и ограниченное исполнение инструкций в Unicorn;
процесс игры, сервер, настоящие профили и устройства не затрагиваются.

## Явные границы исследования

Вопрос `ui-nktileview-property-schema`. Первый запрос
`6263568079dba9f77699077fe2b08c0d859f8d6106a885277277db6803c6ba15`
на 144a8f220 остановлен при Ghidra tail merge за пределами unwind диапазона.
Второй `5e61879f8de0a314be9a63dd1ae03b6e5d4e6db3464f2b8de136df59ec4758a3`
добавил callee 144628e30 и цель JMP 144626640, но collector отклонил callee:
у него нет самостоятельной unwind-записи. Неудачные запросы не повторялись.

Финальный запрос `0ec131ec0ce652a872107a29696e40576da82a9dcf9fdea861328c7910ed549f`
задаёт только wrapper 144a8f220 и tail target 144626640. Они экспортированы
с обычным source-bound CALL_RETURN моделированием хвостового перехода.
Ghidra: `F:/PhoneExit Resources/Vampir/ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-b9b6aa537efc/`.
Псевдокод wrapper согласован с целыми инструкциями; helper экспортирован,
но его полная семантика не разобрана и он не исполняется в replay.

Leaf callee ограничен точными 24 байтами 144628e30..144628e48:
`0f100233d2c681f9140000010f1181b8140000e9f8d7ffff`.
Это четыре прямолинейные инструкции и хвостовой JMP 144626640; далее восемь
байтов INT3 padding. Собственной unwind-границы или отдельного завершённого
Ghidra экспорта leaf этим не заявляется.

## Подтверждённый поток данных

Wrapper сначала обновляет qword frame (RDX) +0x20 по правилу
`value + (value != 0)` с переполнением uint64. Это не счётчик бафов и не
доказанный курсор конкретного формата: фиксируется только операция над полем.
Источник RCX сохраняется как owner.

При owner +0x408 = 0 wrapper возвращается, не вызывая callee / helper.
При ненулевом значении:

1. В RCX передаётся указатель owner +0x408, в RDX — адрес owner +0x430.
2. Leaf читает ровно 16 байтов MOVUPS, копирует их в receiver +0x14b8,
   устанавливает byte receiver +0x14f9 = 1 и вызывает helper с DL = 0.
3. Wrapper повторно читает owner +0x408 и хвостовым вызовом передаёт helper
   DL = 1. Второй вызов не защищён повторным null-check.

Это передача блока, не доказанный массив данных, список иконок или размеры
строк. Тип / единицы / reflected имена полей неизвестны. Повторное чтение
указателя не доказывает, что engine сохраняет его ненулевым при reentrancy.
Регистрационное имя Refresh не подтверждает кнопку или caller строки бафов.

## Bounded native проверка

`replay-nktileview-refresh.py` исполняет целый wrapper и точный leaf; общий
144626640 заменён no-op return fixture с записью аргументов. Не исполняются
отрисовка, layout, allocation, callback scheduling или внешний engine state.
Запрещено исполнение вне двух проверенных диапазонов и fixture entry.

24 случая: receiver отсутствует / присутствует; frame +0x20 равен 0, 1,
0x1000 или uint64 max; блок нулевой, байты 00..0f или ff. Проверены полная
сохранность owner, все байты frame кроме оговорённого поля, receiver 0x1600
байтов кроме копии / флага, порядок двух флагов 0 → 1, возврат и стек.
Это данные искусственных fixtures; mutation / reentrancy из helper не моделируются.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nktileview-refresh.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/0ec131ec0ce652a872107a29696e40576da82a9dcf9fdea861328c7910ed549f/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/nktileview-refresh-replay-d00a-next.json'
```

Capstone 5.0.6 и Unicorn 2.1.4 закреплены; другой SHA / неизвестный код
отклоняются. Отчёт `code-clues/nktileview-refresh-replay-d00a-01.json` вне Git.
Одна зарегистрированная offline проверка `ui-nktileview-refresh-current`
проверяет 24 native случая и привязана к SHA и Ghidra details.

Далее: определить источник owner +0x430 и смысл receiver +0x14b8 / +0x14f9,
политику helper 144626640, reentrancy и путь caller → Refresh. Два вызова
helper не доказывают ни два кадра, ни их объединение, ни отсутствие лишнего
обновления. Правила экономии для 50 окон из этого результата не выводятся.
Reflection schema, entry factory и совместимость старых cooked пакетов открыты.
