# NkTileView: арифметика размещения и cached-count gate

25 октября 2026. EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [передачи блока Refresh](NKTILEVIEW-REFRESH-11316.md).
Нет процесса игры, профилей или сетевых команд; только bounded Unicorn.

Запрос `d2790619b7ff1bbc1e77cd74c66f4a837c1df099466bf2e950f81c96111ca572`
подготовлен для 144626640 с конкретным неизвестным: применение полей
receiver +0x14b8 / +0x14c0. Он повторно использует завершённый Ghidra export
`ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-b9b6aa537efc/details.json`.
Нового экспорта не потребовалось. Ghidra-псевдокод сверялся с инструкциями;
названия переменных decompiler не считаются source property names.

## Поля и подтверждённые типы чтения

16-байтовый блок, копируемый Refresh, участвует в численной арифметике
размещения. Каждый компонент читается MOVSD как double и преобразуется
CVTPD2PS в float32. Точные имена, единицы и связь с cooked свойствами неизвестны.

|Выбор byte +0x14c8|Доступный размер float32|Компонент блока double|Следующий компонент double|Граничное значение double|
|---|---|---|---|---|
|0|+0x12d0|+0x14c0|+0x14d8|+0x14e8|
|ненулевой|+0x12cc|+0x14b8|+0x14d0|+0x14e0|

Флаг выбирает ось вычисления, но его enum / labels horizontal / vertical
не восстановлены. Следующий и граничный компоненты участвуют соответственно
в сумме знаменателя и вычитании удвоенного значения; это не доказанные имена
Spacing / Padding конкретного UProperty.

На положительных целочисленных fixtures результат совпал с количеством k,
для которого `k * size + (k - 1) * gap <= view - 2 * inset`, с минимумом 1.
Это ограниченный geometry oracle, не полная переносимая реализация float32.
Native использует float32 сложение / вычитание / деление, CVTTSS2SI и fmodf.
Переполнение, NaN / Inf, отрицательные размеры и нулевые знаменатели не покрыты.

Импорт 1487f5ba3 проверен через PE import descriptor / IAT:
`api-ms-win-crt-math-l1-1-0.dll!fmodf`. В replay это явный math fixture,
принимающий float32 аргументы XMM0 / XMM1 и возвращающий округлённый float32
результат host math.fmod. Реальная CRT не исполняется.

## Условия пересчёта и пределы экономии

При DL = 0 совпадение вычисленного количества с dword +0x14cc допускает
пропуск дальнейшего пересчёта. DL != 0 обходит это условие. Ранее проверенный
Refresh вызывает этот путь с DL = 0, затем DL = 1: cached gate нельзя считать
доказательством отсутствия повторной работы при вызове Refresh целиком.

В ветви без пересчёта при byte +0x14f7 = 0 сохраняется вычисленное количество;
при ненулевом byte кеш +0x14cc берётся из dword +0x11d8. Оба случая проверены.
Статически виден также ранний выход при byte +0x14f8 = 1; его назначение и
runtime producer не восстановлены, в данном replay этот флаг равен нулю.

## Проверка

`replay-nktileview-packing.py` сохраняет полные native fragments и import
evidence. 128 комбинаций: восемь наборов размеров / gap / inset, два значения
выбора оси, force 0 / 1, совпадающий / другой cache и override 0 / 1.
Граничные fixtures включают точное размещение и доступный размер меньше ячейки.

32 cached exits исполнены полностью до возврата, проверены стек и все байты
объекта кроме предусмотренной записи cache. В 96 случаях исполнен только
prefix: остановка до входа в item-count provider 14462f090, без исполнения
перечисления, построения элементов, virtual calls и downstream layout.
Сравнение результата сделано с независимым ограниченным geometry oracle.
Stack-cookie validation — no-op fixture. Это не весь native helper replay.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nktileview-packing.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/d2790619b7ff1bbc1e77cd74c66f4a837c1df099466bf2e950f81c96111ca572/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/nktileview-packing-replay-d00a-next.json'
```

Проверенный отчёт: `code-clues/nktileview-packing-replay-d00a-02.json` вне Git.
Первый пробный отчёт с четырьмя наборами сохранён отдельно. Два offline теста
проверяют предыдущие 24 wrapper случая и новые 128 packing случаев; check
`ui-nktileview-refresh-current` дополнен зависимостями и остаётся source-bound.

Вывод для сборщика: блок участвует в layout arithmetic, не является доказанным
массивом записей эффектов. Перенос в renderer пока закрыт: нужны source
properties / единицы, producer, actual orientation / DPI и правила применения.
Кеширование / dirty updates прототипа и измерение 50 окон проверяются отдельно.
