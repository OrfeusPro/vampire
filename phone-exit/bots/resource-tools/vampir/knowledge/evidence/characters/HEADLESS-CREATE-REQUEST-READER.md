# Целое чтение запроса создания персонажа

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [ветки создания](HEADLESS-EMPTY-LIST-CREATION-ENTRY.md) и
[источника класса](HEADLESS-CREATE-CLASS-SOURCE.md). Готовые экспорты найдены
через `prepare`; Ghidra повторно не запускалась.

## Подтверждённая структура

Целый constructor ID 103 `0x1456d8120` устанавливает packet table
`0x14992a3a8`, вложенный CreateData table `0x14992a360` по packet `+0x10`
и appearance table `0x149921fb0` по packet `+0x30`.
Leaf constructor `0x145784790` имеет 66 байт до RET; его точные инструкции
и байты включены в native report. Таблицы и reader slots сверены с текущим EXE.
Appearance использует тот же reader, который уже проверялся в списке персонажей.

Чтение выполняется целиком: packet reader `0x1456b83a0` → CreateData reader
`0x145789090` → appearance reader `0x145788d00`, с native строками и callbacks
элементов массива. Для проверенных тел порядок такой; transport header сюда
не входит:

| Поле | Чтение |
| --- | --- |
| Числовой параметр класса | uint32 LE без проверки допустимости класса |
| Имя | uint16 длины UTF-8 в байтах, затем строка |
| Внешность | 10 байт; первый ограничивается сверху значением 2 |
| Строка настроек внешности | тот же формат строки |
| Два дополнительных поля | bool и byte |
| Элементы внешности | uint16 количества; каждый: uint32, byte с clamp 45, uint16 |

Произвольные uint32 в тесте показывают отсутствие проверки в reader. Они не
являются найденными ID классов. Строка `{"x":1}` — синтетическое содержимое;
это не допустимая схема JSON настроек игрового персонажа.

## Проверка и границы

`replay-release-character-create-reader.py` выполнил 36 полных тел: три числа
класса, три имени, две строки внешности, пустые / непустые массивы. Проверены
Unicode, clamp значений 255, bool 255, два элемента массива и canaries вокруг
пакета размером `0x70`. Все 1398 коротких префиксов отклонены; курсор не выходит
за доступный вход. Native allocation / storage / cleanup и input buffer —
явные ограниченные fixtures существующего harness. Строки и массивы остаются
в пределах этих fixtures; произвольные размеры этой проверкой не покрыты.

Команда из `phone-exit/bots`:

```powershell
python -X utf8 -m unittest test_vampir_character_create_reader
```

Проверка `release-character-create-reader` подключена к вопросу
`character-creation-entry` и зависит от исходников harness и экспортов.
Сеть, авторизация, игровой процесс и создание аккаунтов не используются.

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-character-create-reader/b65597845269b31452ff35fcfc91d63ace45eced2fe46359389412ea5e3f391c/manifest.json`.
SHA256 совпадает с именем каталога. Экспорты — comparison
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details
`run-dbbbcb857839`, `run-33b73b3d42b9`, `run-100be368d878`.

Writer, producer, генерация JSON, допустимый Carnage class ID, серверная
политика имён и ответ ID 104 остаются отдельными проверками. Готовый reader
не разрешает отправку синтетического тела серверу. Следом проверить whole
writer и связать класс / внешность с данными UI, затем результат создания.
