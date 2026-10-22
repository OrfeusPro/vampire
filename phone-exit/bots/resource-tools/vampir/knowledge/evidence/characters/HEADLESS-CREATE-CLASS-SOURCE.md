# Источник класса и начальной внешности

22 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [ветки создания](HEADLESS-EMPTY-LIST-CREATION-ENTRY.md).
Повторный экспорт Ghidra не требовался: `prepare` нашёл готовые функции.

## Что подтверждено

Таблица owner `0x149ca7190` содержит producer `0x146449dc0` в virtual slot
`+0x48` и getter `0x14644a0c0` в slot `+0x90`. Constructor `0x146442670`
устанавливает эту таблицу. Связь слотов сверяется с байтами текущего EXE.

Getter возвращает raw uint32 из UI `+0x360`, когда global guard разрешает
поиск, lookup возвращает объект и проверка цепочки типов проходит.
В остальных случаях результат равен sentinel `0x1496726a0`, значение которого
в текущем EXE — 0. Ни числовой порядок классов, ни допустимая строка таблицы
класса этим не доказаны: число копируется без проверки его игровой семантики.

Constructor при тех же условиях копирует byte из UI `+0x364` в owner `+0x30`.
Если UI отсутствует или не подходит, поле `+0x30` остаётся прежним: в replay
там сохраняется начальный canary `0xa5`. Его нельзя считать нулевым значением
внешности по умолчанию.

## Проверка

`replay-release-create-class-source.py` выполняет целые constructor и getter
через существующий ограниченный Unicorn harness. Проверены 144 комбинации:
guard 0 / 1, наличие UI, совпадение / несовпадение / выход за границу цепочки
типов, четыре значения класса и три значения начальной внешности.
В 12 комбинациях источник подходит; в остальных getter возвращает sentinel,
а constructor сохраняет byte `+0x30`. Проверены canaries owner, неизменность UI
и отсутствие lookup при запрещающем guard.

Lookup `0x1445d3da0`, singleton типа `0x145c8df30`, метаданные UI, guard и
класс / внешность — явные fixtures. Реальное окно, producer, JSON внешности,
whole packet writer и сетевое создание не выполнялись. Точные bytes object
writer tail `0x144aae8c0` дополнительно сверены статически, без его исполнения.

Команда из `phone-exit/bots`:

```powershell
python -X utf8 -m unittest test_vampir_create_class_source
```

Проверка `release-create-class-source` зарегистрирована для вопроса
`character-creation-entry`; изменение исходника harness или проверяемых экспортов
инвалидирует её кэш. Авторизация и игровые действия отсутствуют.

## Evidence и следующий шаг

- Constructor / getter: comparison `c7552efd2125-98802d550890/run-fd4956a37b3c`,
  `details/run-1dc059f7b039/details.json`, SHA256
  `f510bcdbfb4fb0d3deef03fe3cb3dc681b2a74eb69633531e986554972500303`.
- Native report: `F:/PhoneExit Resources/Vampir/code-clues/release-create-class-source/6d4781e18bc5387a35821b8ce69f83db29c02164c11988f2d0fda9e873c10021/manifest.json`.
- Fixtures, canaries и границы — в report и воспроизводимом инструменте.

Следом связать UI `+0x360` с допустимой записью класса, затем проверить целые
producer, appearance JSON и wire writer / reader. Не подставлять произвольный
класс или внешний вид. Создание отправлять только после принятого Login и
успешного пустого списка персонажей нужного аккаунта и сервера.
