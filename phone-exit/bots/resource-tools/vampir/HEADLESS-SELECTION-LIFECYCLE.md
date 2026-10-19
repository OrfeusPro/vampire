# Selection service: события и границы перехода

20 октября 2026. Анализ кода установленного клиента, без запуска игры.

Продолжение: [caller slot90 найден отдельно](HEADLESS-CHARACTER-LIST-CALLER.md).
Ниже сохранены результаты и границы первоначального этапа.

## Источник и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 76 функций, 42 предупреждения сохранены.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-277163f3b3eb`.
Manifest SHA256: `ccb1b9d8c55e6b43ebe50bb98282236775c31abe2c41bcf48c4392789a7522ed`.
Имена SelectionLifecycle — аналитические, не исходные C++ символы.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-selection-lifecycle.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_selection_lifecycle.py
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/selection-lifecycle-replay.json`.
SHA256: `d484dd80588dc77cdd156d79ff38dbb6646447c9d6a2804f50e5da7287aaed5e`.
В нём сохранены инструкции, смещения PE, SHA участков, входы и captures.

## Найденные связи

Primary table `0x1499f11f0`, установленная подтверждённым constructor prefix,
содержит slot08 → `0x14560e7d0`. Декомпиляция этой функции показывает регистрацию
двух callbacks: `0x14561af60` в delegate array getter `0x144aa7510` + `0x18`,
и `0x14561b000` в array getter `0x1454de430` + `0x330`.
Derived delegate tables: `0x1489efc38` и `0x1494f93c0` соответственно.
Регистрация пока прочитана статически; фактические emitters и момент события
после загрузки CharacterSelect_02 не установлены. Название WorldEvent не доказывает
завершение загрузки уровня.

Native исполнение `0x14561b000` на семи raw32 значениях (включая 2 и границы
signed/unsigned) подтверждает последовательность:

1. Записать raw32 в service + `0x40`.
2. Вызвать `0x145619e40(service, raw32)` — explicit capture.
3. Вызвать `0x144a64cc0(service + 8, descriptor, &raw32)` — capture рассылки;
   descriptor содержит `0x141423088`.

Тело `0x145619e40` экспортировано: оно формирует строку, перебирает объекты,
сравнивает строки и меняет service + `0xc8`/`0xd0`. Это статическое наблюдение;
в replay исполняется только вход обработчика, backend диспетчера не исполняется.

`0x14561af60` передаёт в UI helper `0x144a4af10` descriptor с callback
`0x1455f7bb0`. Последний — leaf без unwind range, поэтому проверен как 16 байт
инструкций вместо невалидного Ghidra seed. Native исполнение читает singleton
global `0x14b574a90` и делает tail jump в virtual + `0x38` с raw0.
Цель захвачена синтетической таблицей; реальный virtual38 в этом replay не исполняется.

Actual table slot38 → `0x145dbbb10`: экспорт показывает guard virtual+b0,
затем подготовку state1 с label из virtual+c8. Slot70 → `0x145dc2930` имеет
собственный guard и создаёт другой packet через constructor `0x145842880`;
его ID и назначение здесь не установлены. Slot78 → `0x145dbcbe0` также экспортирован.
Эти ветви ещё не дают доказанного вызова slot90/CharacterListRead.

## Следующее действие и ограничения

Проследить emitter двух зарегистрированных callbacks и загрузку cooked level,
проверить виртуальные обработчики и продолжение `0x14561a8d0` из slot78.
Не подменять доказанный WaitingEndNotify → requestB предположением о requestA.
Открыты caller slot90, ответ102, реальная сессия и серверные условия событий.
Сетевой обмен, профиль, память работающей игры и Android не использовались.

Связанные результаты: [World.Id2 → LevelPath](HEADLESS-WORLD-STATE-LABEL.md),
[service/table и packet109](HEADLESS-SELECTION-SERVICE.md),
[state preparation](HEADLESS-SELECTION-STATE-TRANSITION.md),
[WaitingEndNotify → requestB](HEADLESS-WAITING-END-CHARACTER-REQUEST.md).
