# Vampir: периодический Ping и короткая живая сессия

22 октября 2026. Windows EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [живого ID 206](../characters/HEADLESS-LIVE-WORLD-FINISH.md),
[producer](../updates/HEADLESS-RELEASE-BOOTSTRAP.md#исполнение-целого-producer)
и [источника часов](../updates/HEADLESS-RELEASE-CLOCK.md).

## Текущий ID 17

`inspect-release-ping-result.py` ищет точный literal `PktPingResult` в .rdata
проверенного snapshot. RIP candidates подтверждаются инструкциями целых unwind
диапазонов; короткие LEA / mov / xor / ret без unwind отмечаются как кандидаты.
Прежние адреса и соседние функции автоматически не переносятся.

Найдена table `0x1499289b0`, getter `0x1456e5f70` возвращает 17.
Constructor `0x1456d8b60` устанавливает эту table; reader slot +0x20 —
`0x1456dc6e0`. Короткий constructor исполняется по проверенным leaf bytes;
collect оставляет его в очереди из-за отсутствия unwind root.

В регистрации `0x1467b62f0` call `0x1467b65ef` создаёт packet, а
`0x1467b6602` передаёт его вместе с handler table `0x149dc8638` в
`0x1467ccd50`. Handler slot +0x10 — `0x14679da80`, он вызывает
`0x1467d09b0`. Выгрузка всей factory остаётся неполной; эта конкретная
последовательность инструкций доступна. Целиком factory не исполнялась.

`replay-release-ping-result.py` исполняет actual constructor, getter, reader,
handler и receiver. Тело ID 17 — uint32 / uint64, 12 байт. В этой handler-ветви
значения обоих wire fields не влияют на сброс счётчика: wrapper+0x16c становится
нулём. Receiver берёт timestamp отправки из wrapper+0x178, рассчитывает elapsed
по локальному clock cache, затем сбрасывает tracking index +0x168. Source literal
`0x148afeab0` равен **−0.0001**; с последующим отрицанием получается N − sent,
а не сумма двух времён. Wire uint64 не объявляется echo для корреляции ответа.

Handler отдельно проверяет bit 10 значения config+8 и вызывает recovery.
Context / config getters, содержимое clock cache и recovery call — fixtures.
36 случаев проверяют raw result 0 / 16 / `0xffffffff`, raw value 0 / max,
config flags 0 / 512 / 1024 и исходный counter 0 / 6. Во всех случаях counter
сброшен; recovery вызван только при bit 10. 12 коротких префиксов reader отклоняет.
Tracking index проверен только с исходным значением 0, как для одного timing slot.

## Runtime

`PeriodicPing` использует текущий `LobbyPingClock`, N / N − last и порог
**D > 5000**. Начальный Ping уже должен находиться в очереди владельца.
Состояние last / counter меняется только после успешной постановки кадра;
переполнение / закрытая очередь не считаются отправкой. Точный ID 17 сбрасывает
counter. При шести неотвеченных Ping следующая отправка не выполняется:
владелец закрывает соединение с `ping_recovery_required`. Внутреннее engine
recovery и диагностический config override не эмулируются; автоматического
восстановления сокета и повторения игровых действий нет.

`GameConnection` обрабатывает ID 17 и ставит периодический Ping после ID 206
только при явном включении. Runner поддерживает `--observe-world-seconds`
от 0 до 300 вместе с `--read-world-finish` / `--read-world-start`, чтением списка
и выбором индекса. Значение 0 сохраняет прежнюю остановку сразу после ID 206.
Наблюдение имеет общий monotonic deadline, byte / packet / queue budgets.
Полный clock resync и отдельный watchdog для постоянной сессии ещё не сделаны.

Проверены 5 тестов scheduler, 25 socketpair-тестов probe, 8 тестов параметров
runner, 9 тестов соединения, 3 native теста receiver и 3 прежних native теста
producer. Проверены gate 5000 / 5001, N / delta, current key / sequence,
очередь без ложного commit, отсутствие седьмого неотвеченного Ping, reset по ID 17,
readiness, обратный ход UTC и close. Socketpair не доказывает внешнюю сеть.

## Живое наблюдение

Новая проверка через JP / TECNO TECNO KJ5n, при закрытой игре: Login 0,
список / выбор 0 и ID 206 code 0. Затем соединение оставалось открытым заданные
20 секунд: четыре периодических Ping, пять ID 17 с учётом раннего Ping.
Статус `world_observation_complete`, ошибок нет, позиция получена.
Send 1160 / receive 39811 байт, 113 сопутствующих пакетов, byte counts complete.
Сохраняется только ограниченная сводка ID / количества; raw bodies и координаты
в публичный отчёт не записаны. Runner закрыл сокет, маршрут завершился с code 0.

Это короткая проверка heartbeat. `game_session_ready=false` сохранено:
длительная работа, движение, сущности / квесты, разрыв / восстановление и карта
ещё не подтверждены. Повтор того же входа без следующего проверяемого шага не нужен.

## Материалы

Comparison: `F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| details/run-f9f61ab4bfa9/details.json | b2619413e0f269662614496342b1cb3fe6e85bb8350f43a937b16e576cc81177 |
| details/run-b3ab85ff66e0/details.json | 94c22d53d4a2c1063e6f0d0879884c509bffbdb2da709f21964c09e456d052d3 |
| ping-result-replay/0c6f733b9183e703b7902189e58e3726e5c813baa998b0ea2a8306a69e34a28e/manifest.json | 0c6f733b9183e703b7902189e58e3726e5c813baa998b0ea2a8306a69e34a28e |

Другие immutable материалы относительно библиотеки:

- `code-clues/release-ping-result-discovery/5b65b0f3a187f895074fafde00de6e2e4a2c68f1d816da79f3f589d4291da01f/manifest.json`;
- `live-login-observations/40e24ea8641f26a0eeeeeaf6dea9356469e4112163be4c743c7118146187a5e7/manifest.json`.

Имена каталогов этих snapshot совпадают с полными SHA256 manifest.
