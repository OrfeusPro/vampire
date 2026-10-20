# Windows: продолжение после успешного входа в лобби

20 октября 2026. Проверен полный успешный путь обработчика ответа лобби
с настоящими Windows selector и platform gate. Восемь сценариев завершились
возвратом из обработчика; дополнительных сетевых запросов эта проверка не делает.

## Подтверждённая цепочка

- `LobbyLoginResult_Handler`, `0x14677ec50`, получает result = 0.
- Сбрасывает byte объекта состояния `+0x38`.
- Переносит строки ответа `+0x20` и `+0x30` в игровой wrapper `+0xf0`
  и `+0xe0` соответственно; первая строка также попадает в объект `+0x28`.
- `LobbyPost_ExternalGate`, `0x1445cb650`, вызывает
  `Version_ContextSelector`, `0x1445c77a0`. Настоящий selector возвращает 3
  для этого Windows EXE. Gate возвращает 0: внешняя ветвь требует 1 или 2.
- Вызывает predicate `0x145a3f410`. При нулевом результате вызывает
  `LobbyPost_ServiceState`, `0x145a4b8d0`, с аргументом 0.
- Вызывает продолжение `0x144aaa9c0` на игровом wrapper, затем возвращается.

Восьми сценариям соответствуют две формы enum fixture, два результата
служебного predicate и пустые / непустые строки. Порядок вызовов, обе строки
игрового wrapper, копия первой строки и сброшенный pending byte проверены.

Продолжение подключения и служебный метод перехвачены на входе: их backend
в этих сценариях не исполняется. Значение и назначение служебного состояния
пока не установлены. Нельзя утверждать, что оно не влияет на реальный вход.

## Источники и воспроизведение

Клиент: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-7f47677751ba`: 372 функции, 175 предупреждений.
Manifest SHA256: `312b9622dd1cb27301cbbc745e0e6d635e968f7624ff12f96ffc83f74ee17c70`.
В экспорт добавлены platform gate, служебный метод, два SDK playerStatus parser
и два соседних метода lobby base. Последние имеют предварительные имена
`LobbyContext_SetupA/B`, но оказались методами освобождения объектов;
инициализацию lobby kind они не подтверждают. PlayerStatus parser пока
не связан с необходимым контекстом игрового Login.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-windows-continuation.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_preparation.py
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/lobby-windows-continuation-replay.json`.
SHA256: `1dddb8e4b212c6677a836223b8dbeaebe42945da9ad268067ed7edddd1cf0705`.
Он содержит исходные диапазоны инструкций, SHA инструментов и зависимостей,
искусственные строки и результаты сценариев. Использованы готовые fixtures
из `replay-version-platform-context.py`, без новой реализации reflection.

## Что остаётся неизвестным

Реальный lobby kind, полное состояние SDK / playerStatus и служебного объекта
до Login ещё не воспроизведены. Поле kind = 0 в диагностическом запросе
не менялось. Эти сценарии не доказывают причину `LoginResult 16 / InvalidState`.

Игра не запускалась; подключений и новых аккаунтов не создавалось.
Список / выбор персонажа и позиция по-прежнему требуют успешного игрового Login.
Последняя реальная сессия описана в
[проверке InvalidState](HEADLESS-RESULT-ERROR-16.md).
