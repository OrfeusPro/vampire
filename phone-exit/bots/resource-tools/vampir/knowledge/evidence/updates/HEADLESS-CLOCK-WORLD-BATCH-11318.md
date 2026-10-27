# Clock / Ping / bounded world 1.13.18

Источник EXE:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Историческая база:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Пакет offline; авторизация и игровые сетевые команды не выполнялись.

Фиксированная группа исторических clock/world roots сопоставлена по целым
инструкциям, local control flow, фактическим calls / RIP references. 23 roots
разрешены; два неиспользуемых helper-а с одинаковым кодом оставлены unknown.
Отдельно найден и экспортирован whole Ping handler `14679c920`, связанный с
packet table, ID17 constructor / getter и окном регистрации в явном owner.
Clock и world replay — обычные сгенерированные Python-файлы; runtime AST нет.

Current exports в библиотеке `F:/PhoneExit Resources/Vampir/ghidra/request-exports/`
под полным SHA источника:

- `run-5ada05662267/details.json` — 23 roots.
- `run-6f93462ee19c/details.json` — whole handler ID17, 19 инструкций;
  диапазон не включает recovery internals.

Первый handler export `run-c6fb3c8019b9` отклонён из-за выхода decompiler blocks
за unwind ranges. Следующий request с `144ab13f0` отклонён до JVM: это не
unwind root. Actual bytes проверены отдельно: `488b491033d2e9c51b0000`, ровно
11 байт MOV / XOR / E9 к `144ab2fc0`. Для этого единственного адреса и SHA
добавлена строгая модель leaf в Python / Java collector. Она не разрешает
произвольные jumps, не обходит callee рекурсивно и не увеличивает budgets.
Старый SDK MOV / RET leaf сохранён. 14 collector tests прошли, Java скомпилирован;
последующий настоящий Ghidra export подтвердил границы и CALL_RETURN caller.
Неудачные попытки сохранены и не засчитаны как доказательства.

`run-clock-world-batch-11318.py` объединяет четыре bounded native replay:

- Clock 24 и Lobby 10: UTC adapter, calendar, signed minute offset, refresh / tick.
- Producer ID16: 36 ветвей readiness / threshold / outstanding / recovery.
- Bounded world IO: 201 сценарий writers ID109/203, prefix ID202, readers ID204/17
  и receiver Ping. Opaque suffix / nested historical variants остаются ограничением.
- Ping result: 36 полных случаев actual native input archive → reader → whole
  handler → receiver; отдельно 12 коротких входов не доходят до handler.

Итого 307 полных сценариев и 12 short inputs. Ненулевой result code сам по себе
не блокирует reset счётчика Ping; config bit1024 направляет в recovery boundary.
Регистрация проверена статически; whole factory execution не утверждается.
OS time / month / local cache, engine storage, send и recovery internals — fixtures.

Общий report:
`F:/PhoneExit Resources/Vampir/knowledge/clock-world-batch-verified-11318/df03901537712adcd8126df3e22c6a4b9f799f197277d216238ebb9ea1aceea4/manifest.json`.
Кэш связан с полным EXE, exports, кодом, контекстами, Python и native runtime;
component reports сверяются по SHA и содержимому. Owner lock исключает повторный
параллельный build. Изменённые inputs и неполные / чужие reports отклоняются.

Пять source-specific checks подключены к `on_update`: clock/producer, whole
result, periodic policy и bounded world. Current initial / periodic Ping разрешены
отдельным новым SHA; прежние constants для quests / tutorial не переключались.
Scheduler tests проверяют порог, отсутствие commit при отказе очереди, readiness,
потерю ответов и close. Это локальная policy, не transport delivery / live proof.

Отключённый `build-game-candidate-11318.py` требует ровно 16 актуальных source
check reports. Проверяет definitions / dependencies / artifacts / runtime / CRT,
полные EXE / PAK, INI rows, exact parent update audit и compiled tag pointer/literal.
Неполные и устаревшие доказательства отказывают. Base config snapshot:
`f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251`;
его parent находится в `knowledge/update-audits/42948f396d663fa062145c4443050024d88297a25aee723c2803c941fcfba4bd/`.
Существующий snapshot и исторический game candidate не подменялись.

Runtime loader / runner / CDN admission нового game candidate ещё требуют
отдельной интеграции. Network/live/activation/baseline flags остаются false.
Полные nested ID110/206, streaming, настоящая синхронизация, длительная сессия,
reconnect, создание персонажа, quests и tutorial этим пакетом не подтверждены.
