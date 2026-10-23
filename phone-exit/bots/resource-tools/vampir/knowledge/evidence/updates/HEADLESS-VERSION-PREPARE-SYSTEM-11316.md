# Version prepare с native Windows / CPU / NM 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Готовые exports использованы повторно, Ghidra в этом этапе не запускалась.

В 64 сценариях целиком исполнен Version prepare `1467ce6a0` с constructor
`1456d7be0`, NM wrapper/getter, Windows suffix и CPU formatter/getters/trim.
Это один replay с общей памятью и allocator fixtures, а не сопоставление отдельных
результатов. На каждый сценарий приходится 2 NM entries, 1 Windows helper,
1 CPU formatter, 2 CPU getters и по 3 вызова trim wrapper/start/end.

Матрица: четыре poison pattern, context present / absent, пустые / непустые
исходные данные, enum 0 / ffffffff, send return 0 / 1.

- Native Windows helper получает синтетический cold TLS state. При успешном
  API результат `10.0.26100.1.256.64bit` передаётся в combiner; при ошибке — пустой.
  Сверяются порядок acquire / system-info / memset / version / format / release,
  аргументы format и cookie. Сам WinAPI / CRT остаётся fixture.
- CPU formatter получает начальные ASCII buffers, вызывает actual getters и
  native trim. В поле `+38` передаётся `GenuineIntel|Fixture CPU` либо `|` для
  двух пустых частей. Пустые CPU inputs поэтому не означают пустую итоговую строку.
- Native NM cache возвращает `nm-cache-Ж🙂`, передаваемый в поле `+48`.
- Поля целого пакета совпали с ожидаемыми. Временные allocations очищены, входные
  FString и CPU cache не изменены; canaries, owner reset, nonvolatile registers
  и RSP сохранены. Проверены оба ответа send; сеть не вызывается.

Общие ASCII / wide constructors и free проверены на совпадение привязок между
контекстами. Любая подмена actual helper, call site, общего constructor или SHA
экспорта отклоняется. SHA дополнительного fixture-модуля включён в replay report.

## Что ещё не доказано

Platform selector / context lookup в этом целом prepare ещё fixtures, несмотря
на отдельные native проверки. Combiner output задан явно: реальная конкатенация
не подтверждена. OS/CPU state и NM cache синтетические; CPU initializer / CPUID,
реальный WinAPI / CRT, storage cold path NM в общей цепочке не исполняются.
String construction / allocation / free / destruction, log и send — fixtures.
Login prepare, result readers, framing, авторизация и игровая сессия не проверены.

[Контекст](../../native-contexts/version-prepare-system-11316.json),
[квитанция](VERSION-PREPARE-SYSTEM-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_prepare_system_context.py
```

## Обновления

`native-version-prepare-system-context` подключён к game-version / update.
Зависимости включают verifier, fixture-модуль, context, pinned runtime, tests
и пять exports. Изменение helper требует новой проверки; посторонний README
не запускает native replay. Проверка нового SHA требует явного нового context
и переноса call sites / imports / globals, без автоматического продвижения runtime.
Следующий этап: оставшиеся context / combiner зависимости Version и whole Login
prepare, затем result readers. Готовые exports повторно не собирать.
