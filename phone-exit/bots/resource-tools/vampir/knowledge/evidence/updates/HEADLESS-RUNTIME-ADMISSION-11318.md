# Явный runtime-допуск candidate-11318

Источник EXE:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Предыдущий [offline пакет](HEADLESS-CLOCK-WORLD-BATCH-11318.md) сохранён.
Новая интеграция не включает создание персонажа, квесты, обучение или карту.

Loader добавляет отдельные `LATEST_CANDIDATE` / `LATEST_SHA`; прежние
`CANDIDATE=candidate-11316` и `CURRENT_PROBE_SOURCE` не изменены. Manifest
`c8c3f905956ce66f2037f8f759b3e45b889ca4dce3032e4a24c04221d835a575`
и config `f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251`
закреплены полными SHA. Helper `game_candidate_evidence.py` использует stdlib
и не запускает Ghidra / Unicorn / analysis tools. Он повторно проверяет 16
proof reports, current definitions, inputs / artifacts / runtime / CRT,
EXE / PAK / INI / audit. Общая зависимость с конфликтующими digest в двух
reports отклоняется, поздняя запись не скрывает устаревшее доказательство.

`BaseGameProfile` допускает только явный bounded probe; active cache false.
Сам immutable candidate сохраняет runtime/network/live/activation/baseline false:
его данные не переписаны при подключении loader. Source preflight означает
прохождение локальных guards, а не server acceptance.

CDN adapter добавляет точный HTTPS URL
`https://red.gcdn.netmarble.com/red/config/window/real/1_13_18/config.json`.
Проверяются source / snapshot / scope, выбранный SOCKS route, status, encoding
и отсутствие redirects / direct fallback. HTTP в тестах synthetic; отдельно
прошла проверка настоящего loader / source provenance без HTTP.

Probe требует current profile name и current SHA одновременно. Quest / tutorial
requests и observers отклоняются до lobby / auth. Новый `LATEST_PROBE_SOURCE`
добавлен только в bounded world policy; старые quest/tutorial/map identities
сохранены. Проекция карты нового источника не допускается по старому manifest.

`run-live-sessions.py` получил явный `--profile candidate-11318`, включая
`--check-source` и detached handoff. Старый default сохранён. Source проверяется
до password prompt / owner; current profile передаётся в worker явно. Прямой
`run_accounts` также проверяет source и запрещает projection до создания API.
Current owner ограничен 300 секундами; более долгий срок отклоняется. Обычный
и detached CLI задают этот предел независимо от старого режима на 86400 секунд.

Review выявил, что session_control ранее выключал observation deadline.
Исправлено отдельно для нового SHA: публикация connected не делает deadline
бесконечным, finite observation устанавливается даже при наличии LiveSession.
Локальный socketpair тест исполняет Version/Login/list/select/202→203/204→205/206,
публикует connected, продвигает virtual monotonic на 301 секунду и получает
world_observation_complete без Stop/reconnect. Owner закрывается, character
очищается. Старое поведение ловится отрицательным контролем без долгого ожидания.

26 новых тестов объединены в `test_vampir_runtime_admission_11318.py` и один
source-bound `on_update` check. Отдельно прошли 42 game-login socketpair,
15 selected-login, 8 world-flow и 3 прежних source-preflight регрессии.
Старый CDN suite имеет source mismatch для recovered-release на установленном
новом EXE; этот отказ не скрыт и не исправлен ослаблением guard.

Команда без secrets / внешнего IO:

```powershell
python -X utf8 phone-exit/bots/vampir-headless/run-live-sessions.py --check-source --profile candidate-11318
```

Фактический ответ: source_verified, версия 1.13.18, полный current SHA,
network_attempted=false, online_verified=false. Авторизация, реальный сервер,
телефонный маршрут и длительная сессия в этом пакете не проверялись.

Исследование распределено между тремя субагентами: loader, CDN, probe/world
guards. Родитель сверил изменения и исправил найденные review gaps в прямом
helper вызове, bounded owner и конфликтующих dependency hashes. Положительные
native доказательства предыдущего пакета не перезапускались при неизменных
inputs. Следующий этап — отдельный ограниченный online-прогон с текущим
источником; не выдавать локальный fixture flow за живую сессию.
