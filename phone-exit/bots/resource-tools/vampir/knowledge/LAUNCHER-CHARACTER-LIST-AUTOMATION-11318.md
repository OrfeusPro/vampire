# Launcher и CharacterList 1.13.18: итог общего пакета

Штатный `update --resume` сократил очередь **75 → 42 строки**: минус 33.
Всего снято 108 строк из исходных 150. Это причины блокировки, а не 42
независимых ручных эксперимента. Удалены 34 прежние формулировки; одна
зависимость уточнена с `launcher, game-version` до `game-version` после
готовности launcher. Нового неподтверждённого участка этим не добавилось.

Источник EXE —
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.

- [Launcher source contract / runtime](evidence/updates/HEADLESS-LAUNCHER-RUNTIME-11318.md): 14 roots, 11 offline tests, только launcher flow.
- [Финальный SDK manifest / guards](evidence/updates/HEADLESS-LAUNCHER-RUNTIME-FINAL-11318.md): новый pin после обновления общего harness, отдельные account / route / age / source guards.
- [CharacterList](evidence/updates/HEADLESS-CHARACTER-LIST-BATCH-11318.md): 40 semantic roots, две явные E9 зависимости, шесть native компонентов и 1554 строки объявленных сценариев; 18 тестов и 25 reviewed bindings.

Все 29 новых тестов прошли. Положительные проверки CharacterList используют
один native report через hash cache; отрицательные вызывают настоящие verifiers.
Cache hit сверяет полный источник, exports, код / контексты / runtime и состав
отчётов. Exclusive owner lock предотвращает параллельный повтор native build.
Шесть checks включены в `on_update`, source variants выбираются по полному SHA.
Общий проход также перепроверил затронутые Version / wire / Login регрессии;
failed / timeout checks в итоговом журнале отсутствуют.

Пакет распределялся между тремя субагентами: runtime review / scopes,
генератор контекстов, граф / тесты / общий кэш. Их результаты сверены
родительским агентом и дополнительным независимым review. Native проверки
обнаружили и помогли исправить nested input table; экспорт с выходом за unwind
границы сохранён как неудачная попытка, затем повторён с двумя явными targets.
Исторические контексты и доказательства не переписывались.

Launcher получил `prepared_offline`. Автосборщик создал профиль:
`knowledge/prepared-profiles/9842bded4b0dd2765a4950be91a1d3189371020c12e58f7f85572d82481d5fef/manifest.json`
в библиотеке `F:/PhoneExit Resources/Vampir/`. Activation, baseline promotion
и live verification — false. SDK loader отдельно использует ограниченный
launcher manifest `4c8057b367524bc26e226088f5f5ef790309f82b8c81af90ffd7e829acdcd4d2`.
Это не активация игрового профиля и не успешный вход на сервер.

CharacterList сохраняет `coverage=partial`: whole readers и handler выполнены
отдельно; reader→handler композиция / dispatcher / сервер ещё не доказаны.
Не закрыты selection / world entry, часы / Ping, game candidate и остальные
42 строки общей очереди. Новая авторизация в этом пакете не выполнялась.

Следующая работа — один общий пакет четырёх групп:

1. Clock / Lobby synchronization с отдельной проверкой системных часов.
2. Keepalive ID16 / ID17: producer, reader, whole handler / receiver и scheduler.
3. Ограниченный select / world wire, необходимый нынешнему scope game candidate.
4. Current game candidate, config / INI / tag provenance и source / runner guards.

Проверенные input Time / constructors / gate использовать повторно. Старое
исполнение Ping reader / receiver не закрывает whole handler. Ни смена SHA
в старом manifest, ни fixtures не разрешают selection / creation / quests.

Завершающий автопроход: 631.808 секунды, 7 reused stages, 0 новых запусков
Ghidra, 4 context replays. Сохранённые времена reused phases относятся к их
первоначальным исполнениям; `ghidra_batches` не является счётчиком новых запусков.
Journal: `knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
SHA256: `833934730b779d5864a2dfd635f29ff04aa382f67a95b4486a71de8f177dfeb8`.
Полная очередь: `knowledge/reports/update-manual-queue-11318-42.md`.

Факты CharacterList:
`0fd8c6bd19ece0746ff1b3b6baaca87e655ca47ad9a9357ebb716d6242d5da76`
и `23225fe9429278e936f00e5f3e9b20b028b69b5e03d9691a7aa2ed30c4c41baf`.
Финальный runtime факт:
`baaba62ab3f647d5c28d25fffbb562bb6ba0357abab941aa812112bb15969996`.
