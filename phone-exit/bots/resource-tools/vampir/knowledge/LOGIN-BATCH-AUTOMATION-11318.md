# Login 1.13.18: результат общего автопрохода

[Пакет, сценарии и границы](evidence/updates/HEADLESS-LOGIN-BATCH-11318.md).

Очередь штатного `update --resume` уменьшилась **96 → 81 строка**: закрыты
13 переносов checks и два Login result bindings. Новых причин нет. Всего
закрыто 69 строк из исходных 150. Причины сравниваются по capability/contract/
reason; обновлённые evidence/report pointers не являются новыми задачами.

13 проверок включены в `on_update`, 52 теста прошли. Подробные native reports
сохранены самими зарегистрированными тестами: 6772 исполнения перекрывающихся
сценариев. Итоговый автопроход использовал их hash cache; вторая группа
явных адресов и оба `finish` использовали те же reports без запуска тестов.
39 roots оформлены двумя research requests из-за штатного лимита 32; это
один пакет и один коммит, а не отдельные этапы по каждой функции.

Факты: `31b9a9a6906dbad3d0f4771e86c7bf91a5a1cd6f1b32a7924c2f163b844e32b0`
и `5124d3f85e672aeb6c60d5be776ab45d2b08f30650efc65ef7909f28021d2e52`.
Общий native summary в библиотеке ресурсов:
`knowledge/login-batch-verified-summary-11318/9f08d333e6f4cb7c93d30b61513e83ac3d425f2a1bb056dbc401ec117de21889/manifest.json`.

Итоговый прогон занял 495.164 секунды; общий harness изменился, поэтому
затронутые Version/wire и tooling регрессии перепроверены автоматически.
Новых Ghidra-запусков в завершающем прогоне 0, переиспользовано 9 этапов.
Это измерение текущего запуска, не оценка следующего обновления.

Журнал в библиотеке ресурсов:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
SHA256 журнала: `9b5bb2dfa7f25472a46808fe64c81f45943555b2b594294f8f479f6e39b35f97`.
Полная очередь: `knowledge/reports/update-manual-queue-11318-81.md`.

Состояние `needs_review`, profiles пуст, activation/baseline promotion false.
Coverage Login остаётся partial: prepare→wire composition, реальные SDK/
backend/dispatcher и онлайн не подтверждены. Далее общие пакеты SDK/GMC2/NID,
CharacterList и оставшиеся clock/profile prerequisites; общие input/wire
переиспользуются. Не возвращаться к ручному переносу неизменённых helpers.
