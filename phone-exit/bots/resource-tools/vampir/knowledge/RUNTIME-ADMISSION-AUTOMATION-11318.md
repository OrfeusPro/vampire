# Runtime candidate-11318: результат интеграции

Дополнение: после исправления точной CDN пары выполнен ограниченный живой
вход, Game Login 0, world_observation_complete, 13 PingResult за 60 секунд.
Общий runtime check расширен до 31 теста. Остаток 36 строк; current quests /
tutorial ещё не допущены. [Фактический результат и границы](evidence/updates/HEADLESS-LIVE-WORLD-11318.md).

Ниже — результат предыдущего offline этапа до живого прогона.

Подключены отдельные loader / CDN / probe / owner source guards.
[Доказательства, сценарии и ограничения](evidence/updates/HEADLESS-RUNTIME-ADMISSION-11318.md).
26 новых тестов прошли одним зарегистрированным `on_update` check; также
прошли 42 game-login, 15 selected-login, 8 world-flow и 3 preflight регрессии.
Native пакет предыдущего этапа не выполнялся повторно при неизменных inputs.

Фактический `--check-source --profile candidate-11318` вернул source_verified
для установленной 1.13.18, network_attempted=false, online_verified=false.
Реального входа в этом пакете не было. Новый owner ограничен 300 секундами;
socketpair проверил завершение controlled world observation без Stop/reconnect.
Quest / tutorial / старые map projections для нового источника не допускаются.
Прежний `candidate-11316` и его defaults сохранены.

Штатный `update --resume` завершён: очередь остаётся **36 строк**.
Эта интеграция закрывает практический source blocker запуска, но не объявляет
полными контракты Version/Login/selection/world/position и не снимает их
неподтверждённые границы. Runtime check passed, failed / timeout не засчитаны.
Состояние needs_review, live/profile activation/baseline promotion false.

Завершающий прогон: 52.900 секунды, 23 reused stages. Journal:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`
в `F:/PhoneExit Resources/Vampir/`.
SHA256: `1acd30c1e421a1e1c3bc978336c545db8f56b495c63284dac5223208d6b69b40`.
Факт: `8c8f81e20cd7b081284a765d3a69427d59957112432f2abc7d7076b0d471da2b`.

Следующий этап — один ограниченный живой прогон current candidate через явный
телефонный выход. На момент локальной проверки loopback SOCKS 17948 и API 17947
не слушали; отсутствие listener не доказывает отсутствие доступных телефонов.
Сначала восстановить / проверить принадлежащий задаче транспорт, получить
актуальный CDN manifest и patch revision, затем выполнять авторизацию.
