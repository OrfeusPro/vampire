# Vampir: живое завершение входа в мир

Источник: текущий Windows EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
[Native доказательства и политика](HEADLESS-RELEASE-WORLD-FINISH-POSITION.md).

## Живой ID 206 после замены телефонов

22 октября пользователь добавил три телефона. Выбран новый JP / TECNO TECNO KJ5n;
игра на ПК не была запущена. Выполнен один явный `read-world-finish` для прежнего
аккаунта и Franz 2, со свежим GMC2 в памяти и текущим source profile.

Получены Game Login code 0, CharacterList code 0 / один персонаж, выбор ID 110
code 0 / 4724 байта полностью разобраны. Далее в том же соединении прошли
ID 202 → ID 203 → ID 204 code 0 → ID 205 → ID 206 code 0.
Runner завершился со статусом `world_finish_result`, без ошибок.
`server_target_position_received=true`: полный decoder принял ID 206, основной
вектор конечен, `WorldEntryFlow` связал его с world ID из свежего ID 204.

Send 1052 / receive 10064 байта, 30 сопутствующих пакетов, byte counts complete.
Координаты, ID аккаунта, ключи и raw bodies в публичную сводку не сохранялись.
`world_reserve_full_body_validated=false`: полный хвост ID 202 не объявлен
разобранным. `game_session_ready=false`: длительная работа, периодический Ping,
движение, engine correction и отображение на карте не проверялись.

Отчёт в `F:/PhoneExit Resources/Vampir/live-login-observations/`:
`1cafa50a96c220b91dbbed5c3f6bde7893f28e38c86ae1d14c6fe682ccca6d25/manifest.json`,
SHA256 `1cafa50a96c220b91dbbed5c3f6bde7893f28e38c86ae1d14c6fe682ccca6d25`.
Он содержит hashes runner / runtime и границы наблюдения. Соединение закрыто
владеющим runner, временный маршрут завершился с code 0. Другие новые телефоны
не использовались. Следом — поддержание сессии и связь позиции с существующей
картой; повтор готовой авторизации без нового шага не нужен.
