# Игровой LoginResult 58: BlockedIp

20 октября 2026. Продолжение [реального игрового Login](../../vampir-headless/LIVE-GAME-LOGIN.md).
Источник — код установленного клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Подтверждённая расшифровка

`ResultError_Text` 0x1458091b0 преобразует result code 58 в ASCII-ключ
**BlockedIp** по адресу 0x1498ff2b0. Это не порядковый номер строки и не
совпадение с enum Unreal. Полное native-исполнение от входа до возврата
прошло switch по фактическим jump tables и достигло этого литерала.

В уже извлечённой английской таблице ошибок `ProjectRED-Windows-6106.csv`
уникальный ключ BlockedIp сообщает об ограничении доступа с этого IP
и предлагает обратиться в поддержку за пояснением ограничения.
Это подтверждает тип отказа, но не конкретную причину серверного решения.
Не установлены страна / ASN / правила ограничения, адрес из проверки
сервера или способ устранения. Наличие HK в отдельном IP country probe
само по себе не доказывает, что игровой сервис должен принять соединение.

`Result_Gate` 0x1467a8e10 для обычной ветви кода 58 достигает общего helper
0x145f8a7a0. Экспорт helper показывает сначала поиск table override, затем
fallback в 0x1458091b0 и передачу текста popup manager. Сам override lookup
и вывод popup здесь не исполнялись. Поэтому установлены ключ и статическая
локализация, а не полный текст реального игрового окна.

## Проверка native mapper

[replay-result-error-text.py](replay-result-error-text.py) использует готовый
PE / unwind parser и закреплённые Capstone 5.0.6 / Unicorn 2.1.4. Восстановленный
псевдокод mapper содержит предупреждение о bad instruction data. Replay
сохраняет полные source ranges, но декодирует только реально достигнутые
инструкции: inline switch data не выдаются за линейный код.

Проверены семь целых вызовов:

| Код | Фактический ключ |
| --- | --- |
| 0 | Success |
| 1 | InvalidPacketVersion |
| 42 | CustomResultMessageShow |
| 54 | WaitingOverMaxCount |
| 57 | NotExistCharacter |
| 58 | BlockedIp |
| 59 | BlockedInfo |

FString constructor 0x141420f70 заменён ограниченным hook, который читает
ASCII literal из исходного PE и создаёт descriptor. Страницы source data
подгружаются по обращению с пределом 64 страниц; инструкциям запрещён выход
за PE ranges mapper, кроме указанного hook. Нет сетевых запросов, чтения
памяти игры или исполнения popup / backend.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/result-error-text-replay.json`.
SHA256: `9204fca359d1a19f2100cb53c4bab70cfc20f9fbf3677fc73567086d1d742ef1`.
Литерал BlockedIp с NUL: file offset 160 423 600, SHA256
`1f65b0f04cf014898bd97c59b9f4447b11dd48bd8c37e53684271d1b1ae19e30`.

Таблица: `F:/PhoneExit Resources/Vampir/table-study/ProjectRED-Windows-6106.csv`.
SHA256: `0139351e6a9c56a86903c24f55d3d90933167661e60994e203b34c34e97110c3`.
Строка данных 992, key BlockedIp; номер не включает header. Источник из
существующего extraction index: ProjectRED-Windows.pak, entry 6106,
offset 147 073 024, 103 289 байт. Отчёт сохраняет исходную provenance-запись
индекса; его sample hash не назван полным SHA256 PAK. CSV заново не извлекался.

Ghidra 12.1.4: 354 функции / 165 предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-3a7dd3e308b9`.
Manifest SHA256: `e694f3d94c42d65d0e2be17f7ab1f0e8e39c1853a99480c4defcaf5cbb1d09c2`.
functions.json SHA256: `628a902038b451e9c8ddbcebc6e0766cec4bba1c46d8ca20bb355913dd6a3c2c`.

## Runtime

`describe_game_login_error` сопоставляет только подтверждённый код 58:
`BlockedIp`, «Доступ с этого IP ограничен сервером». Game login probe
добавляет эти поля к безопасной сводке. Остальные коды остаются числами,
без догадок. Даже для 58 нет автоматического повтора, смены маршрута или
перехода к списку персонажей.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-result-error-text.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_result_error_text.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_login_probe.py
```

Две проверки source / runtime, шесть game login probe и три проверки Ghidra
прошли — всего 11. Внешние проверки маршрутов документируются отдельно от
этого локального доказательства значения кода.

Официальное [сообщение Netmarble от 26 августа 2026](https://ch.netmarble.com/Eng/Newsroom/Detail?bbs_code=1020&post_seq=6972)
перечисляет состоявшиеся запуски в Корее, Тайване, Гонконге, Макао и Японии.
Это сведения о регионах сервиса, а не доказательство доступности конкретного
endpoint / IP или совместимости выбранного аккаунта и региона.
