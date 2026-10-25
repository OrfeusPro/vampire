# Ограниченный вход существующего персонажа, 1.13.16

25 октября 2026. Продолжение [исправления Game Login](../network/HEADLESS-LOGIN-GEO-FIX-11316.md).
Source SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Пользователь поручил продолжить выбор существующего персонажа и вход в мир.

## Перенос и границы

`candidate-11316` получил отдельную возможность `bounded-world-probe`:
явный выбор из свежего принятого списка, ID202 prefix → ID203 → ID204 →
пустой ID205 → строгий ID206 и ограниченное наблюдение с periodic Ping.
Создание и квестовые команды не включены; recovered-release и baseline сохранены.
Профиль требует отдельный immutable report `world-entry-11316`, не только новый SHA.

Сначала исторические writers/readers найдены ограниченным masked-prefix поиском.
Кандидаты не считались подтверждёнными до проверки полных instruction contracts.
В [verifier](../../../verify-world-entry-relocation.py) для 15 явных пар сравниваются
все инструкции с масками только RIP и relative targets. Local branch offsets,
доступы к полям, виртуальные slots и immediate constants должны совпасть.
Отдельно сохранены пары внешних callees/data: сравнение формы не доказывает
равенство вложенных функций. Native [replay](../../../replay-world-entry-11316.py)
проверяет source SHA, immutable relocation report и явные exports.

Полные exports 14 текущих unwind roots:
`ghidra/request-exports/<SHA>/run-529edd8cc6b1/details.json`, SHA256
`e5afea845d4188d050edb1ab981fde64866191832eab68037357a05aef752199`.
[Карта exports](../../native-contexts/world-entry-exports-11316.json).
Первый batch остановился на Ping handler tail JMP за unwind: recovery target
не имеет unwind root. Handler исключён из следующего batch; его instruction
shape проверена отдельно, целый recovery не объявлен исполненным.
Готовые промежуточные экспорты и журналы сохранены, границы EXE не расширялись.

201 native-сценарий:

- actual ID109 `<QIQ` и ID203 `<Q` writers;
- ID202 outer prefix / nested reader до opaque suffix с явной границей;
- полный ID204 reader с bounded archive/vector fixtures и всеми короткими телами;
- полный ID17 reader с короткими телами;
- current Ping receiver: сброс счётчика / tracking и арифметика elapsed.

Native report:
`code-clues/world-entry-11316/e08456a3836ae25fc4b964e1aea695cba4aed819b61913fba5d18ba0f6a41cc6/manifest.json`.
Relocation report:
`code-clues/world-relocation-11316/67c301f00b6cbf0e3706dad823acb14144e3bfa547fd9dd401f15b1a9f37d9ae/manifest.json`.
Каталоги в библиотеке ресурсов, имена совпадают с SHA manifest.

Archive IO, nested thunk, vector conversion и output writer — fixtures.
Полный ID202 suffix не разобран. ID110 и вложенные ID206 по-прежнему используют
строгие historical parsers: все варианты новой сборки этим переносом не доказаны.
Лишние / короткие / неподдержанные ответы отклоняются. Готовность engine streaming,
активный UI/actor, движение и бессрочная сессия не следуют из native replay.
После code-zero ID204 отправка ID205 — прежняя явная headless policy,
а не имитация загрузки мира официальным Unreal клиентом.

```powershell
$env:PYTHONPATH='phone-exit/bots/vampir-shared;phone-exit/bots'
python -X utf8 -m unittest test_vampir_world_entry_11316 test_vampir_world_entry_flow test_vampir_periodic_ping test_vampir_candidate_game_profile test_vampir_game_login_probe test_vampir_selected_game_login
```

102 локальных теста прошли: native replay / повреждённый export, current world
policy, timeout / malformed / refusal / cleanup, heartbeat queue/threshold и
source-bound передача разрешений runner. Сеть и credentials эти тесты не используют.

## Живой результат через HK

Аккаунт `bot-hk-test@vampir.top`, JP / Franz 2 / server 256, group 253.
Свободный HK Infinix X6525, отдельный native WebRTC транспорт, SOCKS только на
loopback 17948. ClientVersion 262487, launcher flow, язык 1, свежий GMC2 geo.
Сохранённый TID не читался и не менялся; аккаунт / device bindings / назначения
не менялись. Пароль передан через скрытый stdin, без записи в файлы и логи.

- Game Login 0; свежий список с одной записью, выбран index 0.
- CharacterSelectResult 0; body **4728 байт** полностью принят bounded parser.
- ID202 result 0 → ID203 → ID204 result 0 → ID205 → ID206 result 0.
- Полный ID206 принят, конечный серверный вектор получен и проверен на finite.
- Наблюдение после ID206 **120 секунд**, status `world_observation_complete`:
  **24 periodic Ping / 25 ID17**, `world_entry_error=null`, `error=null`.
- Game send / recv **1655 / 48836 байт**; lobby **814 / 11466 байт**.

Это подтверждает ограниченный headless вход и heartbeat на одном текущем теле
ответа / аккаунте / сервере через удалённый телефон. `game_session_ready=false`
сохранён как консервативный общий статус: не доказаны бессрочная сессия, reconnect,
все варианты nested данных, движение, актуальная actor-позиция / engine correction
и готовность к квестовым действиям. Ник в текущем диагностическом отчёте не
раскрывался; прежнее имя Okly не является заново полученным label этой попытки.
Команды квестов, движения, боя, создания и обучения не отправлялись.

После окончания теста игровые сокеты закрыты; принадлежащий пробе транспорт
получил Stop, завершился с code 0. Loopback listener закрыт. Отдельно до
авторизации был обнаружен ещё один preflight guard, допускавший world только
для recovered-release; он расширен на явного кандидата с обязательной
source-bound capability. Эта локальная остановка не была серверным отказом.

Приватный отчёт:
`F:/PhoneExit Resources/Vampir/live-checks/hk-20261025/hk-world-120-result.json`,
SHA256 `250e184e5089dcb68bf9f1abc07674d92c279d6de12d7d25e92777c039446d1a`.
HTTPS CDN manifest SHA256:
`54bbe08ec7ca8fe490c126b572ecb65c04633e23c8b2c44abe3060391685e6c0`,
7632 байта, config 1.13.16. Credentials / raw auth bodies / координаты не сохранены.

Следующий шаг — подключение текущего source к read-only слою карты и отдельный
приём команд движения без блокировки socket pump / heartbeat. Исходящий ID305
и его server result требуют source-bound проверки до отправки. Живую сессию
не считать оставленной онлайн после завершённой ограниченной пробы.
