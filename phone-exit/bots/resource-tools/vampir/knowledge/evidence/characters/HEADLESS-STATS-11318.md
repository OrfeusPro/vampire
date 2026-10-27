# Характеристики 1.13.18 и отдельный живой наблюдатель

Источник: EXE SHA256
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Квесты / tutorial не переносились. Действующий owner не перезапускался.

## Общий source-bound пакет

Shape matcher ограничен 10 stat roots и одним явным PktCharacter reader.
Две неоднозначности разрешены через точные callback table+16: initial wrapper
1457351B0 → table149941188 → callback14573D620 и level reader1456C4B20 →
table149926448 → callback1456C6A70. Ближайший адрес не выбирался.
Alignment: `knowledge/stat-batch-alignment-11318/d6b4ec7817e28a30f19da1463337e989cd7cd7cfb1c430dfd9aab557db86ac81/manifest.json`
в `F:/PhoneExit Resources/Vampir/`.
Общие current input/vector proofs переиспользованы; получены только недостающие
explicit unwind roots: exports run-c76e7785700f и run-ceaa0e5d6498.
Старый источник и старые runtime guards не подменялись.

Generated contexts stat-notify-11318 / stat-initial-11318 связывают current
readers, callbacks, record constructors, apply и model setter с exports.
PktCharacter145787A20 по точным исходным байтам вызывает1457351B0 с main+1C8.
Выполнены 1119 notify и 203 initial сценария в общей памяти: целые readers,
vector/record, current archive, apply и существующие keys модели с коллизиями.
Начальные / уведомительные значения сравниваются с отдельным лёгким
stat_change_11318.py, закреплённым на current SHA.

Полные current отчёты:

- notify: `code-clues/stat-notify-11318/4b6d7da19c0a9af1f043608d84ea7d097679b421448a70326ad3dada99b9c2b8/manifest.json`;
- initial: `code-clues/stat-initial-11318/99fa2824cb6fd12065e41111dadff2233b0e115e315552adcd4072f801343bd8/manifest.json`.

Чтение ID/name slots, reviewed constructor vptr store и reader slot+20
проверены отдельно. PktCharacterLevelUpNotify: ID321, ctor1456BF0C0,
vtable149922028, reader1456C4B20; PktStatChangeNotify: ID322, ctor1456C0770,
vtable149923E48, reader1456C5A10. Binding reports:
`c390d402da90e1b0a4aef9347c5b87d38aa0c4828264eeaeb1e5e5eae3675b3f`
и `4dcd921f619e8883cabf5a231723b33e06a609abf1f93ca7007733536a08d93f`
в `code-clues/stat-packet-bindings-11318/`.

208 current EStat descriptors сверены с указателями имён и int64 values EXE.
Level=3, Hp=4, MaxHp=5, Mp=9, MaxMp=10. Report:
`knowledge/stat-enums-11318/a9a373cdc17c73008ae0bc804a335d0996749187f092b49d7c8afc71a53d98e5/manifest.json`.
Decoder SHA: `70624e1a1225ddf14fddb6e215cf2d31de36285160db76296c42f7db6bcb9cd5`.

14 тестов native/alignment/source bindings passed. Общий
native-stat-batch-11318 включён в on_update и source/dependency cache.
Воспроизводимая генерация contexts проверяется отдельно; unknown bindings
не подставляются по именам или близости адресов.

## Подключение без перезапуска

observe-stats-11318.py работает через существующий leased diagnostics API:
только новые ID321/322, неизменяемая source identity owner из samples endpoint,
bot/session/character/world scope, ограниченные память / строки / records.
Перед decode проверяются полные SHA native reports, codec, contexts, producers,
packet-ID bindings и EStat; в одноразовый worker не импортируются Ghidra / Unicorn.
Raw samples хранятся только в памяти с прежним лимитом 256 KiB / 60 секунд,
не пишутся в файлы. Истечение lease само выключает sampling.

Результат — отдельный analysis.values.readonly_stats с provenance и статусом
waiting_for_notification либо observed_partial. Он не перезаписывает character
owner и не отправляет игровые команды. Пропуски / malformed / смена scope
сбрасывают наблюдения. Значения int64 сохраняются строками; отрицательные или
небезопасные для JS числа не становятся отображаемыми vitals.

Общий UI adapter дополняет только неизвестные поля HP/MP/Level, проверяет scope,
source/proof/codec/packet/enum SHA, обновление наблюдателя не старше 6 секунд.
Известные native поля имеют приоритет. Исходный API snapshot, interaction
adapter, coverage и квестовые действия не меняются. При неполной HP/maxHP или
MP/maxMP паре индикатор остаётся неизвестным. Дополненные значения помечаются
как «наблюдение новых сообщений».

12 наблюдательных тестов passed, включая три Node набора и настоящий отдельный
worker с проверкой реальных proof files. Worker integration использует synthetic
packet fixture: это не полученные HP персонажа. Одна не связанная с изменением
live-interaction регрессия имела intermittent WebCrypto settle timing failure;
standalone и повторный запуск прошли. Старый тест не изменён и не включён в
новый recurring пакет. observed-stats-adapter-11318 включён в on_update/cache.

Requested preview: `1eb4a416e8fb4e5d258c1c76efb0f3c327a246a56c68b9124692e77edf69b3eb`.
В браузере текущей сессии проверены online name, локальный map marker и
неизвестные vitals без fake zero. Numeric overlay проверен synthetic fixtures.

## Что фактически происходит онлайн

Наблюдатель запущен отдельной одноразовой задачей Windows и остаётся после
закрытия Codex. Startup / PID приватно в
`live-checks/persistent-hk-11318-20261027/stats-observer-startup.json`.
Тот же game owner / session продолжают connected, ответы Ping поступают.
API trace содержит только321/322, analysis.error=null,
readonly_stats.status=waiting_for_notification. Три сообщения322 пришли до
подключения наблюдателя; их bodies owner намеренно не сохранял. Новых пока нет.
Начальные HP/MP текущей сессии восстановить через существующий API нельзя.
Игра и транспорт не останавливались; новая авторизация не выполнялась.

Границы: storage/reset/cleanup/memcpy/ownership/external identity services —
bounded fixtures; insertion/listeners/UI/engine side effects не выполнены.
Полный PktCharacter reader не replayed целиком: проверен статический +1C8 link.
Нет causal action confirmation, свежих live HP/MP, объектов окружения, current
movement / engine correction или квестовых capabilities. Queue36 автоматически
не закрывается этим read-only пакетом. Далее дождаться нового соответствующего
сообщения, либо при отдельном согласованном повторном входе подключить новый
initial stats decoder к owner; живую сессию пока сохранять.
