# Ранние условия NID и дополнительные поля аккаунта в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [converter / extensions](HEADLESS-NID-CONVERTER-11316.md).
Использован готовый export `0x1450e3c80`; Ghidra повторно не запускалась.
Проверка работает с сохранённым EXE и synthetic memory, без игры и сети.

## Ранние условия

Исполняются инструкции от `0x1450e3d24` до одного из трёх branch destinations.
На этих адресах observation hook останавливает выполнение перед следующей
стадией. Инструкции не подменены, произвольные targets не разрешены.

| Условие | Куда приходит управление |
| --- | --- |
| Getter 0x14455a0a0 вернул false для authWebViewUrl | 0x1450e3d89, ветка ошибки URL |
| Getter вернул true, signed count settings +0xa0 ≤ 1 | 0x1450e3edd, ветка ошибки clientId |
| Getter вернул true, signed count settings +0xa0 > 1 | 0x1450e4058, базовые context pairs |

У `clientId` FString начинается с settings +0x98, count находится по +0xa0.
Проверено точное signed comparison. Входы count: INT_MIN / -1 / 0 / 1 / 2 /
16 / INT_MAX. Отрицательные и предельные значения — synthetic boundary cases,
а не наблюдение реального FString в игре. Дополнительно проверены уже готовые
и лениво получаемые CDO: settings class вызывается только после успешного URL
getter. Class getters и initialization являются fixtures.

112 случаев: четыре poison fills × два результата URL getter × семь counts ×
два состояния CDO. Проверены аргументы lookup, точный ключ, short circuit,
branch destination и canaries.

Caller проверяет результат getter, но сам здесь не валидирует URL string.
Реализация lookup / правила empty / источник GMC2 не исполнены. Error objects,
их callback delivery и освобождение не исполнены: остановка происходит раньше.
В исходном EXE отдельно сверены UTF-16 тексты будущих error branches:
`0x149739060` — authWebViewUrl is null or empty,
`0x1497390a0` — clientId is null or empty.
Эти тексты не выдаются за наблюдавшиеся ошибки сервера.

## Поля аккаунта

Второй участок `0x1450e48aa..0x1450e4a95` заканчивается перед query assembly.
Проверяются реальные инструкции caller и следующие связи:

| Условие | Добавляемые параметры |
| --- | --- |
| FString context +0xa0 имеет count > 1 по +0xa8 | accessToken из этого FString |
| Count ≤ 1, predicate 0x144531850 true, state getter 0x144528390 дал 0 или 100 | playerId, joinedCountryCode, accessToken |
| Иначе | Поля аккаунта не добавляются |

State getter вызывается перед выбором ветки. Predicate не вызывается при
непустом NID token. В fallback `playerId` читает getter `0x14452b620` с context
receiver, `joinedCountryCode` — `0x14452ab90` с account receiver; accessToken
берётся из account +0x78. Это bindings текущего caller. Полные реализации
getters / predicate и смысл state enum этим не подтверждаются.

512 случаев: четыре poison fills × четыре NID counts (0 / 1 / 2 / 16) × четыре
state bytes (0 / 1 / 100 / 255) × predicate false / true × пустые / непустые
synthetic SDK fields × два состояния account CDO. Counts 0 / 1 моделируют
нулевую и выделенную пустую FString; 2 / 16 — строки длиной 1 / 15 символов.
Проверены приоритет NID token, порядок fallback fields, сохранение пустых полей,
short circuit getters, receiver / destination / map bindings и canaries.

## Границы и воспроизведение

Capstone 5.0.6 / Unicorn 2.1.4. Полные SHA EXE / export и байты каждой
исполняемой инструкции проверяются; instruction / string / heap budgets конечны.
Class getters / initialization, URL lookup, account predicates, player / country
getters, FString storage / free и обе map insertion functions — fixtures.
Все токены и идентификаторы синтетические. Последовательности ранних gates и
account additions исполнены отдельно, вся CheckPossibleToOpen не заявляется.
Logging path, error callbacks, query encoding, browser и auth lifecycle открыты.
Runtime profile не включён.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-gates-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_gates_11316.py
```

Два теста: native scenarios / precedence и отказ при повреждении export.
Check `nid-gates-native-11316` связан с SHA / export / tools в research-checks.json.
В release-update-targets.json scope текущего NID root дополнен этими участками
и required_check. Повтор того же SHA автоматический; при новой сборке нужно
сверить branch destinations, offsets, literals и getters перед переносом check.
Совпадение diagnostic signature не разрешает автоматически обновлять runtime.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Export `ghidra/request-exports/<SHA>/run-988ec3bf8f0a/details.json`,
  SHA `ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd`.
- Report `code-clues/nid-gates-11316/ef03ffa1746f2d46c1f82fbb5ab1a699c9ade676e24b4c8360f8410a07ed5fb8/manifest.json`.
- ASCII keys `0x149533368` accessToken, `0x14952d540` playerId,
  `0x149533388` joinedCountryCode.

Следом — сверить final query encoding / browser delivery и auth source guards
для подключения нового SDK profile. Настоящие getters и error callbacks
сохраняются как отдельные unknown; живой вход проверять после доступности серверов.
