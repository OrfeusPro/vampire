# WaitingEndNotify 1.13.16 → запрос персонажей

24 октября 2026. Источник — собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Перенесён [исторический инициатор](../characters/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).
Это отдельное событие, а не действие
[reset после LoginResult](HEADLESS-LOGIN-CONTINUATION-11316.md).

## Поиск и привязки

Прежняя строка `PktWaitingEndNotifyHandler::OnHandler()` в текущем EXE не найдена.
Сохранён literal `PktWaitingEndNotify` по `149926f18`; соседняя packet table
`149926ec8` связана с constructor `1456d7d00` и actual ID getter `1456e4d10` → 27.
Регистрация в окне `1467b5186..1467b51cf` внутри owner `1467b4c60` создаёт
packet через этот constructor, задаёт handler table `149dc66c0` и передаёт
packet/handler в `1467cb6c0`. Table slot `+10` → handler `14679d2d0`.
Source bytes, инструкции, аргументы и table links проверяются автоматически.
Oversized owner целиком не экспортируется и не исполняется.

Новые exports: `run-6034b73830e4`, четыре явных unwind roots:

| Роль | Адрес |
| --- | --- |
| Handler | `14679d2d0` |
| Predicate | `145c9ad90` |
| Запрос списка | `145dadc40` |
| Quick-select thunk | `145d5c120` |

Request routine вызывает constructor `1456d7200`, устанавливающий table
`1499289e0` и byte `+a = 0`. Slot `+28` этой table → actual getter
`1456e4c00` → 101. На virtual send boundary проверяются table и byte `+a`.
Packet constructor, singleton getter `144ab0c40`, peer flag getter
`144ab0d20` и destructor `1456b66c0` исполняются native.

## Исполненные условия

В одной памяти исполняются notify constructor → handler → peer flag → predicate
→ request/quick-select, включая native E9-переходы. Predicate проверяет global,
наличие объекта, metadata count/index/pointer и лишь затем вызывает policy virtual.
Lookup/type objects и virtual policy result заданы fixtures. Видимый UI отсутствует.

| Peer flag | Policy result | Результат |
| --- | --- | --- |
| 0 | 0 | Quick-select со значением selected `+28`, либо next при sentinel |
| 0 | nonzero | Без запроса и selection/next |
| nonzero | 1 | Request → send capture ID 101 |
| nonzero | 0 | Повторный predicate, затем next |
| nonzero | 2/4 | Повторный predicate, затем selection с notify `+10` |

Проверены 16 основных случаев и 8 fallback: disabled global, null policy object,
metadata mismatch и короткий metadata count при обоих peer flags. Только два
основных случая достигают ID 101; fallback возвращает 4 и не отправляет запрос.
Проверяются источник selection arguments, порядок и число вызовов, packet guards,
неизменность notify и ABI. Имена enum для raw policy values не установлены.

## Воспроизведение и обновления

[Context](../../native-contexts/waiting-end-11316.json),
[verifier](../../../verify-waiting-end-context.py),
[три теста](../../../../../test_vampir_waiting_end_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_waiting_end_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-waiting-end-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/waiting-end-11316.json
```

Report: `F:/PhoneExit Resources/Vampir/knowledge/native-waiting-end-checks/14711f3d34bb9d5f81402a9e90c8c401a5924210cbf3798301faba84a06a767c/manifest.json`.
Context и report содержат полный SHA, хеши exports, source bytes и границы replay.
Check `native-waiting-end-context` подключён к `character-list`.

На следующем патче искать packet через literal/name getter/table, затем actual ID,
constructor и его registration; handler/predicate/request/callees проверять отдельно.
Отсутствующая diagnostic строка не требует повторного поиска внутри reset.
Literal и сходство адресов сами по себе не подтверждают роль или runtime readiness.

## Что ещё не установлено

Notify reader и сетевой dispatch не включены; raw64 notify задан fixture.
Не доказано время прихода ID 27 после успешного Login и обязательность этого пути.
UI, lookup/type objects, policy implementation, send/selection/next и diagnostics
остаются fixtures/captures. ID 101 не отправлялся серверу; ответ списка и создание
персонажа не проверены. Профиль и baseline не активированы.
Далее — текущий reader/handler ответа списка и его связь с runtime decoder;
для живого входа также остаются зависимости игрового профиля и Ping clock.
