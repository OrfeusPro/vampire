# Действия выбранного персонажа

Запрошенный сценарий: клик по квесту запускает выполнение; появившиеся квестовые
реплики можно выбирать; доступна команда пропуска; обучение может требовать
экипировки и других действий с инвентарём. Одного QuestUpdate для всего сценария
недостаточно. Contracts действий и серверный результат проверяются отдельно.

Уточнённые режимы: показывать сообщения для ручного выбора; по умолчанию
пропускать только доступные диалоги / ролики; auto quest включается отдельно и
запускается кликом по квесту. Если требуется подойти к NPC, показывать цель и
ждать нового игрового состояния. [Готовая UI-панель и её текущая граница](../vampir/UI-LIVE-MESSAGES.md).

## Готовая основа очереди

`vampir_core.action_queue.SessionActionQueue` — ограниченная очередь намерений,
не сетевой отправитель. Идентичность bot / session / source задана при создании.
Контракты передаются только владельцем при создании; по умолчанию список пуст,
ни одно действие недоступно. SHA здесь обозначает заявленный контракт адаптера,
не заменяет его проверку по клиенту. Runtime-профиль пока не разрешает действия.

Поддержаны формы намерений, пока без игровых packet contracts:

| Вид | Поля |
| --- | --- |
| quest_follow | quest_id |
| dialogue_select | dialogue_id, choice_id |
| dialogue_skip | dialogue_id |
| tutorial_equip | item_instance_id |

Все ID — ограниченные десятичные строки uint64. Это нейтральные поля будущего
адаптера, не утверждение, что игровой протокол использует такие же имена / ID.
Для экипировки конкретный item instance отличается от ID шаблона предмета.
Произвольные packet bodies и дополнительные поля не принимаются.

Намерение включает уникальный request ID и SHA контекста, построенного адаптером
из относящегося к действию подтверждённого состояния. Heartbeat / время опроса
не должны создавать новый контекст. Сам HTTP handler не исполняет команды;
claim / sent / resolve требуют private owner key и вызываются владельцем сокета.
Функция сети или callback в самой очереди отсутствует.

- До исполнения owner сравнивает текущий context: устаревшее намерение отклоняется.
- Повтор того же request ID возвращает прежний статус. Другие параметры с тем же
  ID отклоняются. После удаления подробной истории ID не забывается.
- Максимум 16 незавершённых действий, 64 подробные записи и 4096 request IDs за
  сессию; после общего лимита новые намерения отклоняются, старые не повторяются.
- По одному выполняющемуся действию на аккаунт. Разные аккаунты независимы.
- Queued истекает через 5 секунд до отправки. Executing / sent имеют 10 секунд
  до неизвестного исхода. Sent не означает серверное подтверждение выполнения.
- Unknown блокирует очередь и отклоняет последующие queued. Новые request IDs
  не обходят эту блокировку. Только owner после нового подтверждённого контекста
  может вызвать resume_after_sync; прежний неизвестный исход не переписывается.
- При закрытии queued получает известный отказ до отправки, executing / sent —
  unknown. Слепого повторения / переноса команды в другую сессию нет.

`test_vampir_action_queue.py`: 5 тестов прошли. Проверены 50 synthetic accounts
параллельно, private owner key, чужая session, повтор / изменение request ID,
одновременные намерения, stale context, expiry, unknown / синхронизация, close,
лимиты / забытая подробная история, неизвестный contract и некорректные поля.
Контракты в тесте синтетические, сеть и игровой сервер не вызываются.

## Что ещё требуется

Очередь подключена к новому LiveSessionServer через POST /actions и /policy,
но ещё не к game pump. В текущем уже онлайн-owner её нет; сохранённое соединение
не перезапускается. Analysis остаётся
наблюдательным и не используется для обхода отсутствующего action channel.

Новый owner явно вызывает install_actions с private key и source-bound contracts,
затем offer_actions с точными kind / context / arguments. По умолчанию канал не
создаётся; production launcher его пока не устанавливает. HTTP не может установить
contract, опубликовать offer, claim / sent / resolve или подтвердить исполнение.
Токен новых владельцев — 32 случайных байта в 64 hex-символах, совместимых с
UI adapter. Прежний онлайн-процесс не меняет формат своего токена.

POST /actions принимает request_id, kind, context, arguments, policy и origin;
bot_id / session_id и session token обязательны. Policy содержит ровно два bool:
skip_dialogues / auto_quests. Origin manual или auto_skip; последний допустим
только для dialogue_skip при разрешённом пропуске. Существующий receipt возвращается
после удаления offer без повторной постановки. Изменение намерения с прежним ID
отклоняется. Новое намерение должно точно совпадать с текущим owner offer.

Claim проверяет offer повторно, а также character / world и текущую policy.
Смена мира удаляет offers; возвращение в прежний мир их не восстанавливает.
Выключение пропуска отменяет queued auto_skip до отправки. Отдельное изменение
policy не ставит квест в очередь. В намерении сохраняются исходные policy / origin;
claim также передаёт current_policy владельцу. Перед отправкой handler обязан
проверить новый игровой контекст и текущую policy; сама очередь ничего не посылает.
Закрытие сессии завершает очередь, sent получает unknown.

Проверка: 5 тестов test_vampir_action_api.py с настоящим loopback HTTP и 50
synthetic sessions; 5 тестов очереди; 16 прежних live session / quest / diagnostics
тестов. Проверены токены, чужие session / origin, точные offers, повтор / подмена,
owner-only confirmation, отключение skip, смена мира и close после sent.
После unknown только owner с новым предложенным context может разблокировать
очередь; прежний receipt остаётся unknown. Проверен отдельный сценарий синхронизации.
Игрового сокета в этих проверках нет. Snapshot публикует action_queue / action_policy только
при установленном канале; interaction и source-bound message decoder ещё нужны.

Current QuestUpdate codec и typed outgoing frame проверены отдельно:
81 native тело / 29 коротких входов / 6 отказов записи, без игровых команд.
[Wire proof и границы](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-WIRE-11316.md).

До включения кнопок нужны: получение выбранной задачи /
диалога / инвентаря, подтверждённые обработчики каждого действия, owner-side
проверка непосредственно перед отправкой, API с существующей session-token
проверкой и журналом результата, затем обновление UI по серверному подтверждению.
Покупка / удаление / расход ценных предметов в generic «обучение» не разрешаются
автоматически. Неподдержанный этап должен показать точную причину остановки.

[Текущая связь массива задач и прогресса](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-TASK-LOOKUP-11316.md)
ещё не доказывает порядок QuestTask / selected state / выполнение маршрута.

## Переход из владельца сокета в typed outbound

`GameConnection.queue_quest_update` теперь ставит typed QuestUpdate в ту же
ограниченную очередь, которой пользуются heartbeat и смена ключа. Требует
accepted WorldMoveFinish (complete_world, finish_response, code 0) и точного
совпадения source SHA с этим world flow. Сырые packet bodies не принимаются.
Перед вызовом owner обязан отдельно подтвердить задачу, контекст и допустимость
действия; метод не выбирает квест и не устанавливает action contract.

`test_vampir_quest_connection.py`: 4 теста на настоящих локальных сокетах.
Вход в мир проходит synthetic wire цепочку 102/110/202/204/206. Проверены
отказ до 206, world refusal, закрытое соединение, чужой SHA, malformed payload,
key rotation перед QuestUpdate, последовательность пакетов, backpressure без
расхода sequence и два независимых владельца. Пакет 1810 декодирован на другой
стороне локального сокета и сверен с typed body. Это проверяет транспортный
переход, не серверное выполнение квеста.

Метод вызывается только явным кодом owner; production launcher/API/game pump
его пока не вызывают. Очередь намерений и этот typed переход ещё предстоит
соединить через подтверждённый selected-state handler и decoder результата.
Возврат метода означает постановку в outbound, не принятие сервером.
Текущий уже онлайн-owner не перезапускался и игровых команд не получал.

## Получение намерения и постановка QuestUpdate владельцем

`install_actions(..., connection=game_connection)` дополнительно привязывает
очередь к одному явному GameConnection той же source SHA. По умолчанию привязки
нет, старые read-only / API тесты не устанавливают игровой sender. После claim
owner может вызвать `dispatch_quest_action(key, request_id, context=..., payload=...)`.
Payload — typed QuestUpdate, полученный от будущего подтверждённого обработчика
выбранного шага; raw30 обязан совпасть с quest_id намерения. Индекс задачи,
цель и вектор этот метод не вычисляет и не допускает автоматически.

Под lock сессии повторно проверяются private owner key, connected/Stop,
точный offer, context, character/world scope, bound connection identity/world,
kind quest_follow, origin manual и payload. Выполняется только неблокирующий
append в outbound этого connection; socket.send здесь не вызывается.
HTTP не получает возможности передать payload/connection/contract или вызвать
этот метод. Auto quest continuation и остальные kinds через него не выполняются.

Очередь `queue_claimed` сохраняет execution fence во время append. Повтор
sent/terminal receipt возвращается без append. Известный отказ до append
(в том числе malformed payload и backpressure) — failed/not_queued. Неизвестная
ошибка — unknown и блокировка последующих действий. Текст исключения не попадает
в snapshot. Sent здесь означает принятие локальной outbound-очередью;
серверное подтверждение по-прежнему требует отдельного owner resolve.
Истечение executing до dispatch и close не разрешают позднюю постановку.
При close сессия освобождает ссылку на bound connection; жизненным циклом
самого сокета продолжает управлять его владелец.

`test_vampir_quest_dispatch.py`: 5 интеграционных тестов с реальными loopback
HTTP и локальными socketpair. Вход в synthetic мир проходит wire цепочку.
Проверены end-to-end body/sequence, повтор HTTP/dispatch без нового пакета,
отсутствие авто-confirm после локального приёма, чужой owner, stale context,
смена world/offer, рассогласование bound world, закрытое соединение,
неверный quest ID/NaN, backpressure, uncertain outcome после append,
expiry/close и два независимых owner/connection. Contracts и выбранный шаг
в этих тестах синтетические; сервер игры не вызывается.

Production launcher/loop пока не устанавливает привязку и не вызывает dispatch.
Нужны source-bound selected-state handler/offer builder и decoder результата.
Текущий онлайн-процесс остаётся на прежнем коде без перезапуска.

## Наблюдение QuestUpdateResult без автоматического подтверждения

`vampir_core.quest_update_result.decode_quest_update_result` принимает только
current source SHA и полное bytes-тело на 30 байт. Формат `<IQBBQQ` проверен
по whole native readers/writers, handler связывает qword с quest key, первый
byte со state, вложенный byte/counters с progress. State ограничивается до 6,
вложенный byte сохраняется; mutable/trailing/short input отклоняется.
[Wire proof](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-UPDATE-RESULT-11316.md),
[receiver proof](../resource-tools/vampir/knowledge/evidence/scenarios/HEADLESS-QUEST-RESULT-APPLICATION-11316.md).

Новый LiveSession наблюдает ID1811 только после публикации персонажа и при точном
совпадении character/world со snapshot. `quest_update_result` содержит последний
полный ответ: result_code, quest_id строкой uint64, state и progress raw08/raw10/
raw18 (оба qword строками), context и received_at_ms. Явные поля:
semantics=last_received_message, applied_to_local_task=false,
action_confirmed=false, correlation=not_established. Coverage quest_result
различает not_verified/not_received/last_received_message/decode_error.
Данные относятся к своей session; без source/context не принимаются.

Journal добавляет quest_update_result_received с code/quest/state/index либо
quest_result_decode_error. Raw body, auth и другие данные в запись не добавляются.
История ограничена существующими 256 событиями; последний ответ один. Ошибка
декодирования очищает предыдущий ответ, счётчик ограничен 2^53-1. Смена мира и
close очищают ответ. Устаревший context игнорируется, чужой результат не меняет
последний относящийся к session ответ. GET state/journal используют прежний API.

Ответ1811 не меняет список квестов из1854, не создаёт model/task/offer и не
вызывает resolve_action даже при code0. Code1197, допускаемый native gate
в одном режиме, также не объявляется успехом. Для confirmation нужны исходное
sent intention, точная корреляция и подтверждённая смена прогресса; сейчас их нет.

`test_vampir_live_quest_results.py`: 4 теста проверили portable decoder против
900 результатов текущего native replay, короткие/лишние/неверные типы/source,
50 synthetic sessions, точность uint64, независимость копий и HTTP state,
scope/source/world/close, ошибку после валидного ответа, журнал и сохранение
sent receipt/списка1854 без подтверждения. Регрессии прежних live quests,
action API/dispatch прошли отдельно. Игрового сервера в этих тестах нет.

Изменение доступно новым owner-процессам после обычного запуска. Уже работающий
owner не перезапускался и новые поля в нём не появились; observational analysis
не используется для подмены сетевого обработчика. Далее корреляция receipt и
выбранного шага, затем ограниченный игровой тест с сохранением условий сессии.
