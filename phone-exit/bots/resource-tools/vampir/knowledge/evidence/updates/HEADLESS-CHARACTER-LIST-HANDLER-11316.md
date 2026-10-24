# CharacterListReadResult 1.13.16: регистрация и handler

24 октября 2026. Собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [целого reader списка](HEADLESS-CHARACTER-LIST-RECORDS-11316.md).
Здесь packet/records synthetic; reader и handler ещё не объединены одним replay.

## Привязки

Окно `1467b52b0..1467b52fb` внутри owner `1467b4c60` выделяет handler/packet,
задаёт handler table `149dc67e0`, вызывает packet constructor `1456d7220` и
регистрирует пару через `1467cb6c0`. Table slot `+10` → handler `146796360`.
Packet table `149928a48`, slot `+28` → actual getter `1456e4c10` → ID 102.
Source bytes, instructions, аргументы и table links проверяются; oversized
registration owner целиком не экспортируется и не исполняется.

Новый export — `run-afee1165a63c`, один handler. Gate `1467cd7b0` и predicate
`145c9ad90` использованы из готовых `run-eff5f37ca91c` / `run-6034b73830e4`.
Peer getter `144ab0c40` и setter `144ab1530` исполняются native: setter пишет
DL в `[peer+10]+2a6`. Global pointer задаётся synthetic peer, не объектом игры.

Отдельно проверен запрос списка: constructor `1456d7200`, table `1499289e0`,
actual ID getter `1456e4c00` → 101. Writer slot `+10` → `140bb4a10`,
три source bytes `b0 01 c3`: AL = 1 и RET. Native вызов не изменяет packet/archive;
constructor ставит packet byte `+a = 0`. Это пустое тело запроса, не TCP send proof.

## Ветви handler

Handler передаёт result из packet `+10`, ID 102, нулевой temporary и policy 0
в actual gate. При отказе вызывает service virtual `+38` с аргументом 0;
service — fixture, сетевое закрытие этим не доказано.

При успешном gate вызывается actual predicate. Только raw policy 1 доходит до
публикации списка. Disabled global и отсутствие policy object дают fallback 4.
Имена enum для этих raw policy values не установлены.

На проверенной ветви публикации:

- Vector из packet `+18` переносится в state `+70` через bounded reserve/copy.
  Code 0 сам по себе не означает пустой список или обновлённый кэш.
- Packet `+30` копируется в state `+80`, low32 packet `+28` — в state `+84`;
  full raw64 `+40` передаётся отдельному setter capture.
- Signed-negative raw64 `+28` вызывает SDK diagnostic capture и не отменяет
  последующий общий переход. Значению не назначена семантика по одному offset.
- Preferred raw64 `+38` сравнивается с sentinel 0; ненулевое значение ищется
  среди record raw64 `+8`. Выбирается первый match, иначе index 0.
- При наличии controller index сохраняется в `+3f8`; его отсутствие не отменяет
  публикацию списка. Для пустого списка native также сохраняет 0, тогда как
  portable `preferred_character_index` возвращает None. Index 0 не доказывает
  наличие персонажа и не разрешает создание.
- Выполняются общие backend captures, mode 6 и actual peer flag reset в 0.
  Mode 6 одинаков для empty/nonempty в исследованной ветви. Backend/экран и
  отправка CharacterCreate здесь не исполнены.

## Проверки и границы

101 сценарий: result 0/1/42/58/ffffffff × gate state 0/1 × raw policy 0/1/2/4
× пустой/непустой список; дополнительно ошибки 14/22/37/54/9400/9818/9819/90021,
preferred sentinel/first/last/missing/duplicate/high-bit values, отсутствие controller/
policy, disabled global, owner callback и signed raw28.
15 сценариев публикуют данные. Ошибки/неподходящая policy не меняют state fields,
index и peer flag. Проверены ABI, packet immutability и state/controller guards.

Fixtures: packet/record/type objects, getters, strings/log/SDK, state reserve/copy/
cleanup, controller/UI/owner/effect/flow/exit backends. Видимый UI отсутствует.
Нативные allocator/copy lifetime, dispatcher, реальные services и живой сервер
не доказаны. Пустоту для бота нужно брать из свежего полного принятого ответа,
а не из нулевого кэша или controller index после отказа.

## Воспроизведение и обновление

[Context](../../native-contexts/character-list-handler-11316.json),
[verifier](../../../verify-character-list-handler-context.py),
[три теста](../../../../../test_vampir_character_list_handler_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_list_handler_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-character-list-handler-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/character-list-handler-11316.json
```

Report: `F:/PhoneExit Resources/Vampir/knowledge/native-character-list-handler-checks/50bb48269e0a5ad0bc2c533ef153253172263e5f4f3762222766ce3a3bbbedfd/manifest.json`.
Check `native-character-list-handler-context` связан с `character-list`.
Для патча проверить registration/table/ID, gate/predicate, preferred scan,
state stores и peer setter; unsupported branches оставлять в ручной очереди.

Далее — source-bound профиль для отдельной живой проверки, необходимые clock/
transport checks и source checks создания. Профиль/baseline не активированы;
Game Login, свежий список и создание этим offline replay не выполнялись.
