# Launcher 1.13.18: response callbacks → dispatch → cleanup

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [асинхронной передачи результата](HEADLESS-LAUNCHER-DISPATCH-11318.md).
Профиль 1.13.18 и авторизация ещё не включены.

## Исполняемый путь

Whole token callback1444CC4B0 (551 инструкция) и sign-in callback1444D3A30
(762 инструкции) теперь вызываются в одной VM с настоящими dispatcher
1444E57F0/1444E6AC0 и temporary cleanup1444C59F0. Whole bytes, unwind fragments,
block/direct-flow и conditional fallthroughs проверяются прежним валидатором.
Fixture очереди получает payload, записанный native dispatcher; временную
ссылку снимает native cleanup. Доставка callback движком не предполагается.

В дополнение к двум exports из предыдущего proof используется:
`run-e3abc26162e7/details.json`, SHA256
`0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42`.

## 74 сценария

На каждую route приходится 37 случаев:

- 4 ранних выхода: shutdown, отсутствующий weak control, его strong count 0,
  отсутствующий owner pointer;
- нет response, response доступен только через второй predicate, invalid JSON;
- 30 сочетаний: HTTP199/200/206/207/400 × errorCode absent/0/7 × resultData
  absent/present.

Проверяется настоящий порядок ветвлений и аргументы result constructors
(сами constructors — fixtures):

| Причина | Category | Stage token / sign-in |
| --- | --- | --- |
| Оба response predicates=false | 0x1315410, исходный HTTP status | 4 / 10 |
| Invalid JSON | 0x262F640, исходный response pair | 5 / 11 |
| Ненулевой errorCode | 0x1CA86D0, SDK error | 6 / 12 |
| HTTP вне 200..206 при absent/zero errorCode | 0x1CA86D0, HTTP status | 6 / 12 |
| Token HTTP допустим, resultData отсутствует | 0x262F640 | 5 |
| Token HTTP допустим, resultData присутствует | 0, getter value | 0 |
| Sign-in HTTP допустим, absent/zero errorCode | Дальше передаётся исходный response | Не создаётся новый result |

Допустимый диапазон следует из native unsigned comparison; replay проверяет
его границы 200/206 и отказы199/207/400, а не каждый внутренний HTTP code.
Ненулевой SDK error имеет приоритет над HTTP status, включая HTTP200/206.
При раннем выходе нет result allocation или dispatch. Во всех остальных
случаях ровно одна передача в очередь. Weak owner strong count возвращается
к исходным 2 или 0. Для нового result после callback остаётся ровно одна strong
ссылка очереди; её контрольный release выполняет тест, destructor не заявлен.

Результаты token: 4 early, 1 transport, 6 invalid-json/result, 22 error,
4 token. Sign-in: 4 early, 1 transport, 1 invalid-json, 22 error, 9 original.
В частности, sign-in при отсутствующем resultData всё равно доходит до
передачи исходного response после SDK boundary calls. Это не доказательство
наличия identity или успешного входа.

## Значимые ограничения

HTTP predicates/status/body, JSON parser/field existence/getters, string
operations и result constructors — fixtures. HTTP input control=null,
saved delegates пусты, allocator успешен, diagnostics выключены.
Conversion IAT14899BBB0 проверен по PE как
`api-ms-win-crt-convert-l1-1-0.dll!_wtoi`, затем перенаправлен только в
эмуляторе на bounded fixture для строк 0/7. CRT conversion не выполнялась.

Token getter возвращает пустой FString, который native callback может
передать в success constructor. Строгая политика portable parser не ослаблена:
успешный stage 0 не доказывает непустой токен или авторизацию сервера.
Sign-in nested object не имеет identity fields; SDK singleton/state/event
helpers также fixtures. Они позволяют пройти whole callback, но не доказывают
изменение настоящего SDK context или его свежесть. Предыдущие
[native getter checks](HEADLESS-LAUNCHER-RESULT-GETTERS-11318.md) остаются отдельным
результатом; в эту композицию их storage/type gates ещё не включены.

## Воспроизведение и следующий шаг

Runner `replay-launcher-dispatch-11318.py`, вызов `run(with_responses=True)`;
helper `launcher-response-cases-11318.py`; тест
`test_vampir_launcher_response_callbacks_11318.py`; check
`launcher-response-callbacks-11318`. Прежние 16 dispatcher cases также выполняются.
Оба unittest прошли. Артефакт:
`code-clues/launcher-response-callbacks-11318/d142e76cf19331fca4abbb2a3fc30ff0251ae19ed1a776c2b42a123c823c6ae2/manifest.json`.

`native_execution=true`, `network_used=false`, `profile_activation=false`,
`compatibility=not_established`. Никаких credentials или настоящих tokens
входами не были. Далее actual JSON/getter composition и identity/token/SDK
context, engine writers и подготовка проверенного runtime profile нового SHA;
engine delivery, nonempty delegates и destruction требуют отдельной проверки.
