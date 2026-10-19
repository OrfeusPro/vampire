# Response errorCode: native variant → string → _wtoi

19 октября 2026. Продолжение [response gates](HEADLESS-SDK-RESPONSE-GATES.md).
Источник — собранный Windows EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это код клиента, не исходный C++ проект.

Инструмент `replay-sdk-response-variant.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-response-variant-replay.json`,
SHA256 `38b0cca6470ad5c61280dbd2701c07a6940f8327d46272d52cfbd17b6ff18496`.
Report ссылается SHA на response gate evidence, сохраняет converter/factory/
virtual target fragments, bytes/file offsets/SHA, vtable bytes и tool SHA.

## Заменённая граница исполнения

В прежнем replay `0x144476940` целиком возвращал fixture FString.
Теперь он исполняется native вместе с `AsString` wrapper `0x1415e48f0` и
реальным virtual `TryGetString` `0x1415ef250`, затем исходный caller вызывает
реальный local Windows CRT `_wtoi` через прежний verified IAT bridge.

Underlying variant objects и их выбор **ещё fixtures**. JSON fixture parser
сохраняет numeric spelling; actual native JSON reader не исполняется.
FString assignment `0x14143c260` — bounded copy fixture; allocation/free как ранее.
Refcount block задаётся null, destructive reference lifecycle не исследуется.

## Source-bound string и number-string representations

| Representation | Source factory | Type tag | Vtable | Slot+0x58 |
| --- | --- | --- | --- | --- |
| String | 0x14446eed0 | 2 | 0x1489cf248 | 0x1415ef250 |
| Number stored as text | 0x14446eff0 | 3 | 0x1489cf398 | 0x1415ef250 |

Vtable pointers происходят из decoded factory LEA/stores; type tags также
записываются этими native factories. Source factories экспортированы статически,
сами factories не исполнялись. Fixtures используют соответствующий tag/layout,
FString по object+`0x10` и настоящий vtable из EXE.

Для tag2 converter вызывает native AsString wrapper →virtual slot 58.
Для tag3 он пробует native virtual slot 58, получает true и переносит FString.
Сам TryGetString копирует object+0x10 в output и возвращает true.
Numeric double fallback/форматирование и bool/null/array/object ветви не исполнены.

Таким образом, доказана конверсия **выбранных представлений**, а не утверждение,
что любой JSON number в живом ответе всегда получает именно этот класс.
Полный source path parser → value factory остаётся отдельной зависимостью.

## Десять caller fixtures

Восемь числовых JSON literals сохранены fixture parser как number-text с tag3,
затем настоящий converter/virtual call и `_wtoi` дали:

| Исходный numeric text | _wtoi result | Native gate outcome |
| --- | --- | --- |
| 0 | 0 | player field slice достигнут |
| 1 | 1 | nonzero_errorCode |
| -1 | -1 | nonzero_errorCode |
| 0.1 | 0 | player field slice достигнут |
| 1e3 | 1 | nonzero_errorCode |
| -0 | 0 | player field slice достигнут |
| 0e2 | 0 | player field slice достигнут |
| 2147483648 | 2147483647 | nonzero_errorCode |

Строковые JSON `"0"` и `"oops"` используют tag2, сохраняют исходный текст,
дают 0 в CRT. Это compatibility observations в Windows fixture domain.
Не считать дробный/malformed numeric text корректным server response и не
переносить permissive _wtoi в новый runtime как универсальную success policy.

## Состояние и далее

Уменьшена граница подстановки: теперь converter и virtual value conversion
реальные. Полный JSON parser/type selection остаётся открытым. Ранее найденные
network/JSON/field fixtures и остановки callback сохраняют прежние ограничения.
Реальные login POST/accounts/tokens/registry/Saved/process memory не использованы.

Следующее: idpInfo и финальный success callback/SetSignIn, затем привязка
SDK token/player к game Login; остальные variant/parser branches не забыты.
Схема ответа пока не считается полным runtime authorization boundary.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_response_variant.py' -v`.
Три regression tests проверяют source/vtable bindings, 10 native caller outcomes
и различие JSON string/number-string tags.
