# Полные обработчики launcher response в 1.13.18

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Baseline EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request `466d7ddfcef1114e340614e2dc504e4cfdf735f9593260096d6ecd090f60b777`.
Продолжение [request key/callback references](HEADLESS-LAUNCHER-REFERENCES-11318.md).

Current export run-e3abc26162e7 SHA256
`0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42`.
Baseline run-aa8c16b9c37f SHA256
`68a258e1f298e7e607337b366ef673deb7af1fece47a33bf24442fbc9647cd0e`.

| Response | Baseline | Current | Инструкций | Direct calls | RIP refs |
| --- | --- | --- | --- | --- | --- |
| launcher/token | 1444CC1B0 | 1444CC4B0 | 551 | 57 | 27 |
| launcher/sign-in | 1444D3730 | 1444D3A30 | 762 | 125 | 26 |

Целые functions экспортированы, bytes и все unwind fragments сверены
существующим валидатором формы. Внутренние branch targets сравниваются по offset,
не маскируются без контроля. Данные и внешние direct targets сохраняются парами.
После учёта импортов обе полные формы совпали.

## Косвенный CRT import

Прямое сравнение сначала обнаружило по одному несовпадению текста RIP-relative
косвенного вызова. Внешний адрес здесь не заменяется без проверки:
PE import table в обоих EXE связывает slot с
`api-ms-win-crt-convert-l1-1-0.dll!_wtoi`. Проверяются DLL/name и фактический
RIP-relative CALL, а не предполагаемая одинаковая разница адресов.

В новом EXE обе инструкции используют slot14899BBB0:
call1444CC8C6 (offset1046 от token response),
call1444D3E58 (offset1064 от sign-in response).
Для shape edge сохраняется identity импорта; остальные косвенные вызовы
сравниваются прежним способом. Ровно один такой import call на функцию обязателен.
CRT conversion не исполнялась; входная строка и обработка её ошибок не проверены.

## Ссылки разбора и передачи результата

Обе функции ссылаются на global14B563DA0/14B563DF0, соответствующие прежним
errorCode/resultData. Current initialization этих двух labels ещё не включена
в отдельный key audit; поэтому numeric references не подменяют проверку значений.
Token response вызывает getter14447D460 и dispatcher1444E57F0;
sign-in response — getter14447D210 и dispatcher1444E6AC0.
Наличие вызовов закреплено по whole instructions, но их исполнение/аргументы
на всех путях и содержимое JSON не установлены. Также видны проверки lifetime
owner и внешних response predicates; они не объявлены проверенными native ветвями.

Tool `audit-launcher-responses-11318.py`, тест
`test_vampir_launcher_responses_11318.py`, check `launcher-responses-11318`.
Артефакт: `code-clues/launcher-responses-11318/fb9a061901ba15cd611932259a86203a250c3f1fd236497826b90a9beb1055f4/manifest.json`.

## Границы и следующий шаг

Static source comparison, native_execution=false, network_used=false,
profile_activation=false, compatibility=not_established. Внешние callees/data
не признаны эквивалентными по одной форме callback. Ответы сервера, headers,
actual response JSON, SDK/GMC2 context и транспорт не исполнялись.

Далее source key initialization errorCode/resultData, whole getters/dispatch
и transport, затем ограниченная native цепочка и подготовка отдельного профиля.
Прежняя сессия не перезапускалась; новая авторизация не выполнялась.
