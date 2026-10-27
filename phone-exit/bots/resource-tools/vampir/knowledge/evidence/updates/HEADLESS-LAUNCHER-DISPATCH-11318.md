# Launcher 1.13.18: передача результата в асинхронную очередь

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [response references](HEADLESS-LAUNCHER-RESPONSES-11318.md)
и [result getters](HEADLESS-LAUNCHER-RESULT-GETTERS-11318.md).
Профиль и авторизация не включались.

## Whole dispatch и temporary cleanup

Whole функции 1444E57F0 (token) и 1444E6AC0 (sign-in), по 120 инструкций,
вызываются из соответствующих response callbacks. В новом replay они
исполняются вместе с whole temporary cleanup1444C59F0 (48 инструкций).
Проверены source bytes, block/direct-flow coverage, conditional fallthroughs
и нормализованные полные формы существующим валидатором.

| Route | Saved delegate в owner | Queue callable |
| --- | --- | --- |
| token | +188 | 1444DEC90 |
| sign-in | +98 | 1444DEF50 |

При пустом saved delegate dispatcher дважды вызывает копирование delegate,
выделяет payload0x30 и записывает:

| Payload offset | Значение |
| --- | --- |
| +0 | Source vptr149538388 |
| +8 | Owner pointer |
| +10/+18 | Delegate pointer/count, здесь 0 |
| +20 | Result pointer |
| +28 | Shared control pointer |

Вызывается queue helper141409D30 с RCX=1 и stack callable, содержащим source
callback и payload pointer. Fixture очереди проверяет все поля и явно забирает
payload, очищая локальный callable. Затем исполняется настоящий temporary
cleanup1444C59F0, а не подмена его refcount эффекта.

## 16 проверок

Матрица: обе routes × result pointer null/non-null × control null/refcount1/2/7.
Для non-null control native instructions увеличивают strong count дважды:
для временного объекта и для queue payload. На входе queue проверяется N+2.
Actual cleanup уменьшает счётчик до N+1, сохраняя очередь владельцем ссылки
после возврата dispatcher. Контрольный release очереди выполняет сам тест,
возвращая N; это не исполнение engine consumer или destructor.

Сравниваются owner0x200 байт, input pair16 байт и opaque result0x40 байт:
они не меняются. Порядок: две копии пустого delegate → allocation → queue
ownership transfer → native temporary cleanup. Hook на cleanup только наблюдает
его аргументы и не меняет RIP/RAX/память.

Обе функции проверяются целиком, но saved delegate пуст, diagnostics выключены,
allocator успешен. Ветки непустых delegates, их уничтожения и logging не
исполнялись. Non-null result с null control — synthetic input, не утверждение
о реальном server result lifecycle.

## Источники и воспроизведение

| Экспорт | SHA256 |
| --- | --- |
| run-fcd0aa6ac1ac | b84631a01e8c4b0cd4a961bd943315d763096114daba4582eca82e4c96426fa3 |
| run-d9172c33c6b8 | ac9cff086151c3c3025feb7b738d02dd6aabb5c47feea45a1744bc7b913a4cfe |

Первый cleanup collect был отклонён: decompiler вышел за unwind ranges на
E9 по1444C5A8B →141483080. Новое задание явно включило target141483080,
collector применил штатную CALL_RETURN модель. Границы не расширялись, EXE
не менялся. Free root экспортирован для модели, но в replay не исполняется;
его boundary запрещает неожиданное освобождение в пустом delegate режиме.

Tool `replay-launcher-dispatch-11318.py`, тест
`test_vampir_launcher_dispatch_11318.py`, check `launcher-dispatch-11318`.
Артефакт:
`code-clues/launcher-dispatch-11318/6cc8f75ec78565cc297698f5df6a4760bfabc123523404d6b98e7bae1fe01d0b/manifest.json`.

## Границы и следующий шаг

Delegate copy, allocator и queue ownership transfer — fixtures. Доставка
callable движком, consumer1444DEC90/1444DEF50, nonempty delegates, destructor,
response callbacks, JSON/HTTP и настоящий SDK context здесь не исполнены.
Opaque result не разбирается. Native refcount удержания не доказывает доставку
или успех входа. `native_execution=true`, `network_used=false`,
`profile_activation=false`, `compatibility=not_established`.

Далее связать whole response callbacks/HTTP/errorCode gates с проверенными
getters и dispatch, затем SDK context/engine writers и профиль нового SHA.
Квестовые команды и повторная авторизация не выполнялись.
