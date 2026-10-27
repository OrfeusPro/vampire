# Login 1.13.18: общий пакет подготовки и обработки ответа

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Baseline SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверка offline: без credentials, сокетов, игровых команд и активации профиля.

## Единый перенос

`align-login-batch-11318.py` обрабатывает фиксированные 38 roots из 13 прежних
контекстов. Полные instruction/control shapes сверяются по двум полным SHA;
call/RIP references, таблицы и bounded leaves формируют явные соответствия.
Поиск ограничен ±64 KiB вокруг каждого старого root. Из трёх одинаковых UTF-8
wrappers выбирается только цель подтверждённого native caller. Близость адреса
и совпадение prefix сами по себе не разрешают перенос.

Для регистрации отдельно проверяется общий helper `1467CBB90`; registration
window `1467B51A4` связывает constructor `1456D7A70`, ID 4 и handler
`14679B390`. Его таблица и call inventory сверяются с текущим источником.
Constructor/reader LoginResult: `1456D7A70` / `1456DC520`.
Login prepare/constructor: `1467CE500` / `1456D7950`.
Post-state wrapper/target: `146755A10` / `144A2DBC0`.
Continuation constructor/reset: `1464A6920` / `1464ACDE0`.

Готовые exports общего input archive, Login constructor/prepare и gate
переиспользованы. Недостающие 21 root получены одним collect, общий register
helper — ещё одним. Полного обхода EXE / дерева callees нет.

Текущие exports в библиотеке ресурсов, относительно
`ghidra/request-exports/<EXE SHA>/`:

- `run-b66ea903e973/details.json`: 21 root пакета;
- `run-896228001291/details.json`: общий register helper;
- `run-ed5c8eee70bc/details.json`: общий input archive;
- `run-b92399af7eb5/details.json`: constructor/prepare;
- `run-450b89173dc1/details.json`: общий gate с inline data.

Каждый context закрепляет полные SHA нужных exports. Генератор сначала
вычисляет весь набор, затем записывает 13 новых source-specific JSON; прежние
контексты сохранены. Matching остаётся кандидатом до native replay.

## Исполненные сценарии

| Контекст | Проверенные случаи |
| --- | --- |
| Login prepare | 672 |
| Prepare с native SDK getters/leaves | 2016 |
| Prepare с native metadata pipeline | 448 |
| Metadata collector/selector/loader/writer/copy/move | 288 |
| LoginResult constructor/nested readers | 320 + 332 short + 25 failures |
| Result с native input | 320 + 332 short + 25 failures |
| Result с native UTF-8 | 160 + 332 short + 25 failures + 4 boundaries + 6 special |
| Result с actual buffer constructors | предыдущие 527 + 72 construction |
| Result → handler в одной VM | предыдущие 599 + 46 handler + 131 rejected |
| Handler с synthetic packet | 40 |
| Post-state wrapper и tail target | 44 |
| Actual continuation constructor/getter/virtual reset | 8 |
| Registration ID 4 | static window/table/call links |

Итого 6772 исполнения в перекрывающихся наборах; это не число уникальных
игровых ситуаций. 13 штатных suites содержат 52 теста, все прошли. Старые
регрессии сохранены, каждый suite также проверяет текущий SHA. Actual packet
после reader поступает handler без host переписывания полей; 131 неполный
вариант не вызывает handler/services/writes. Guards, ABI, порядок полей,
ownership/cleanup, SDK gates и отрицательные source/export/call checks
проверяются существующими verifier/test наборами.

Общий gate `1467CDC80` использует
[готовую проверку code/data и switch tables](HEADLESS-VERSION-RESULT-HANDLER-11318.md).
Остальные roots сохраняют whole-unwind validation. Для расширенных input/
handler композиций разрешены ровно объявленные 20/22 roots текущего SHA;
произвольного повышения бюджета нет.

Добавлены actual Login handler случаи `0x1197` при двух gate states.
При state 0 вызывается error service, затем происходят state writes и
post-state capture; при state 1 продолжение блокируется. Следовательно,
прохождение gate не равно успеху сервера. Portable parser policy не ослаблена.

Расширенный ручной unittest glob дополнительно захватил исторический
`test_vampir_login_context.NativeVersionDeviceInputTests`: его прежний replay
отказал с `Device source changed`. Он не относится к этим 13 зарегистрированным
наборам, не переносился и не засчитан как passed. SHA guard сохранён.

## Автоматизация и доказательства

Все 13 checks получили новый SHA, current contexts/exports и зависимости,
`on_update=true`. Их reviewed targets и два недостающих Login bindings
добавлены в граф контрактов. Наборы запускаются штатным обновлятором;
неизменившиеся зависимости используют его hash cache.

`test_vampir_login_batch_support.py` сохраняет подробный native report прямо
из зарегистрированной проверки в `knowledge/login-batch-verified-11318/`
библиотеки ресурсов. Отдельный replay ради файла доказательств не нужен.
Report содержит имя контекста, EXE SHA, полные SHA context/verifier и результат.

Alignment report в библиотеке ресурсов:
`knowledge/login-batch-alignment-11318/6df02dac3418645d33cc7f9cc69fd35c5115aa4fedb4a98542b52df4ec84c159/manifest.json`.
Первоначальный общий replay 13 контекстов (до добавления четырёх 1197 cases):
`knowledge/login-batch-native-candidate-11318/b4a1a1cf9b790c7ec2cbf4ade77bd33dbb88e2337e22284b5c33db1825762f6b/manifest.json`.

## Границы

SDK UserInfo/maps/variants/strings, storage/allocator/clock, network send,
post-state services, UI и реальная engine delivery остаются объявленными
fixtures. Post-state и continuation исполняются отдельно; внутри handler это
captures. Registration static, фактический dispatcher не исполняется.
Complex switch services вне покрытых ветвей не считаются проверенными.

Contract coverage остаётся partial: общей prepare→wire composition и реальной
SDK/backend/session проверки нет. SDK/GMC2/NID, текущий CharacterList/clock,
source-bound profile и онлайн ещё открыты. Старые квестовые результаты
1.13.16 не перенесены автоматически. Runtime, baseline и рабочие профили
не переключались.
