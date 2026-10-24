# Metadata внутри целого Login 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Готовые пять exports использованы повторно; Ghidra не запускалась.
На одном Unicorn harness с общим allocator исполняются целые Login prepare /
constructor, три SDK getters, шесть leaf getters и цепочка metadata из шести roots.
Это 11 явных unwind roots и шесть явных leaf bodies. Лимит 16 roots не расширен.

## Интеграция

Fixture готового результата `14560b0d0` удалена в новом контексте. Реальный
Login caller передаёт aux handle и адрес временного FString в collector.
Collector вызывает loader → UserInfo copy/move → writer → selector, затем
возвращается в caller. Наблюдение на return boundary читает результат, не меняя
его. Caller копирует этот же текст в поле `Login+d8`. Сравниваются наблюдение,
независимо рассчитанный ожидаемый текст и поле пакета в send boundary.

Обе цепочки используют один SDK manager: metadata seed не подменяет global
manager pointer или handles. Optional DeviceKey определяется тем же `manager+38`,
что и основные Login SDK-поля. Поэтому при наличии aux handle и отсутствии
main handle metadata собирается без DeviceKey, а поля `+30` / `+a0` остаются пустыми.
При отсутствии aux handle collector не вызывается и `+d8` пусто.

Общие строковые / SDK fixtures диспетчеризуются только внутри реального вызова
collector. После его возврата восстанавливается прежнее поведение границ Login;
до send и post-send SDK-вызовов active marker уже снят. Сохраняются проверки
отдельных native SDK getters, native entry counts и всего caller lifecycle.

Память UserInfo/control/settings выделена отдельно от owner/handles/cache SDK.
Временные строки, map buffer и пакет используют общую таблицу владения памятью;
проверяются canaries, repeated free, сохранность inputs и отсутствие утечек.
Только persistent member SDK `+58` остаётся во владении SDK, как в прежней проверке.
Shared allocator допускает до 8 192 байт на одну allocation только в новом
metadata-контексте (для map buffer); общий scratch/heap бюджет не изменён.
В прежних Login-контекстах предел остаётся 2 048 байт.

## Матрица

448 сценариев: 14 прежних SDK/platform branches × пустые/Unicode caller inputs
× send 0/1 × 8 metadata сценариев. Selector фиксирован 3, cache warm, poison 55;
их другие варианты остаются в прежних самостоятельных caller/SDK проверках.

Восемь metadata сценариев: backend отсутствует; shared object отсутствует;
готов с заполненным UserInfo; готов с пустым UserInfo и marketing;
готов с пустыми gates и marketing; две strong ссылки с Unicode/кавычкой и marketing;
две weak ссылки с пустым NID; unmanaged backend с пустым channel type и marketing.
Маркетинговые поля всё равно подавляются, если основной UserInfo недоступен.

Проверены фактический вход в collector, его отсутствие при SDK gate, 27 selector
вызовов при доступном UserInfo, поля и refcounts pipeline, metadata `+d8`,
остальные поля Login, порядок send/post-notify/event/destructor, общий cleanup
и сохранение восьми nonvolatile регистров / RSP. Пустые caller inputs не заменяют
готовую metadata пустым результатом: эти источники проверяются независимо.

Самостоятельная metadata-проверка после выделения session API сохраняет 288
сценариев, включая полный перебор её optional/marketing/poison вариантов.
Прежние SDK 2 016 и caller 672 сценария также проходят.

## Границы и обновления

SDK backend/settings/UserInfo и getters writer, map/hash/lookup/variant/string
primitives, allocator/destructor/send/post-event остаются fixtures. Реальные SDK
values и JSON escaping не доказаны. Platform/selector, NM provider и прочие
неподключённые зависимости Login также сохраняют прежние границы.
Native writer/archive/result reader ещё не включены. Нет сети, авторизации,
изменения default preset, ключей, аккаунтов, baseline или активации runtime.

[Контекст](../../native-contexts/login-prepare-metadata-11316.json),
[квитанция](LOGIN-PREPARE-METADATA-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_prepare_metadata_context.py
```

Три новых теста прошли за 19,477 секунды, включая общий replay и отказы при
подмене metadata SHA, collector root и callee. Это время этого набора, не всего
обновления. Отдельная metadata-проверка после refactor прошла за 16,272 секунды.

`native-login-prepare-metadata-context` подключён к game-login/update. Кэш учитывает
оба verifier, SDK fixtures, контексты, harness/runtime/тесты и пять exports.
При следующем SHA переносить не только внешние roots, но и объявленные callees,
UserInfo offsets/gates, manager layout и общую проекцию в `+d8`. Неподтверждённые
связи остаются в очереди; game-login остаётся partial, runtime promotion запрещён.

Следующий этап — реальные SDK/UserInfo/string/map/variant boundaries,
интеграция native writer/archive и текущий result reader. Готовые exports не повторять.
