# Полный LoginResult handler: правило обновления и автоматическая проверка

30 октября 2026. Целевой источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Исходные reviewed роли импортированы из 1.13.18
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Доказательства, квитанции и замеры](AUTO-LOGIN-FULL-11322.json).

## Область результата

`login-full-v1` исполняет два native roots: целый LoginResult handler и общий
result gate, а также native leaf ID 4. Пакет 352 байта и восемь строк создаются
синтетически. Native reader этим пакетом не исполняется. SDK, UI, clock,
storage, predicate/apply, post-state и continuation представлены явными fixtures;
их реальные effects и успешный игровой вход остаются отдельными доказательствами.

48 сценариев покрывают 40 service / success / error / early-return сочетаний
и восемь новых сочетаний trailing predicate × allocated temporary × poison.
Проверяются точные events с call sites и аргументами, записи в state/controller,
derived values, source buffers, canaries, GPR / XMM6–15 / RSP. При false predicate
native handler создаёт пустой temporary; allocation в apply — ограниченная fixture.
Настоящее освобождение сервиса этим не доказывается, его вызов и аргумент проверяются.

Два субагента подготовили правило и verifier / независимый контракт; дополнительная
сверка сопоставила прежние 40 outcomes и новые восемь веток с инструкциями.
Координатор подключил driver, реестры, зависимости, кэш и выполнил приёмку.

Первый native проход отклонил новый verifier: guard popup ошибочно сравнивал R8D
с result code. Инструкции используют source-bound UI selector, загруженный из RIP
у handler +289; +353 передаёт его в R8D. Guard исправлен по данным PE и stack
objects, добавлена regression-проверка. Исходный неуспешный журнал сохранён;
после исправления создана новая tools identity и новое native доказательство.

48 случаев прошли до публикации. Кэш затем ошибочно принял semantic labels
`source="packet"` / `"empty_temporary"` внутри событий за пути EXE. Исправление
сохраняет безусловную проверку path при собственном `source_sha256`; при
унаследованном SHA путями считаются path-like строки. Тесты проверяют labels,
подмену absolute / relative / drive / URI / EXE путей и неизменность SHA guards.
Публикация продолжена с готовым native report без повторного native исполнения.

## Правило переноса

Handler22 изменился: 356 инструкций, 1557 байт, 85 calls, четыре новых вызова
в trailing-ветке. Разовый импорт из reviewed18 проверяет идентичность ролей
81 прежнего вызова и новый явный instruction slice predicate / apply / free.
Это не утверждение о неизменности всего handler18. Новый source-bound native
report обязателен. Уже проверенные current early-handler, gate и packet contexts
с reports служат независимыми входами.

Для следующего патча базой становится полный проверенный current handler.
Сверяются все инструкции и ветвления с relocations, code/data gate boundaries,
calls / aliases, RIP / literal / table inputs, packet ID table и named memcpy thunk.
Fixture boundaries учитываются отдельно от исполнения их логики. Изменение layout,
неоднозначность, повреждение доказательства или зависимость без report дают блокер.

Семейство зарегистрировано в [native-check-adapters.json](../../native-check-adapters.json)
и подключено к `update --auto`, resumable journal и publication cache.
Указатель публикации: `generated-login-full/index.json` в библиотеке ресурсов.
Новые tools закреплены полными SHA; прежние proof engines и reports не переписаны.
После изменения реестра первый общий проход обновляет publication receipts,
повтор использует их с проверкой целостности источников и lineage.

Зарегистрированный общий набор: 522 тестов passed; новые 48 native случаев прошли.
Два повтора семейства не запускали native / JVM; последний использовал 3 этапа и одну publication receipt, 7.086661 с.
Первый общий проход 24 drivers: 248.277842 с; тёплый: 49.789689 с.
Оба использовали 72 готовых semantic stages без native replay и JVM.
Тёплый проход: publications reused 24, полных publish/transfer 0, PE rebuild 0.
Две функции взяты из одного готового export: missing 0, Ghidra не запускался.
Byte SHA 30 инструментов / contexts совпали с результатом Git checkout.
Замеры относятся к выбранным drivers; глобальная сверка исторического индекса учитывается отдельно.

## Что остаётся

Нужно соединить reader352 / 28 операций с handler над тем же packet, затем
подтвердить registration owner/window. Отдельные gate, post-state и continuation
reports используются как готовые зависимости; их композиция не подразумевается.
Clock / heartbeat, world, настоящий SDK backend и полный онлайн-вход остаются
открытыми. Этот offline пакет не выполнял авторизацию, игровые команды,
назначение профиля и не менял текущую сессию.
