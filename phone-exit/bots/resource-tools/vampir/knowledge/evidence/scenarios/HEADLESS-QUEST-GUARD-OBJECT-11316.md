# Источник объекта внешней проверки смены окружения

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `6d0e771bbefd4d0323933f0fa520109f04be17f93504924e72f4d7c1f587bbbf`.
Новый export run-d3cea0b3b866; полный SHA закреплён в
`knowledge/native-contexts/quest-environment-update-11316.json`.
Продолжение [writer и retry](HEADLESS-QUEST-ENVIRONMENT-UPDATE-11316.md).

## Whole getter 1445D2A20

Writer 14560F9E0 вызывает getter с RCX=0. При ненулевом аргументе getter
сразу читает pointer context+158 и возвращает его. При нулевом аргументе:

1. Читает global 14B559008. Если он null, переходит к fallback 1445C32B0.
2. Для ненулевого global получает ожидаемый class descriptor через 143BEFC30,
   читает descriptor объекта через object+10 и сравнивает signed depth+38.
   Затем проверяет pointer в parent array по objectClass+30 и индексу expected+38
   на равенство expected+30. Несовпадение направляет в тот же fallback.
3. При совпадении получает token по globalObject+11F8; fallback даёт свой token.
   Нулевой fallback завершает поиск с 0.
4. Token передаётся в 143C1BAC0. При ненулевом результате возвращается pointer
   resultContext+158, иначе 0. В последнем поле тоже может быть null.

Это проверенные адреса/поля, не установленные имена классов UE. Объект результата
пока не называется world, actor или controller по предполагаемому назначению.
Writer проверяет его virtual+7B8; реализация этой проверки ещё неизвестна.
В тестовом коде прежнее аналитическое имя world сохранено для scratch-переменной.

## Native replay вместо getter fixture

Целый getter добавлен в общий replay writer/retry/readiness. Прежняя подстановка
самого getter удалена. В 36 direct/retry случаях writer проходит настоящий getter:
missing означает null global и null fallback; deny/allow используют native typecheck,
загрузку +11F8, resolution и чтение context+158. После этого virtual+7B8 остаётся
receiver-checked fixture. 12 phase cases сохраняют отсутствие вызова getter.

Дополнительно 9 whole-getter случаев:
valid global; null global с fallback; недостаточный depth; другой parent pointer;
null fallback; null resolver result; null context+158; явный context; явный context
с null +158. Проверены результат и точная последовательность вызовов.
Несовпадение класса вызывает fallback, а не автоматически запрещает результат.
Явный context обходит global/class/fallback/resolver.

Итого прежние 48 случаев и 9 новых проверок getter прошли.
Артефакт: `code-clues/quest-environment-update-11316/ef8e9305ba28fa9bae14ece7348b8ce3389704ef71b2630ed2a6a83afa93bae9/manifest.json`.
Tool: `replay-quest-environment-update-11316.py`;
тест: `test_vampir_quest_environment_update_11316.py`;
check: `native-quest-environment-update-11316`.

## Fixtures и оставшееся неизвестное

Class descriptor provider, fallback token provider и context resolver — fixtures;
объекты/descriptor chains/parent arrays/context+158 — synthetic память. Сам getter
выполняет все ветвления и чтения. Active engine globals и реальные типы не получены.
Model lookup, registration, virtual+7B8 guard, empty text/formatting, phase request
и callback sink сохраняют прежние ограничения. Callback 145606830 не исполняется.
`network_used=false`, `action_admitted=false`.

Поиск pending+44 не завершён. Candidate1456137A0 экспортирован, но его receiver
ещё не связан с этим окружением; совпадение смещения не допускает его в replay.
Методы source environment vtable+90/+98 (145612FE0/145612FA0) экспортированы:
форматируют диагностическую строку и передают phase=5 в145618B30. Прямого store+44
в этих двух функциях нет; их реальные side effects зависят от phase handler.

Далее нужны producer pending+44, source virtual+7B8 и callback применения.
Затем — активные условия, selected task и actor position для реального offer.
Живая сессия не перезапускалась; игровые команды не отправлялись.
