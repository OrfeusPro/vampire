# LoginResult 1.13.16: post-state wrapper и отдельный хвостовой callee

Источник: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [общей reader/handler цепочки](HEADLESS-LOGIN-RESULT-BODY-HANDLER-11316.md).
[Контекст двух функций](../../native-contexts/login-post-state-11316.json).

## Причина отказа выгрузки и решение

Wrapper `146755540` имеет PE unwind range `146755540..1467555a4`, ровно
100 bytes. Он заканчивается исходным E9 `146755599 → 144a2d8c0` после
восстановления stack/RBX. Target — отдельный unwind root, 386 bytes.

Сначала target выгружен отдельно в `run-41aca37e5552`. Определение его как функции
не устранило поглощение тела декомпилятором: попытка wrapper `run-5f80b4f65c04`
снова отвергнута как block вне unwind, как и прежний `run-aaeae96c7f8b`.
Неудачные материалы и логи сохранены. Очередь не обходилась повтором того же
задания: после изменения модели подготовлен новый request.

Collector теперь передаёт `requested_tail_calls` только для проверенного E9
на другой явно указанный unwind root того же задания. Локальные/условные/
косвенные переходы и неуказанные targets не переклассифицируются. Ghidra
сверяет bytes и displacement, наличие отдельной целевой функции и применяет
`FlowOverride.CALL_RETURN` как **analysis metadata**. Native bytes не меняются.
Запись модели попадает в export; ограничения unwind blocks сохраняются.

`run-c0c472fc6e1c` успешно экспортировал только 100-byte wrapper, с полным block
coverage и записью модели хвостового вызова. Target export использован повторно.
Native replay исполняет настоящий E9 и RET callee, а не Ghidra flow override.
Бюджеты roots/инструкций/памяти не увеличивались; обхода дерева вызовов нет.

## Native проверка

Исполняются wrapper, target и 8-byte singleton getter `144a27d00`, читающий
`14b590c48`. Память singleton/service, class tables и actor синтетическая.
Lookup, predicates, assignment, backend helpers и virtual methods — fixtures.

44 сценария покрывают:

- отсутствие actor, class index/count и несовпадение class entry;
- service bytes `+260/+261`, занятую synthetic slot, mode 0/3 и predicates;
- альтернативу list-match и основной путь, direct callee flag 0;
- virtual order `+2e8,+540` либо `+4c8,+540,+2e8` и параметры backend calls;
- object index в пределах / вне count и chunk 0/1; marker `40000000` capture;
- native QWORD zero store в service `+250`, отсутствие иных записей service/actor,
  guards, восемь nonvolatile GPR и stack. На входе target stack тот же, что у
  wrapper: хвостовой вызов не создаёт дополнительного return address.

Названия mode/actor/slot служат аналитическими метками, не доказанной семантикой
игрового UI. Zero store не доказывает реальное освобождение объекта. Backend
проверки не подменяются их фактическим выполнением.

Wrapper не определяет Boolean RAX: на некоторых ранних ветках остаётся адрес
type-info или service; callee обновляет AL. Первый вариант теста ошибочно
сравнивал весь RAX с 0/1; после проверки инструкций тест сохраняет raw значение
и проверяет только соответствующий low-byte contract. Handler игнорирует этот
возврат. Не использовать его как признак успешной сетевой сессии.

## Проверки и автоматизация

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_requested_tail_calls.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_post_state_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_research_workflow.py
```

Два tail-model unit tests, три native tests (9,382 секунды) и 14 workflow tests
прошли. Native tests также отвергают подмену tail/callee/export и замену native
target fixture. Реальный Ghidra run подтвердил компиляцию нового script и
сохранение unwind-границ. Это время тестов, не всей цепочки обновления.

`native-login-post-state-context` подключён к game-login/update. При новом SHA
сверять wrapper call, E9/target, getter/global/class layout, declared callbacks
и native branches. Полные SHA двух exports и контекст входят в зависимости.
Совпадение функции не разрешает автоматическое runtime promotion.

## Что осталось

Post-state проверен отдельно: общая reader/handler цепочка пока вызывает capture.
Нужно включить его туда, затем проверить getter `1464af340`, его объект и virtual
`+28`, чтобы установить реальную цепочку к CharacterListRead. Этот участок сам
по себе её не доказывает; helpers/virtual backends ещё не исполнены.
Реальные services/getters/storage, dispatcher и серверная сессия остаются открытыми.
Не запускались сеть, авторизация, игра; аккаунты, пресеты и baseline сохранены.
