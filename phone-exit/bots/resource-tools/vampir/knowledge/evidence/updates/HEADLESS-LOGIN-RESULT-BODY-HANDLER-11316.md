# LoginResult 1.13.16: reader и handler на одном объекте

Источник: EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
[Общий контекст](../../native-contexts/login-result-body-handler-11316.json)
соединяет [buffer/string reader](HEADLESS-LOGIN-RESULT-BUFFER-11316.md)
и [current handler/gate](HEADLESS-LOGIN-RESULT-HANDLER-11316.md).
Готовые девять exports использованы повторно; Ghidra не запускалась.

## Что теперь исполняется вместе

Native packet/nested constructors, concrete/base input buffer constructors,
numeric/raw input, FString/std::string/UTF-8 и packet reader создают и заполняют
объект. Handler получает **тот же pointer в той же памяти Unicorn**. После
reader host не записывает заново поля, strings, vptr или ID пакета.
Проверяется неизменность packet во время handler и canaries reader allocations.

Input archive/source buffer и service/state/controller regions разнесены.
Handler string fixture heap начинается после ограниченной области reader heap.
Общий free target выбирает reader storage fixture до вызова handler и handler
storage fixture во время него. Проверки reader ownership/temporary cleanup
поэтому продолжают выполняться. Native roots нельзя заменять handler fixtures.

Полная цепочка содержит 22 явных roots и девять immutable exports. Этот набор
разрешён только с budget 22 / scope `login-result-body-handler`, текущими
reviewed reader/buffer/handler/gate bindings и ровно 22 roots. Прежние default
16, explicit 19 и buffer 20 scopes сохранены; exports limit 9 действует только
для этой интеграции. Необъявленное исполнение и произвольное расширение бюджета
отвергаются. Нет автоматического обхода callees.

## Проверенные сценарии

Прежние 160 полных reader cases, 332 коротких тела, 25 отказов, 72 constructor
calls и string boundaries/special cases сохранены. Они не выдаются за 160
handler cases: общая reader → handler матрица состоит из **44 случаев**.

Это прежние 38 success/error/early/controller/SDK сценариев плюс шесть строк:
пустая, `Ж界🙂` и ASCII длиной 15/16/127/128. В каждом случае сначала читается
body native reader, decoded fields сравниваются со строгим Python decoder,
затем actual handler копирует их в synthetic state. Проверяются восемь native
state stores, строки через storage fixture, branches и отсутствие успешных
state/controller stores на covered отказах. Сервисные getters остаются fixtures.

Отдельно **131 отказ**: все 106 коротких префиксов выбранного тела и 25
принудительных reader failures. Common dispatch gate тестового harness вызывает
handler только при полном успешном чтении. Во всех этих случаях handler,
его сервисы и state writes не вызываются. Это проверка локальной связи replay,
а не доказательство поведения настоящего сетевого dispatcher.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_body_handler_context.py
```

Тесты также отклоняют отсутствие reviewed scope, бюджеты 23/32, несовпадение
handler SHA и подмену gate export. Отдельные reader/handler и прежние Version
budget проверки сохраняются.

## Следующий патч и оставшееся неизвестное

`native-login-result-body-handler-context` подключён к game-login/update.
Кэш зависит от двух verifiers, input/string storage fixtures, harness/runtime,
decoder/context/tests и девяти exports. Новый SHA требует переноса explicit
bindings, source/call/table links, ABI и всего набора проверок. Runtime promotion
не разрешён автоматически; покрытие игрового входа остаётся частичным.

Следующие участки: реальные services/getters/storage и сетевой dispatch, затем
post-state `146755540` / getter `1464af340` / virtual `+28`. Отклонённый
`run-aaeae96c7f8b` сохраняется: block вне unwind надо объяснить до нового collect.
Не называть post-state запросом персонажей без доказанной цепочки.

Body synthetic, чтение little endian; storage allocation/growth/assignment/free,
UI/SDK/clock/persistence/disconnect/post-state backends — fixtures/captures.
Ограничения malformed UTF-8 / zero stack сохранены. Не доказаны live session,
все result codes, реальный ownership сервисов или полный lifecycle сокета.
Сеть, авторизация, игра и смена рабочих профилей не запускались.
