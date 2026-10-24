# LoginResult 1.13.16: регистрация ID 4 и текущий handler

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это статическая проверка инструкций собранного клиента. Исполнение обработчика,
сеть и успешная сессия в этот результат не входят.

## Доказанная связь

В `.text` найден один E8 rel32 candidate на constructor `1456d7690`:
`1467b4d07`, unwind owner `1467b4c60`. Инструкции этого участка проверены:

1. В `1467b4cd4` выделяется объект handler размером 8 bytes.
2. LEA `1467b4ce6` получает table `149dc65b8`; следующая инструкция пишет её
   в объект RDI. Null-ветвь сохраняется в проверяемом control flow.
3. Выделяется packet размером `140`; `1467b4d07` вызывает его constructor.
4. В `1467b4d11..1467b4d1a` передаются R8=handler, RDX=packet, RCX=dispatcher
   и вызывается registration helper `1467cb6c0`.
5. Constructor связан с packet table `149926590`; slot `+28` указывает на
   getter `141453c40`, который возвращает ID 4. Slot `+10` handler table
   указывает на **`14679aec0`**.

Одно найденное E8 упоминание не доказывает отсутствие indirect/encoded references.
Роль обработчика установлена по цепочке регистрации, а не по prefix старого handler.
Старые адреса из [исторического replay](../network/HEADLESS-LOGIN-RESULT-HANDLER.md)
не перенесены автоматически.

## Сохранённые материалы и лимиты

Owner регистрации имеет unwind range 67 858 bytes. Общий collector отклонил
его до Ghidra: предел 65 536 bytes. Лимит не увеличивался. Вместо полного
export проверяется точное окно **75 bytes**, `1467b4cd4..1467b4d1f`.
Это статический участок, не исполняемый fragment и не полный owner replay.

Новая выгрузка содержит только два explicit roots:
`14679aec0` и `1467cb6c0`, run `run-83255b6c29bc` в
`ghidra/request-exports/<SHA>/`. Ghidra project использован повторно;
готовый result constructor export `run-3c0581002a58` использован повторно.
Полные SHA экспортов, окно, bindings и direct/virtual call inventory сохранены
в [контексте](../../native-contexts/login-result-registration-11316.json).
Все инструкции exports сверяются с EXE; полный SHA источника обязателен.

## Следующие явные участки

Handler export показывает current result gate `1467cd7b0`, вызываемый с raw code
и packet ID, записи полей в state и отдельные error paths. Следующий post-state
вызов — `146755540`, затем getter `1464af340` и virtual slot `+28`.
Эти адреса пока ориентиры для следующей проверки. Native success/error branches,
state semantics и переход к CharacterListRead этим не доказаны.

Registration helper получает packet ID через virtual `+28` и передаёт tuple
packet/handler в helper `1467b4400`. Реальное содержимое контейнера, ownership
и вызов handler при сетевом dispatch остаются открытыми.

## Автоматизация

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_registration.py
```

Три теста прошли за 12,957 секунды. Проверены полная цепочка и отказ при подмене
handler/table/constructor/packet-ID slot, export SHA и callee result gate.
`login-result-registration` подключён к game-login и update с явными входными
зависимостями. При новом SHA требуются review constructor xref/window/ABI,
ID/table links и перенос проверки. Совпадение call inventory не подтверждает
поведение веток; автоматического runtime promotion нет.

Большую функцию не экспортировать повторно без конкретной новой необходимости.
Готовые два roots использовать для переноса gate и полного handler replay.
Строгий decoder, source guard, аккаунты и рабочие пресеты сохранены.
