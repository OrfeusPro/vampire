# После LoginResult 1.13.16: final virtual +28 сбрасывает состояние

Источник: EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это перенос на текущий SHA уже существующего
[контракта границы списка](../characters/HEADLESS-CHARACTER-LIST-BOUNDARY.md),
а не новый поиск той же ветви. Исторические адреса не переносились автоматически.

## Current связи

После post-state current handler вызывает getter `1464af340`, затем virtual
`+28`. Проверенное окно `14679b22f..14679b242` сохранено в
[контексте](../../native-contexts/login-continuation-11316.json).
8-byte getter реально читает global `14b5fe3c8`.

Constructor `1464a6450` пишет this в этот global. Он сначала ставит base table
`149cb7b18`, затем в `1464a6521` заменяет её final table **`149cb7b48`**.
У base slot `+28` — no-op leaf; final slot `+28` — **`1464ac910`**.
Выбор только первой таблицы дал бы неверное действие продолжения.

Init owner `14665b750` содержит allocation/constructor и последующую запись
возвращённого pointer в global. Его окно проверено статически; init owner
не исполняется в replay. Последующие lifecycle изменения объекта этим не исключены.

Все три roots экспортированы одним явным batch `run-c288c83765a6` в
`ghidra/request-exports/<SHA>/`; SHA в контексте. Обхода callees нет.
Native replay исполняет constructor, getter и метод, разрешённый через
**реальную final table созданного объекта**. Вызов из whole handler пока capture.

## Сохранённые invariants

Восемь прежних сценариев перенесены по фактическим current stores/callees:
level 0/1/2/5 и capacity 128/256. Constructor/getter проверяют this/global,
порядок base/final vptr; reset проверяет:

- count/refcount-like поля `f0/140/190/210/260/2b0/300`: при level > 1 становятся 1;
- capacity `244/294/2e4` ограничивается 128; при 256 три shrink captures;
- indices `248/298/2e8` получают FFFFFFFF, count/flag fields обнуляются;
- WORD `+308`, current global byte `14b5f0dc9`, fields `338/33c` сбрасываются;
- instruction-addressed native stores, object canaries, stack и восемь nonvolatile GPR.

Container init/clear/shrink/destructor backends — объявленные captures с fixture
return 0. Их полные эффекты и реальные непустые destructor loops не проверены.
Объект и seeds synthetic; значения полей не объявляются именами игровых сущностей.

## Что это меняет в плане

Как и в исторической проверке, final virtual `+28` выполняет сброс состояния.
Прямое создание/отправка CharacterListRead здесь не подтверждено. Не повторять
поиск инициатора внутри этого reset без новых данных. Следующий известный путь:
[исторический WaitingEndNotify → CharacterListRead](../characters/HEADLESS-WAITING-END-CHARACTER-REQUEST.md).
Его current registration/ID/handler/predicate/request entry ещё надо перенести.
Старый ID 27 и старые адреса не считать автоматически подтверждёнными для 1.13.16.

Отдельно остаётся интеграция actual post-state и continuation в общий handler,
реальные getters/services/storage, dispatch и серверная сессия. Проверка reset
сама по себе не закрывает ни один из этих пунктов.

## Автоматизация

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_continuation_context.py
```

Три теста прошли за 10,285 секунды: current binding и восемь сценариев, отказ
при подстановке base table, другого getter global, callee или export SHA.
`native-login-continuation-context` включён в game-login/update; tool/context,
native harness/runtime и export входят в зависимости. Для нового SHA требуются
review final vptr/global/slot и повтор invariants; runtime promotion запрещён.
Сеть, игра, авторизация, аккаунты, рабочие пресеты и baseline не менялись.
