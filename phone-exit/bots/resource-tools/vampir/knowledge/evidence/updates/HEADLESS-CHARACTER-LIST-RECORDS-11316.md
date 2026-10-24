# CharacterListReadResult 1.13.16: общий reader с непустыми записями

24 октября 2026. Собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Объединены [внешний reader](HEADLESS-CHARACTER-LIST-ENVELOPE-11316.md),
[record](HEADLESS-CHARACTER-RECORD-11316.md) и
[непустые коллекции](HEADLESS-CHARACTER-EXTENSIONS-11316.md).
Это проверка тела ответа, ещё не handler или живая сессия.

## Общая цепочка

В одной Unicorn memory выполняются packet constructor `1456d7220`, reader
`1456dbc30`, generic vector `144aac530`, list resize `1456e6a20`, record thunk
`1456dcdc0`, actual record/nested/input/string/collection readers и map insert.
Packet table `149928a48`, ID getter `1456e4c10` → 102 и source blocks проверяются.
Ни packet fields, ни записи не заполняются результатом portable decoder.

Использованы 34 явных unwind roots и 10 уже готовых exports. Ghidra не запускался.
Это объединение прежних разрешённых пакетов, а не новый batch из 34 roots.
Scope `character-list-records` разрешает этот набор только для текущего полного
SHA и проверенных ключевых bindings; иной scope/бюджет отклоняется.
Общий обход EXE, расширение дерева вызовов и произвольное исполнение не добавлены.

Actual constructor/reader получают тот же input archive и stack objects.
Buffer constructor задаёт cursor/size через ABI. Owner для FString storage fixture
наблюдается на входе actual record constructor, поэтому назначения ограничены
тремя известными строковыми полями текущей записи. Прежние проверки с фиксированным
owner сохраняют поведение.

## Storage и защита от смешивания записей

Allocation/free, container reset/rehash, bit capacity, unseen-key predicate,
shallow record copy и cleanup — явные fixtures. Copy переносит native object bytes,
а не заново декодирует wire. Allocator lifetime / actual copy implementation
клиента не доказаны и здесь не подменяются утверждением о native контейнерах.

Повторно используемый адрес временной записи получает новую generation.
Storage предыдущей скопированной записи сохраняется отдельно; map reset новой
generation не может затереть старые строки/коллекции. Итоговый массив извлекается
после чтения всех записей и сопоставляется целиком с portable decoder.
Так проверяются различия между соседними записями, а не только одна общая fixture.

Локальные границы: 4 записи, до 8 элементов/уникальных map keys в каждой коллекции,
4096 байт input, ограниченный scratch heap и один миллион инструкций на whole read.
Это границы доказательства, не заявленные серверные лимиты.

## Проверки

- 32 полных ответа: 0/1/2/4 записи, четыре варианта данных, result 0/58 и два
  заполнения packet memory. Строки ASCII/Unicode, числа, enum clamps, пустые/
  непустые коллекции, optional absence/presence и повторные ключи различаются.
- Четыре записи сохраняют различные строки и коллекции; copy generations 1/2/3/4
  соответствуют разным назначениям в результирующем массиве.
- Все 291 короткий префикс выбранного смешанного ответа отклонены. 154 поочерёдных
  отказа scalar/raw чтения останавливают последующие операции.
- Пять дополнительных усечений ответа с четырьмя записями проверяют отказ после
  уже скопированных записей. Частичный count может быть ненулевым, но records
  не публикуются как принятый список.
- Проверены header/tail, все поля записей/коллекций, ABI, packet padding,
  input buffer/cursor и guards каждой allocation. Native trailing bytes допустимы;
  portable exact-size policy не ослаблена.

## Воспроизведение и обновление

[Context](../../native-contexts/character-list-records-11316.json),
[verifier](../../../verify-character-list-records-context.py),
[storage fixtures](../../../character-list-storage-fixtures.py),
[три теста](../../../../../test_vampir_character_list_records_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_list_records_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-character-list-records-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/character-list-records-11316.json
```

Report: `F:/PhoneExit Resources/Vampir/knowledge/native-character-list-records-checks/fef3af45fceaa96d4cf7f112d47ce198e7661a995646ea35a72c8b84b45f73f8/manifest.json`.
Полные SHA source/exports/tool/context сохранены; check
`native-character-list-records-context` связан с `character-list`.
На следующем патче сначала проверить bindings и компоненты, затем общий reader;
сохранять отдельные проверки distinct records, усечений и partial-count rejection.
Новый SHA требует явной проверки scope, а не автоматического переноса адресов.

## Следующий участок

Перенести текущие result registration/handler и условия публикации принятого списка,
выбора существующего персонажа либо перехода к созданию при пустом списке.
Dispatcher, UI/services и сетевое состояние не исполнены. Игровой профиль,
baseline и runtime поддержка нового SHA автоматически не активированы.
Авторизация, свежий список и создание персонажа этим replay не выполнялись.
