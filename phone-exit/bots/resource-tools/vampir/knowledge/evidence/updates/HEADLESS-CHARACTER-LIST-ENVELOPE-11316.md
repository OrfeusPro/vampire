# CharacterListReadResult 1.13.16: внешний reader и счётчик

24 октября 2026. Собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [инициатора ID 101](HEADLESS-WAITING-END-11316.md).

## Привязки текущей сборки

Constructor `1456d7220` устанавливает packet table `149928a48`.
Slot `+20` → reader `1456dbc30`; slot `+28` → actual getter `1456e4c10` → 102.
Рядом находится literal `PktCharacterListReadResult` по `149928a98`.
Constructor/ID getter исполняются; table links, source bytes и callees сверяются.

Reader сначала читает u32 в `+10` и `+14`, очищает прежний массив `+18`,
затем через native archive vector `144aac530` читает u16 count.
Vector callback table `149928ed0` связывает resize `1456e6a20` и record thunk
`1456dcdc0`. При ненулевом count thunk вызывает record constructor `145783840`,
затем generic read thunk `144aad190`. Здесь проходит явная граница следующего
исследования: записи персонажей не подменяются готовым пустым массивом.

После массива обязательны поля:

| Packet offset | Wire тип |
| --- | --- |
| `+28` | u64 |
| `+30` | u32 |
| `+38` | u64 |
| `+40` | u64 |

Полный ответ с count 0 занимает 38 байт. Один прочитанный нулевой count
не означает принятого пустого списка: хвост также должен успешно прочитаться.
Result code остаётся отдельным условием; error result не разрешает создание.

## Выполненные проверки

Исполнены whole outer reader, vector loop, resize, concrete/base input constructors,
actual u16/u32/u64/raw IO и bookkeeping. Поля input cursor/size заданы actual
constructor через ABI, после него не переписываются. Allocation/cleanup fixtures
ограничены; при ненулевом count исполнение явно останавливается перед record.

- 24 полных случая: result 0/1/58/ffffffff, raw14 0/80000000/ffffffff,
  два исходных заполнения памяти; хвост содержит ненулевые границы u32/u64.
- Все 38 коротких префиксов отклонены. Отказы каждой из семи scalar/count
  операций останавливают чтение без следующих операций.
- Counts 1/2/4 достигают явной границы record constructor; 65535 отклоняется
  локальным fixture budget до allocation. Ни один не возвращается как accepted empty.
- Native reader принимает trailing bytes, потребляя 38. Runtime exact-size policy
  не ослаблена. Принятые поля сверены с существующим portable decoder;
  preferred_character_index для пустого списка возвращает None.
- Проверены ABI, packet padding/guards, input buffer и неизменные поля archive.

## Воспроизведение и повторное использование

[Context](../../native-contexts/character-list-envelope-11316.json),
[verifier](../../../verify-character-list-envelope-context.py),
[три теста](../../../../../test_vampir_character_list_envelope_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_list_envelope_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-character-list-envelope-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/character-list-envelope-11316.json
```

Новый export — `run-e6ab6fd97914`, четыре явных unwind roots. Input IO и buffer
constructor exports использованы повторно: `run-6c5bd9da86eb`, `run-80386d1eb460`.
Report: `F:/PhoneExit Resources/Vampir/knowledge/native-character-list-envelope-checks/d24f8e2f2e69ccc46cac5c62681bea0f9bb38c3a27e8164f7b6f3c5d731a92c8/manifest.json`.
SHA exports, source, tool и context сохранены в машинных результатах.

Check `native-character-list-envelope-context` подключён к `character-list`.
На следующем патче заново проверить packet constructor/table/ID, callback table,
outer/vector/resize/record thunk и archive callees; затем переносить context.
Совпадение empty fixture не подтверждает вложенные records новой версии.

## Оставшиеся границы

Это проверка envelope, не поддержка целого списка текущего SHA в runtime.
Record fields, appearance/optional containers, result registration/handler и network
dispatch ещё не перенесены. Нет живого списка, разрешения на создание, выбора или
входа в мир. Source guard, профиль и baseline не менялись.
Далее проверить current CharacterRecord constructor `145783840`, reader из table
`149928500 +20`, связанные nested readers и runtime projection. После records —
whole list и handler. Для живого входа отдельно остаются профиль и Ping clock.
