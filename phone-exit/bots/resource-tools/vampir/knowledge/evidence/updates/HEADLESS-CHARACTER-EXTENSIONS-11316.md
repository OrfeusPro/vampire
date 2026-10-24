# CharacterRecord 1.13.16: непустые коллекции внешности и optional map

24 октября 2026. Собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [полей записи](HEADLESS-CHARACTER-RECORD-11316.md) и перенос
[исторических коллекций](../characters/HEADLESS-CHARACTER-LIST-EXTENSIONS.md).
Проверены два отдельных native компонента; интеграция целой записи/списка ещё впереди.

## Актуальные связи

| Компонент | Table / callback | Функции |
| --- | --- | --- |
| Вектор внешности | `14993f850` | resize `1456ba460`, callback `14573b9c0` |
| Запись внешности | `149920048` | constructor `145782c60`, reader `145786390` |
| Optional reader | `149921c80` | `1456c3000` |
| Optional vector callbacks | `149924f18` | resize `1456d2260`, callback `1456c6e70` |
| Вставка map | прямой call callback | insert `1456bd7a0`, pair constructor `1456bbbd0` |
| Значение map | `149921b18` | constructor `1457841c0`, reader `1457893b0` |

Generic vector `144aac530`, input constructors/scalars/raw, read thunk и TimeBase
использованы повторно. Table slots, source blocks и callee inventory проверяются.
Внешность исполняется в наборе из 11 roots, optional — из 18; оба укладываются
в существующий лимит 19 без изменения общего harness.

Внешность читает u16 count и элементы `u32 / enum byte / u16`, размещая их
в native элементах размером 16 байт. Enum ограничивается максимумом 45.
Optional reader читает bool presence, u16 count, затем элементы
`key byte / enum byte / u32 / u32 / u32 / raw64`; enum ограничивается 9.
Порядок/типы подтверждены actual readers и portable projection, не именами полей.

## Что исполняется и что подставлено

Native: vector loop, resize control flow, item/value constructors/readers, pair
constructor, insert body, hash-chain поиск повторного ключа и overwrite значения.
Фиксируются новые insertions: повторный ключ обязан обновить существующий узел,
не достигнув новой вставки. Результат сопоставляется с portable last-value-wins.

Fixtures: preallocated arrays/map storage, reset/cleanup, bit-vector capacity,
предикат вставки нового ключа и перераспределение bucket heads/chain metadata.
Это не проверка allocator lifetime или целой native реализации TMap.
Восемь узлов, buckets 1/2/4/8/16 и максимум 4096 байт — локальные границы replay,
не лимиты сервера. Нехватка storage даёт явный `local_storage_budget`, не пустые данные.

## Проверки

- Внешность: 5 полных вариантов — пустой, один элемент, числовые границы,
  восемь одинаковых элементов, восемь различных с clamps 44/45/46 и выше.
  Все 58 коротких префиксов выбранного тела и 42 отказа primitive/raw чтения отклонены.
- Optional: 19 вариантов, включая отсутствующий/пустой блок, presence 1/2/255,
  key 0/255, enum 0/9/10/255, u32/u64 границы и повторные ключи.
  Восемь ключей с шагом 16 создают коллизии после native выбора размера buckets;
  повтор первого ключа проверяет поиск по цепочке после rehash fixture.
  Все 201 короткий префикс и 94 отказа чтения отклонены.
- Порядок и кратность элементов внешности сохраняются. Map сортируется только
  при сравнении результата; source lookup/overwrite исполняются native.
- Проверены vtables сохранённых элементов/значений/TimeBase, ABI, input/output
  guards, неизменность input buffer и остановка после отказа.
  Native trailing bytes допустимы; portable exact-size policy не менялась.

## Экспорт и воспроизведение

Первый `run-5d4c44f86e89` остановился на resize `1456d2260`: decompiler включил
блок за requested unwind bounds. Попытка сохранена и не повторялась с тем же
заданием. Новое задание явно добавило targets `1456d19c0` / `1456c7280`, поэтому
существующая модель E9 → CALL_RETURN сработала. Source bytes и unwind не менялись.
Готовый export `run-96408f02c1d2` содержит 11 явных roots, включая два targets
только для статической модели/fixtures. Остальные пять exports использованы повторно.

[Context](../../native-contexts/character-extensions-11316.json),
[verifier](../../../verify-character-extensions-context.py),
[три теста](../../../../../test_vampir_character_extensions_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_extensions_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-character-extensions-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/character-extensions-11316.json
```

Report: `F:/PhoneExit Resources/Vampir/knowledge/native-character-extensions-checks/ad474d2d5379e1461d414cdd6c690c11558737533a00a1c6a4efeb2260802b85/manifest.json`.
Check `native-character-extensions-context` подключён к `character-list`.
На следующем патче перепроверять callbacks/entry tables, clamps, map insertion,
duplicate lookup и archive callees; перенос bindings требует проверки по новому SHA.

## Следующий шаг

В старом whole-record replay границы непустых коллекций пока остаются:
эта проверка компонентов их автоматически не снимает. Далее объединить readers
и storage fixtures в одном record/list на общей памяти, проверить смешанные
непустые collections, короткие тела и handler gates. Сеть, свежий список,
создание/выбор персонажа и игровой профиль этим результатом не подтверждаются.
