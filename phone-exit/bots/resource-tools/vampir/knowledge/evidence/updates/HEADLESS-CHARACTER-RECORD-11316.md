# CharacterRecord 1.13.16: чтение полей и вложенных структур

24 октября 2026. Собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [внешнего ответа списка](HEADLESS-CHARACTER-LIST-ENVELOPE-11316.md).
Полный список новой сборки пока не объявлен поддержанным.

## Проверенные привязки

| Участок | Constructor / table | Reader |
| --- | --- | --- |
| CharacterRecord | `145783840` / `149928500` | `145788500` |
| Временные поля | `1457a3500` / `14991f3b8` | `1457fdce0` |
| Четыре u16 | `1457904d0` / `149920550` | `145794bc0` |
| Внешность | table `149920090` в record `+b0` | `145787a30` |
| Optional | table `149921c80` в record `+110` | `1456c3000` |

Table slot `+20`, source bytes и прямые/виртуальные callee sites проверяются.
Record constructor исполняется целиком; вложенные table и начальные пустые строки/
контейнеры задаёт он, без ручной подмены полей после конструктора.
Через actual read thunk `144aad190` выполняются вложенные readers.

Проверена проекция 12 raw u64, двух u32, четырёх u16, трёх FString,
enum `+60`, десяти байтов внешности, двух её флагов и bool `+108`.
Имена/ID/уровень/позиция по этим смещениям здесь не назначаются.
Временные значения берутся из `TimeBase +8`, а не из адресов table.

## Native цепочка и тесты

Исполняются 22 явных unwind roots: 14 существующих input/string функций и
8 record/nested/vector функций. Повторно использованы concrete/base buffer,
scalar/raw IO, FString/std::string/UTF-8, временные readers и vector.
Пять новых roots экспортированы двумя пакетами: `run-0b2ae7adfcf9`
и `run-5f5962528f71`. Остальные семь exports использованы повторно.

Лимит 22 roots / 9 exports разрешён только для явного scope `character-record`
с проверенным набором bindings. Он не разрешает обход дерева вызовов, иной scope
или увеличение бюджета; это проверяется отрицательными тестами.

- 128 полных случаев: пустые, ASCII, кириллица/японский/emoji и строки с переходом
  за SSO; enum 0/6/7/255; appearance enum 0/1/2/255; bool 0/1/2/255;
  два исходных заполнения объекта. Числа различаются по полям, u16 включают
  0/7fff/8000/ffff, u64 проходят переполнение исходной последовательности.
- Все 201 короткий префикс выбранного Unicode body отклонены; 128 поочерёдных
  отказов primitive/raw чтения не достигают успешного возврата. После отказа
  не выполняется следующее чтение.
- Поля каждого принятого record сверены с portable decoder, обёрнутым в
  одноэлементный список с явным хвостом. Record bytes/дескрипторы не подменяются
  результатом Python-декодера.
- Native принимает extra bytes, потребляя только record; строгий portable decoder
  не изменён. Проверены ABI, vtables, padding/guards, input cursor/buffer и guards
  всех строковых allocations.
- Непустые appearance items и present optional данные останавливаются на явных
  границах `appearance_items_not_ported` / `optional_items_not_ported`.
  Их нельзя считать пустыми данными или принятым record.

## Воспроизведение и обновление

[Context](../../native-contexts/character-record-11316.json),
[verifier](../../../verify-character-record-context.py),
[три теста](../../../../../test_vampir_character_record_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_record_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-character-record-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/character-record-11316.json
```

Report: `F:/PhoneExit Resources/Vampir/knowledge/native-character-record-checks/8b1a15a7510d2081f1cdc9d320a19db33b978df0654c68618fcd4d50b850e6e3/manifest.json`.
Source/tool/context/exports SHA и выбранные fixtures сохранены в машинных данных.
Check `native-character-record-context` связан с `character-list`.

Для следующего патча найти record через callback table списка, сверить constructor,
все reader slots, порядок полей, clamps и callees archive/string/nested readers.
Новый context и scope требуют проверки; только совпадения тела недостаточно.
Проверку envelope не заменять проверкой records и наоборот.

## Границы и следующий шаг

Storage/allocation/free и пустой resize внешности — bounded fixtures. Не доказан
жизненный цикл настоящего allocator и повторное чтение в непустой объект.
Present optional и непустые appearance collections ещё не перенесены.
Далее — callbacks `14993f850` для appearance items и `149924f18` для optional
map, затем whole-list integration и result handler. Видимое состояние сервера,
свежий список, создание, выбор и вход в мир не проверены; профиль не активирован.
