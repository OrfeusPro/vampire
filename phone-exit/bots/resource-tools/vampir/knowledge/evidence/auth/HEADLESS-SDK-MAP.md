# Vampir — объединение строковых констант и чтение auth URL

19 октября: [real public response](../updates/HEADLESS-PUBLIC-GMC2.md) дал 93 ordinary/1 secret
string values; общий merge получил 94 entries, auth URL getter и offline token
binding проверены на этой карте. Native callback целиком/аккаунт ещё не проверены.

19 октября 2026. Продолжение [secret list](HEADLESS-SDK-SECRET-LIST.md).
Общий код объединяет уже строковые карты и повторяет найденную prefix-проверку
адреса. Получение актуального GMC2 и создание игровой сессии ещё не готовы.
Продолжение: [native path append и полный offline token plan](HEADLESS-SDK-PATH.md).

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA относятся к image base `0x140000000`. Версия игры и Android parity неизвестны.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-map.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_map.py -v
```

Зависимости закреплены в `requirements-native.txt`. Отчёт
`F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-map.json`, SHA256
`3bfe3a2fffed8ef40037c6f5bcc9cbed857f727cc56c1a5a802c13accc050560`.
Сохранены инструкции, смещения, source/tool/fragment hashes, CRC/fold tables,
литералы, доказательство импорта memmove и искусственные входы/выходы.
Игра, сеть и аккаунты не использовались; `.invalid` — искусственные адреса.

## Связи normal → secret → SDK map → auth

| Адрес | Подтверждённая связь |
|---|---|
| Parser `0x1444f1250` | После normal constants вызывается insertion `0x14150df70`, RCX=общая выходная карта R15 |
| Parser `0x1444f162f` | После secret constants вызывается та же insertion с той же картой |
| `0x14150e025..0x14150e06b` | При совпавшем ключе освобождаются старые строки и копируются новые key/value |
| SDK getter `0x144553700` | Делегирует `0x144502730` для карты object+`0x310` |
| `0x144502773/7a3` → `0x141420380` | Хеш строки: ASCII lowercase переводится в uppercase, затем CRC table |
| `0x144502780/7b0` → `0x141437e50` | Поиск по bucket chain; ASCII-регистр ключа не различается, остальные единицы сравниваются точно |
| `0x144502818` → `0x144584280` | Проверка значения через префиксы `http://`, затем `https://` |
| `0x1445842d9/315` → `0x141432f20` → `0x1414599a0` | Префикс сравнивается без учёта регистра ASCII |
| Auth caller `0x1450e286d..0x1450e2895` | Ключ `authTokenUrl` передаётся SDK getter, затем проверяется AL |

При замене копируются и key, и value: сохраняется написание нового ключа.
Порядок parser устанавливает приоритет secret над normal для совпавших ключей.
Полное заполнение object+`0x310` после GMC2 callback ещё требует tracing;
связь caller с getter доказана, но весь lifetime карты не исполнен.

## Границы native проверки

В Unicorn исполнены SDK getter, key hash, bucket-chain comparison и URL prefix
checker: 24 сценария. Карта искусственная, с одним bucket и цепочкой коллизий;
ключи, значения и лимиты явные. FString allocation/assign/free заменены shims,
memcpy обрабатывается ограниченным shim из прежнего эмулятора.
CRC и ASCII fold tables взяты из указанного EXE, хеш не подменяется.

Отдельно исполнен existing-key replacement slice `0x14150e037..0x14150e070`:
три сценария с явным индексом существующей записи. Memmove подтверждён через
PE/IAT как VCRUNTIME140.dll!memmove и заменён ограниченной копией 32 байт.
New-key insertion, growth, cleanup и полный parser не исполнялись.
Пять дополнительных native hash-вызовов подтверждают ASCII case equivalence.

Если ключ отсутствует или prefix не проходит, native getter возвращает false
и оставляет выходную строку прежней. `https://` и `http://` без host проходят:
checker проверяет именно префикс, а не корректность полного URL.
HTTP-запросы этим не выполняются. Актуальный endpoint по строкам EXE не выбирается.

## Общий код и следующий шаг

[sdk_config.py](../../../../../vampir-shared/vampir_core/sdk_config.py), только stdlib:

- `merge_sdk_string_constants(ordinary, secret)` объединяет уже строковые карты,
  secret заменяет ASCII-equivalent ключ с его новым написанием. Входы не меняются.
- `lookup_sdk_url_value(constants, key)` возвращает найденную строку при native
  HTTP(S) prefix check, иначе None. Host/path/порт здесь не проверяются.

Локальные границы: 512 записей, 256 UTF-16 units на key, 4096 на value,
65536 UTF-16 bytes значений на карту; NUL и aliases внутри одной входной карты
отклоняются. Это строгая локальная политика, а не полная толерантность native.
JSON numbers/objects не превращаются в строки по догадке: их stringify ещё
не восстановлен. Вход функций — итоговые строковые значения.

Пять тестов проверяют source/code/data, parser order и auth call chain,
native vectors/replay, замену и отсутствие изменения входов при отказе.
Android backend здесь не используется, но H06 остаётся открытым до запуска.
Далее `0x144476940` для stringify и заполнение SDK+`0x310`. Auth path append
`0x1450e2b01` → `0x14142c9d0` также требует проверки до связывания request plan;
не добавлять/удалять слеши по предположению. DECKEY lookup ещё не восстановлен.
`network_ready=false`, вход по почте/паролю и бой ещё не готовы.
