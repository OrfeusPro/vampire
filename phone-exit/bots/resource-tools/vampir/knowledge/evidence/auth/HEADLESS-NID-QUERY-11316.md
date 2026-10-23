# Кодирование NID query и передача URL в состояние 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [gates / account additions](HEADLESS-NID-GATES-11316.md).
Сохранённый EXE и synthetic memory, без процесса игры, браузера и сети.

## Текущие связи

Явный prepare / collect получил два недостающих exports. Повторный экспорт
готового NID root не выполнялся. Проверены инструкции и единственные CALL:

- CheckPossibleToOpen `0x1450e3c80`: callsite `0x1450e4b80` → serializer
  `0x14458d3d0`.
- Serializer `0x14458d3d0` → value encoder `0x141c19460`.

Это текущие source-bound связи, а не перенос прежних адресов.
Сериализация карты параметров целиком пока не исполнена.

## Кодирование значений

Исполнена вся функция `0x141c19460`, включая реальные whitelist initialization /
lookup и hex conversion leaves. У двух leaves нет unwind roots; их границы
от явного CALL target до RET сверены инструкциями и закреплены по SHA:

| Leaf | Размер, байты | SHA256 |
| --- | --- | --- |
| 0x141c0c360, whitelist | 672 | 663726f7c82a66ae51abe32b2f2fe17e7cc91ed1ab171caf47e6367fd6810f77 |
| 0x1415b3090, hex | 102 | 6fafe4a5bef6c84ba8b5f0daac1379c237e228a7c343fc50ab135801adc87f95 |

Whitelist BSS flag / table по `0x14b408a0c` / `0x14b408a10` обнуляются перед
каждой группой, затем выполняются cold initialization и warm lookup. Источник
таблицы разрешённых символов читается native-кодом из проверенного EXE.
Hex leaf тоже исполняется, без fixture результата.

396 случаев: четыре poison fills × 99 значений (95 печатных ASCII символов,
пустая строка, строка со специальными символами, весь печатный ASCII и hex digits).
Все результаты совпали с существующим portable `_escape_ascii`, а для пустого
входа — с пустой строкой. Подтверждены `%20`, `%2B`, `%26`, `%3D`, uppercase hex
и неизменяемые safe chars. Проверены canaries вокруг выходного FString.

Single UTF-16-unit → ASCII conversion, reserve / append storage и stack-cookie
helper — fixtures. Unicode / surrogate pairs / непечатные значения не покрыты.
Из этих результатов нельзя разрешать Unicode в portable auth encoder.

## Сборка и передача URL

Отдельно исполнен NID slice `0x1450e4a95..0x1450e4c29`, до allocation результата.
Native builder копирует base, добавляет настоящий ASCII literal `?` через
`0x1417619b0`, добавляет synthetic query и завершает строку нулём. Проверен
source-bound memcpy tail `0x141453890` → импорт memcpy.

48 случаев: четыре poison fills × четыре bases × три queries. Проверены
пустые base / query, обычный auth endpoint, завершающий slash и base с уже
имеющимся query. Во всех случаях native caller передаёт `base + ? + query`
в FString storage helper `0x1414277b0` для owner +0x48, затем owner +0x58.
Он не заменяет `?` на `&` при уже имеющемся query. Это наблюдение локального
builder; portable endpoint policy остаётся ограниченной проверенным auth URL.

Map copy `0x1414b0050`, serializer `0x14458d3d0`, owner storage helper и free —
fixtures. Query задан явно; его порядок не объявляется порядком Unreal map.
Буфер inline, growth path не исполняется и неизвестный переход остановит replay.
Реализация owner storage helper и сохранение в реальном объекте не проверены.
Этот участок подготавливает состояние URL, но не открывает браузер. Success /
error result callbacks, UI lifecycle, credential acquisition и вся авторизация
остаются непроверенными. Runtime profile по-прежнему не включён.

## Проверки и обновление

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-query-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_query_11316.py
```

Capstone 5.0.6 / Unicorn 2.1.4; полные SHA EXE / четырёх exports / двух leaves,
байты инструкций и конечные instruction / heap / string budgets.
Три теста: поведение / owner bindings, отказ при неверном leaf SHA и повреждении
export. Check `nid-query-native-11316` связан с tool / portable helper / export
dependencies. Его scope и required_checks добавлены в release-update-targets.json.
При новом SHA нужно найти serializer / encoder через подтверждённый caller,
сверить leaves, whitelist / hex, slice и owner bindings, затем перенести check.
Старые адреса и положительные тесты не разрешают новую сборку автоматически.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Serializer: `ghidra/request-exports/<SHA>/run-bdb7533f59ee/details.json`,
  SHA `8ab07dc9d0542e95324e9af17f528f9c5438a0d1d0d7740fe9b157ab1d112834`.
- Encoder: `ghidra/request-exports/<SHA>/run-cd25b4a7660d/details.json`,
  SHA `8906d32083c6889a5f9ac118899d13fb2e03c45f398c10270d8a3143e6af3a2a`.
- Caller export: предыдущий evidence по ссылке выше; ASCII append export:
  [GMC2 URL](HEADLESS-GMC2-URL-NATIVE-11316.md).
- Report: `code-clues/nid-query-11316/f7ac909d8abafa957b3ce68a42ffbeff83a2822d616e393259a9d7c714079786/manifest.json`.

Следом перенести auth source guards и проверить browser / result boundary для
профиля 1.13.16. Полная map serialization и Unicode сохраняются отдельными unknown;
живой вход не заменять этими локальными проверками.
