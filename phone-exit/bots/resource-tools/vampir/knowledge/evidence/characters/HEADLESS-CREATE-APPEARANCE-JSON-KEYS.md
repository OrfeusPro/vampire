# JSON внешности: числовые ключи, культура и переносимый builder

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [producer запроса](HEADLESS-CREATE-PRODUCER.md).

## Исполненная цепочка

Целые outer `0x146447e50`, entry `0x1456746c0`, AsNumber wrapper `0x1414b93c0`
и core `0x1414a4280` передают ID definition форматтеру `0x14148e740`.
Тот использует native integer formatter `0x14148e8a0` и соединение частей
`0x141478570`. Затем выполняются ToString wrapper `0x1414c3fa0`, проверка revision
`0x1414d3120` и source-bound virtual leaf для чтения полученного FString.
Все перечисленные функции исполняются в replay; форматтер не заменён готовой строкой.

ID форматируется **по numeric rules культуры**, а не независимым `str(ID)`.
Для текущих ID 1–7 проверены две явные таблицы цифр: латинская и арабская.
Минимум integer digits задан 1, максимум 20, fractional digits 0, группировка
включена. Для однозначных ID группировка не добавляет разделителей.

| Настройка | ID в текущих BoneGroup F / M | Ключ при Latin rules |
| --- | --- | --- |
| Height | 1 | "1" |
| Chest | 2 | "2" |
| Pelvis | 3 | "3" |
| Shape | 4 | "4" |
| Waist | 5 | "5" |
| Thigh | 6 | "6" |
| Head | 7 | "7" |

Обе таблицы заново извлечены из текущего PAK с проверкой full SHA, directory
и blobs. С арабской таблицей formatter возвращает `١`–`٧`. Текущая культура
живого клиента не читается: Latin rules для бота — явная политика, а не вывод
о настройке установленной игры. Поле пресета `Cheat` соответствует группе
`Chest` через ранее найденный slider enum 1; имя descriptor не исправляется.

## 36 сценариев

Две таблицы цифр × два пола × voice 0 / 1 / 255 × map empty / full / sparse.
Sparse map имеет 35 slots с занятыми индексами 0, 3, 7, 8, 16, 31, 32, 34.
Первые семь групп известны, последняя неизвестна и пропускается, даже если её
fixture float равен NaN. Это не означает, что NaN допустим для известной группы.

Native float32 преобразуется в double перед JSON setter: проверены 0.4, 0.3,
0.5, signed zero, 0.125, -2.5 и 1. VoiceType записывается всегда, в том числе
при пустой map. Значения сравниваются по double bytes, включая знак нуля.
Полученный JSON для сравнения строится из captures реальных native setter calls.

Culture lookup / rules, неизменная revision, history construction и повышенные
refcounts, definition lookup, FString storage / append / reserve / free,
JSON object setter / writer — fixtures. Native history layout / lifetime и
перестройка при смене культуры не проверены. Virtual leaf bindings проверены
по текущему EXE. Lookup использует точные имена из таблиц; полноценный engine
lookup с нечувствительным к регистру сравнением здесь не исполняется.

**Native serializer bytes не проверены**: whitespace, порядок свойств и запись
чисел могут отличаться. Подтверждено числовое содержание для заданных условий,
а не побайтное совпадение с JSON-строкой клиента и не принятие сервером.

## Runtime builder

Добавлен [character_appearance.py](../../../../../vampir-shared/vampir_core/character_appearance.py).
`encode_character_appearance(settings, voice, source_sha256=…, key_profile='latin')`
использует только проверенную таблицу текущей сборки и явно выбранные Latin keys.
Settings округляются до float32, затем передаются JSON как числа double.
VoiceType — byte 0–255; это диапазон wire, не перечень разрешённых голосов.
Builder сохраняет signed zero, отклоняет неизвестные настройки, bool вместо
числа, NaN, бесконечности, overflow float32, чужой SHA и другой key profile.
Отказ для неизвестной настройки строже native skip и помогает обнаружить ошибку
сборки payload до отправки. Игровые диапазоны float этим не устанавливаются.

Два теста проверили native сценарии и совпадение числовой семантики portable
JSON при Latin rules, а также отклонение неподдержанных входов. Builder пока
не подключён к отправке. Следом — целый handler ID 104, затем создание после
принятого пустого списка с явным кандидатом Carnage. Точный код занятого ника
ещё неизвестен; автоматический повтор по произвольной ошибке не разрешён.

## Воспроизведение и доказательства

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-appearance-json-keys.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_appearance_json_keys.py
```

[Native tool](../../../replay-release-appearance-json-keys.py), check
`release-appearance-json-keys`. Игра, авторизация и сеть не используются.
Отчёт в библиотеке ресурсов:
`code-clues/release-appearance-json-keys/0a0f3498f72ad569023d20262d6554041b67bc25c86ebd092910fce3ccfd60ac/manifest.json`.

Экспорты в общем comparison project
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Каталог | SHA256 details.json | Роль |
| --- | --- | --- |
| run-dc5979512d24 | 89478968108e418bd9e9c838152a2c70e00407e28a608338ee23ffa70a16d730 | AsNumber / ToString wrappers |
| run-7b99355a924a | 73635de588134c157424416285ef539e6689961ec7372e0f2b12423648a83d26 | AsNumber core / revision |
| run-f1248d98cd75 | 38109ed10c25dc33b390f9e365d39de11f11b20dfbe53a0aa6272f0915c029fb | Formatter / history constructor |
| run-d8e1fdc27ed5 | d5288d671696447b7d1064f09df37e0967771cb7c2a272a890a049693cef11a2 | Integer digits / parts join |
