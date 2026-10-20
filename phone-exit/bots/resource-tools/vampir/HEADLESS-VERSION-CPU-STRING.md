# Version: полная CPU-строка и source enum form

20 октября 2026. Продолжение [CPU initializer](HEADLESS-GAME-LOGIN-INPUTS.md)
и [Windows / platform context](HEADLESS-VERSION-WINDOWS-CONTEXT.md).
Два поля Version теперь подготавливаются общим runtime из явных входов:
Windows context по +0x28 и CPU text по +0x38. Остальные поля и сетевой
bootstrap этим helper не выбираются. Игровой Version / Login не отправлялся.

## Источник и Ghidra

Собранный Windows EXE:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Память игры не читалась, её процесс не запускался.

После чтения существующего экспорта Ghidra дополнены enum object constructor
и setter. Два других кандидата проверены в промежуточном экспорте и не включены
в окончательный manifest. Итог — 295 функций / 121 предупреждение.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-bed761f3d699`.
Manifest SHA256: `8f7fe5426f4f977cdf53b3f7c296571d12ffab997cd3cb347dd6cfc9843e61bc`.
functions.json SHA256: `ed5fa1bb8b5ce2381df90f50efc4b3bb0afcb6458a36ef91cea0f4c4d2df369b`.
Предупреждения сохранены. Имена аналитические, это не исходный C++ проект.

## Весь native путь CPU text

`replay-version-cpu-string.py` объединяет уже проверенный initializer
`0x140ff54a0`, getters `0x1415c1460` / `0x1415c1440` и полный formatter
`0x1414476a0`. Вызовы normalization `0x1414344c0` исполняются вместе с
trailing trim `0x1414342b0` и leading trim `0x141434530`. Эти две функции
проходят настоящие iswspace loops, удаляют крайние символы и перемещают
FString descriptors; результат не задаётся готовой строкой fixture.

У текущего compiled Windows path третий вход — literal Unknown.
После его нормализации выбирается формат `%s|%s`, аргументы — vendor и brand.
Итоговый local runtime профиль ограничен ASCII: whitespace — пробел, tab,
CR, LF, vertical tab и form feed. Unicode / locale parity не заявляется.
Пробелы внутри brand, Unknown в самой brand и внутренние `|` сохраняются.

Девять сценариев: обычные Intel / AMD, padding, смешанные whitespace,
brand только из whitespace, пустая brand, brand Unknown, внутренние `|`,
отсутствие extended CPUID brand и отключённый initializer с прежними буферами.
Для каждой комбинации исполняется вся цепочка до результата getter.
CPUID, ASCII iswspace, FString construction / allocation, memmove,
capacity shrink, formatter и cookie остаются bounded fixtures / hooks.
Альтернативная ветвь третьего входа не объявляется исполненной.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-cpu-string-replay.json`.
SHA256: `85c875dfb01fe03a906b4b645b264a7f1f4cee113900fb4fa2baf035a3c2c6fa`.

## Enum form из descriptor до Windows label

Настоящий constructor `0x1416bf350` устанавливает vtable `0x1489e4b80`
и обнуляет enum form. Его slot+0x2f8 указывает на setter `0x1417202f0`.
Slot bytes проверены непосредственно в EXE. Setter копирует массив members,
пишет R8B в object+0x50, R9B — в object+0x51.

В factory `0x1417cc270` источник аргументов подтверждён инструкциями:

- `0x1417cc4cb`: R9D из descriptor+0x2e.
- `0x1417cc4d4`: R8D из descriptor+0x2f.
- `0x1417cc4df`: virtual call через slot+0x2f8.

Descriptor ENnOsType содержит form 2 по +0x2f и flags 0 по +0x2e.
`replay-version-enum-form.py` выполняет constructor, настоящий factory prefix
с загрузками аргументов и virtual dispatch, setter до обоих stores, затем
selector и полный lookup/value. Для source descriptor получается form 2,
selector 3 и строка Windows без `ENnOsType::`.
Четыре сценария проверяют source pair (2,0), пары (0,0), (1,0) и (2,1).
Нулевой form возвращает полное имя ENnOsType::Windows; ненулевой удаляет scope.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-enum-form-replay.json`.
SHA256: `c8fc4c238d1abba2140bf3d0ec9512fcd02c678db03317e59e337b18f094d304`.
Полная reflection construction, package / object discovery, необязательное
добавление Max и registration после stores исключены. Base object constructor,
array allocation / copy, name pool и string helpers — fixtures. Это source
dataflow до lookup, не снимок активного reflection object игры.

## Общий runtime

`vampir_core.version_cpu.VersionCpuInput(vendor, brand)` принимает явные ASCII
строки с границами 12 / 48 символов. NUL, прочие control chars, Unicode
и oversized inputs отклоняются; hardware strings скрыты из repr.
`text()` удаляет только проверенные крайние ASCII whitespace и соединяет
строки через `|`. Этот helper сам не запрашивает CPU, не придумывает марку
и не вызывает Capstone / Unicorn / Ghidra.

`version_inputs.bind_windows_version_inputs(payload, cpu=..., windows_version=...)`
заполняет только strings[1] / [2], соответствующие +0x28 / +0x38.
Первое поле — `Windows_` + suffix из проверенной модели WindowsVersion;
None явно обозначает отказ OS API и даёт Windows_. Порядок concatenation
следует прежнему [Version_Prepare](HEADLESS-CONNECTED-VERSION-PACKET.md);
внутренности общих FString concatenation helpers в новый replay не входят.
Второе поле — CPU text. Исходный immutable payload не меняется.
Уже заполненное отличающееся значение вызывает отказ вместо замены контекста.

Helper не выбирает AppVersion, device key, callback string, compiled tag,
ключ шифрования, sequence или сервер. Наблюдение CPU для настоящего runtime
и остальные Login inputs ещё нужно подключить. Пустые поля не выдаются
за готовый реальный Version payload.

## Проверки

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_cpu_string.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_version_enum_form.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_windows_version.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_version_packet_writer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Все 16 целевых проверок прошли: четыре CPU / binding, одна enum form,
пять Windows version, три Version writer и три Ghidra provenance.
Проверяется воспроизводимость отчётов, сохранение прочих полей шаблона,
отказ при конфликте, ограничения ASCII и все прежние native writer vectors.
