# Источники оставшихся полей Version / Login

20 октября 2026. После успешных SDK SignUp / SignIn проверены оставшиеся
источники игровых пакетов. Игровой сокет пока не открывался: SDK token
сам по себе не заполняет все поля Version / Login и не разрешает переход
к списку персонажей.

## Источник и экспорт

Собранный Windows EXE:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это код клиента, не доступный исходный C++ проект.

Сначала прочитаны существующие [Version fields](HEADLESS-CONNECTED-VERSION-PACKET.md),
[Login fields](HEADLESS-LOGIN-PACKET-FIELDS.md),
[device input](HEADLESS-VERSION-DEVICE-INPUT.md) и общий индекс Ghidra.
Добавлены восемь функций, всего 289 функций / 120 предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-cf27bd2c85fb`.
Manifest SHA256: `cd0133da09ad2eab3bc37ed8fc7d07c337f31ef7ea5eba5361243f755cceb97a`.
functions.json SHA256: `55a5e3e25e6ad4733c604cf2bc8f0dde6136a5c0661ddb031d490fae3b87c8cd`.

`build-game-login-input-index.py` переиспользует проверенные PE / unwind /
Capstone helpers. Поиск кандидатов RIP ограничен common memory encodings
и соседями двух буферов; истинные ссылки принимаются только после полного
декодирования с границы unwind. Это не исчерпывающий список записей global
и не доказательство отсутствия последующих overrides.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/game-login-input-index.json`.
SHA256: `0bef74165d72f473ec577e87e78da8eaa015cfcb5b502a2742e2dd8a1bf685c1`.
Сохранены участки, инструкции, file offsets, literals и SHA.

## Подтверждённые связи

| Поле | Источник | Что установлено |
| --- | --- | --- |
| Version+0x10 / Login+0x40 | global 0x14b520d10 | AppVersion из NetworkSetting; в PE это zero-fill, не готовая строка |
| Version+0x38 | getter 0x1414476a0 | Формат двух / трёх строк через `\|`; первые два источника — CPU vendor / brand |
| Version+0xb0 / Login+0x110 | pointer global 0x14b14ae28 | В PE указывает на ASCII `AC7F34E3AFA91ED417BE86CD45BF18C8` |
| Version+0xc0 / Login+0x120 | DWORD global 0x14b125530 | В PE значение 1; семантика и отсутствие runtime-записей не доказаны |
| Login+0x98 | selector 0x1445c77a0 | Для compiled platform name Windows выбирается 3, ранее проверенный mapping даёт byte 3 |
| Version+0x28 | context lookup + `_` + Windows suffix | Источники уточнены, итоговая строка текущего ПК ещё не восстановлена |

Compiled ASCII строка не названа SHA, версией протокола или device ID:
такая семантика не установлена. Её статическая связь с пакетами подтверждена
прежними preparation replay и текущими instruction references. Активные значения
процесса не читались. AppVersion основного INI ранее найден как 1.12.14,
но [порядок config overrides](HEADLESS-CONFIG-STARTUP.md) ещё требует проверки.

## CPU vendor / brand: полное native исполнение

Initializer `0x140ff54a0` пишет ASCII vendor в `0x14b058cb2` из CPUID leaf 0
в порядке EBX / EDX / ECX и завершает его NUL. Brand в `0x14b058cbf`
собирается из CPUID 0x80000002–0x80000004, если максимальный extended leaf
не меньше 0x80000004. Без поддержки brand очищается. При нулевом
`0x14b058cb0` initializer пропускает заполнение обоих буферов.

Getter `0x1415c1460` копирует vendor, `0x1415c1440` — brand в FString.
Ghidra показала intrinsic CPUID с предупреждениями об удалённых блоках;
смысл проверен по фактическим инструкциям и исполнением, не по одному
восстановленному порядку регистров в псевдокоде.

`replay-version-cpu-input.py` исполняет initializer целиком и оба getter
в одном экземпляре Unicorn на четырёх сценариях: Intel, AMD с padding,
неподдержанный extended brand и выключенный initializer с прежними строками.
Все outputs совпали с отдельной ожидаемой моделью. CPUID registers — явные
fixtures, FString ASCII constructor / CPU feature predicate / cookie — hooks.
Сведения CPU данного ПК не считывались. Trim и итоговое форматирование
`0x1414476a0` этим replay не исполнялись; padding намеренно сохраняется.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-cpu-input-replay.json`.
SHA256: `018b291b09e84ee16e5c5330b0872493f992a4bdc4839253c8b12b33d929f6db`.

## Platform context и Windows suffix

`0x143c13690` конструирует строку из compiled ASCII Windows по адресу
`0x14899fb38`. Selector `0x1445c77a0` сравнивает её с Android / IOS / Windows
и выбирает 1 / 2 / 3 соответственно; прочие значения дают 0.
Это статическая связь и литералы текущего EXE, отдельного replay selector нет.

`0x1445bdfe0` получает reflection object через enum accessor `0x1445d23b0`
и global `0x14b117630`. Его имя и текущие enum entries ещё не установлены.
Ранее экспортированный lookup ищет key в массиве, а value helper может
удалять prefix до `::` при выставленном object+0x50. Нельзя заменять содержимое
этого store строкой Windows только по смысловому сходству.

Windows suffix `0x1415c3960` использует GetNativeSystemInfo / GetVersionExW,
формат `%d.%d.%d.%d.%d.%s` и literal 64bit. Полный helper с OS fixtures,
получение актуальных значений и комбинация context + `_` + suffix ещё открыты.

## Проверки и следующие действия

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-game-login-input-index.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-version-cpu-input.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_version_cpu_input.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Три новые проверки воспроизводят отчёты, проверяют реальные source bytes,
CPUID leaves, padding и отключённую ветвь. Три проверки Ghidra подтвердили
provenance и полный экспорт. Все шесть прошли. Runtime пока не менялся: частично установленные поля
не превращены в шаблон с догадками. Следом — завершить platform context /
Windows suffix и остальные Login inputs, затем контролируемый игровой вход
через HK и lifecycle списка персонажей.
