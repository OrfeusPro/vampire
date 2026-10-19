# GMC2 DecryptXOR: 16-битные единицы и пропуск нуля

19 октября 2026. Полный helper `1444ddf50` и actual FString append `1414242a0`
исполнены на 18 fixtures. Преобразование использует повторяющиеся 16-битные
единицы ключа и пропускает нулевые результаты через штатную ветку append.
Общий xor_gmc2_utf16_units побайтно совпал с native output units.
Это отдельный primitive, не завершённое декодирование GMC2 response.

## Источник и воспроизведение

[build-headless-gmc2-xor.py](build-headless-gmc2-xor.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-gmc2-xor.py`.
EXE SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Та же локальная цепочка Image/Capstone 5.0.6/Unicorn 2.1.4, что в
[GMC2 graph](HEADLESS-SDK-CONFIG.md). Нет account files, процесса игры,
чтения памяти, device identity, HTTP или реальных ключей сессии.

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-gmc2-xor.json`,
SHA256 `09c99ead722fcbd2eba01af9fd35fa08326785b882e3b871b4dd1d26406cf93c`.
Включены source instructions/file offsets/bytes/fragment SHA, ParseConstants
caller context, все входные/выходные uint16 fixtures и guard/termination checks.

## Наблюдаемая семантика

| Участок | Подтверждение |
|---|---|
| Source | R8 descriptor → pointer/count; цикл обрабатывает ровно count units |
| Key | R9 FString descriptor; период=count-1 при count>0 |
| `1444de003` | signed idiv периода для индекса key |
| `1444de00e` | загружает word key[index % period] |
| `1444de015` | XOR DX с word source[index] |
| `1444de019` | вызывает FString append1414242a0 |
| `1414242b0..2b3` | DX==0 → return, без добавления единицы |
| Остальной append | добавляет nonzero unit и поддерживает storage terminator |
| Caller `1444f0f6e` | ParseConstantsTemplateGroups вызывает helper до JSON parse |

Key fixtures задают логические units и отдельный storage NUL; период не включает
этот storage terminator. Source descriptor count используется как есть: нельзя
самовольно вычитать один или обрезать source по нулю. Например source [0,0,0]
с key [1,2] даёт [1,2,1], а source [1,0,1,0] с key [1] — [1,1].
Результат не обязан быть корректным Unicode: unpaired surrogate units сохраняются.
Это не UTF-8 byte XOR и не обычная обратимая XOR-функция с сохранением нулей.

Пустой логический key даёт нулевой период. Для непустого source native idiv
тогда ведёт к division-by-zero; эта опасная ветка установлена по инструкциям,
а не исполнена в fixtures. Общий helper отклоняет empty key до вычислений,
включая empty source. В native empty source цикл пропускается.

## Native исполнение и локальные ограничения

Целиком исполнены XOR helper и single-unit append. Logging отключён явным
fixture byte `14b4f2060`, полученным из RIP reference инструкции 1444ddf61;
diagnostic ветка не исполнялась. Output growth — bounded shim,
copy/output writes и append zero gate native. До/после 16-byte output descriptor
стоят guards; output terminator проверяется. Fixtures включают все source
units 0..255, high units/surrogates, zero outcomes, repeated keys, 1024 nonzero
и 1024 полностью обнуляющихся результатов. Лимит инструкций 131072.
Это не полный allocator/string runtime или ошибки heap allocation.

Общий `vampir-shared/vampir_core/gmc2_decode.py` принимает bytes с little-endian
uint16 units, key без storage terminator. Возвращает raw bytes units без
storage terminator. Никакого Base64/Unicode/JSON guessing, key acquisition,
active defaults или I/O. Local budgets: source максимум 2 МиБ, key непустой
до 8192 байт, оба буфера чётной длины; bytearray/другие типы отклоняются.
Это локальные границы, не серверные лимиты. Нули ключа как units разрешены,
потому что native использует descriptor count, а не C-string scan.

Четыре теста сверяют source/word width/idiv/append gate/caller, повторяют
18 native fixtures и общий primitive, проверяют raw surrogates/source count,
input types/size budgets и воспроизводимость report. `network_ready=false`.
Далее нужно доказать предшествующее извлечение/декодирование encConstants,
происхождение key/DECKEY, encSecretConstants и конечный JSON/schema.
Статическое соседство полей пока не объявляется полной цепочкой расшифровки.
