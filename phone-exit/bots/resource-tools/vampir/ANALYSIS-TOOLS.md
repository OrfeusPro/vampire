# Vampir: выбор инструментов исследования

Проверено 19 октября 2026. Общее правило закреплено в корневом
[AGENTS.md](../../../../AGENTS.md). Готовые результаты искать через
[главный указатель](../../vampir/README.md) и [индекс ресурсов](RESOURCE-INDEX.md).
Инструменты используются при разработке; в приложение бота они не входят.

Перед новым исследованием сверять адрес и имя через `function-registry.py --query`;
правила структуры, доказательств и текущих вопросов — в
[knowledge/README.md](knowledge/README.md). Если база устарела, выполнить
`function-registry.py --build`; query проверяет SHA входных материалов.

| Задача | Инструмент и порядок | Фактически проверено |
| --- | --- | --- |
| Функции EXE/DLL, ветвления, callers/callees | Ghidra, сначала существующий экспорт | 22 функции; повторный экспорт совпал побайтно |
| Инструкции и поведение native-кода | Capstone/Unicorn после Ghidra | Существующие source-bound replay scenarios; подробности в основном README |
| Unreal PAK и cooked assets | CUE4Parse, если формат и входные данные поддержаны | Установка/сборка, заголовки трёх loose assets; четыре PAK заблокированы зашифрованным индексом |
| Reflection, классы, SDK, mappings | Dumper-7 для отдельного live-эксперимента | DLL собрана; разрешённая проверка 20 октября остановилась на EnumProcessModules до загрузки DLL; SDK ещё нет |
| Прямой TCP-захват Windows | PktMon с явным включением и правами администратора; затем [импорт PCAPNG](import-pcapng-tcp.py) | Первый прямой захват сохранён; импорт выявил пропуски игровых TCP-байтов. Полная сессия не восстановлена |
| Подтверждённый нестандартный формат / PAK без доступного индекса | Существующие scanner и декодеры | Сохраняются действующие извлечения; не заменять проверенный путь неподтверждённым |

## Ghidra

[Полная инструкция](knowledge/evidence/tools/HEADLESS-GHIDRA.md), закрепление в `ghidra-tools.lock.json`.
Ghidra 12.1.4 и отдельная Temurin JDK21 установлены вне Git. Общие результаты:
`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Для очередного участка сначала читать `.c` и call graph, затем дополнять manifest
и пакетный экспорт. Ручной disassembly нужен для неоднозначности псевдокода,
границ функции, calling convention и проверки поведения. Decompiler warnings
сохранять. Угаданный тип или название функции не доказывает её семантику.

## Установка CUE4Parse и Dumper-7

Официальные источники: [CUE4Parse](https://github.com/FabianFG/CUE4Parse),
[Dumper-7](https://github.com/Encryqed/Dumper-7).
Закрепление архивов/версий/SHA: `secondary-tools.lock.json`.
Транзитивные NuGet зависимости и content hashes: `cue4parse-probe/packages.lock.json`.

- CUE4Parse `1.2.2.202610`, upstream commit
  `1e3293d4b3ecaf6ef3d73641b9ffe47fa4cf1562`, Apache-2.0.
- Отдельный portable .NET SDK `10.0.402`, официальный архив Microsoft с SHA512.
  Системный .NET и Android JDK не меняются.
- Dumper-7 commit `90d1f390d26e31a1f71d29af56c6bd2f240b7493`.
  Собран имеющимся Visual Studio Build Tools 2022 / MSVC 14.44 / `v143`.
  Upstream указывает `v145`; передаём `PlatformToolset=v143` без правки исходников.
  Собираем `Dumper/Dumper.vcxproj`: общий `.sln` ссылается на отсутствующий
  `SDKTest/SDKTest.vcxproj`, поэтому сборка решения целиком завершается ошибкой.
  Первичная компиляция имела upstream C4018/C4244/C4267/C4305 warnings;
  итоговая сборка проекта успешна. Это не проверка сгенерированного SDK.

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/install-secondary-tools.py
python -X utf8 phone-exit/bots/resource-tools/vampir/check-secondary-tools.py
```

Установка проверяет хеши скачанных архивов, безопасные пути ZIP, собирает probe
с `RestoreLockedMode=true` и DLL. Нужен установленный MSBuild с C++ v143.
По умолчанию всё находится в `F:/PhoneExit Resources/Vampir/tools/`;
корень библиотеки можно задать `PHONEEXIT_VAMPIR_RESOURCES`.
`secondary-tools-install.json` хранит пути и SHA собранных DLL,
`secondary-tools-check.json` — SHA входов, результаты, ошибки и границы проверки.
Повторная установка и повторная проверка пройдены.
[Снимок результатов с SHA входов и инструментов](secondary-tools-evidence.json)
хранится в Git; полные логи остаются в библиотеке ресурсов.

При первом restore NuGet сообщил NU1903 для транзитивного
`Microsoft.Bcl.Memory 9.0.0`. В probe явно закреплён исправленный `9.0.14`
([официальное уведомление Microsoft](https://github.com/dotnet/announcements/issues/384)).
Повторная сборка: 0 ошибок, 0 предупреждений; предупреждение не подавлялось.

## Проверка на данных Vampir

Probe читает файлы, не запускает клиент и не получает ключи или профиль аккаунта.
Профиль `GAME_UE5_5` выбран по ранее найденному литералу EXE
`E:/Work/UE5/Release-5.5/.../GameEngine.cpp`;
[привязка и границы](knowledge/evidence/game-data/NPC-LOOT.md). Это не полное определение cooked custom versions.
Предварительные пробы `UE4_27/UE5_0` дали overflow на loose header;
некоторые другие UE5 profiles тоже читают этот header, поэтому сам успех
чтения не доказывает версию движка.

| Вход | Результат |
| --- | --- |
| `pakchunk103-Windows.pak` | PAK v11, encrypted index, mount не выполнялся |
| `pakchunk101-Windows.pak` | PAK v11, encrypted index, mount не выполнялся |
| `pakchunk100-Windows.pak` | PAK v11, encrypted index, mount не выполнялся |
| `ProjectRED-Windows.pak` | PAK v11, encrypted index, mount не выполнялся |
| `pak-extracted/ProjectRED-Windows/000001.uasset` | Header 1039 bytes, names10, exports1/imports3 |
| `pak-extracted/ProjectRED-Windows/000003.uasset` | Header 1129 bytes, names10, exports1/imports3 |
| `pak-extracted/ProjectRED-Windows/000007.uasset` | Header 900 bytes, names10, exports1/imports3 |

Три header совпали с существующим layout из `inspect-ui.py` по name offset/count,
export/import counts. Проверены границы summary/name table/полного header;
SHA каждого входа, номер записи, источник PAK и его версия записаны в отчёте.
Полный SHA PAK вычисляется по фактическому файлу, отдельно от старого sample SHA
из `pc-pak-inventory.json`. Извлечение/decompression средствами CUE4Parse,
UObject properties, DataTable и карта этим тестом не подтверждены.

Практический результат: CUE4Parse уже пригодна как независимая проверка header.
Для ускорения полного разбора нужны проверенные mappings/custom versions и,
для штатного mount этих PAK, доступный ключ индекса. До этого основной путь —
существующий scanner нешифрованных записей. Повторять те же попытки без новых
данных не нужно. FModel — отдельный GUI на этой библиотеке; в этой работе
не устанавливался, оснований ожидать обход данного ограничения нет.

## Dumper-7: что готово и что осталось

20 октября пользователь разрешил live-эксперимент. Повышенный helper получил
отказ 5 при перечислении модулей, до загрузки DLL. SDK не получен; причина
отказа и совместимость не установлены.
[Точные условия и отчёты](knowledge/evidence/tools/HEADLESS-DUMPER7-LIVE.md).

DLL: `tools/dumper7/Dumper-7-90d1f390d26e31a1f71d29af56c6bd2f240b7493/Dumper/x64/Release/Dumper-7.dll`
относительно библиотеки Vampir. Проверены сигнатуры MZ/PE, machine `0x8664`,
флаг DLL, SHA256. DLL не загружалась в процесс и не внедрялась в Vampir.
Совместимость поиска GObjects/FName/ProcessEvent и создание SDK/mappings
остаются неизвестными. Официальный workflow требует DLL injection в работающий
клиент; это отдельный эксперимент после явного согласования пользователя.
Получение SDK не восстанавливает исходный C++ и не расшифровывает игровой
сетевой протокол автоматически.

После обновления клиента сначала сверять исходный SHA и структуру ресурсов.
Кэш, адреса и mappings предыдущей версии помечать прежней версией;
повторять только затронутые исследования. Ни один из этих инструментов
не нужен для обычной работы будущего лёгкого headless-бота.
