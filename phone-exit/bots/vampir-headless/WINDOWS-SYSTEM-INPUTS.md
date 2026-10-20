# Реальные CPU inputs без запуска игры

20 октября 2026. Добавлен собственный Windows helper для CPUID. Собраны
DLL и Python reader, наблюдены реальные vendor / brand и подготовлены два
проверенных поля Version. Игра не запускается, её память / реестр не читаются.
Полный игровой Version / Login пока не отправляется.

## Источник поведения

Порядок CPUID и формат строк установлены по собранному клиенту SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Сначала использованы уже проверенные [initializer / getters](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-GAME-LOGIN-INPUTS.md)
и [полная CPU-цепочка / binding](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-VERSION-CPU-STRING.md).
DLL не содержит игровой код и не загружает его: это собственная реализация
простого чтения CPUID с установленным порядком регистров.

## Собственный helper

`windows/system-inputs.cpp` экспортирует одну функцию `vampir_read_cpu`.
Она принимает два буфера с размерами, отклоняет null / недостаточные буферы
до записи и читает:

- Vendor: CPUID leaf 0, порядок EBX / EDX / ECX, максимум 12 байт + NUL.
- Brand: три leaf 0x80000002–0x80000004, если extended max не меньше
  0x80000004; иначе пустая строка. Максимум 48 байт + NUL.

Helper не использует game SDK, Capstone, Unicorn, Ghidra, process inspection,
реестр, сеть или собственные постоянные фоновые процессы. Его DLL загружается
только в процесс бота на Windows x64. Android этот reader не вызывает.

## Сборка

Используются уже установленные MSVC 14.44.35207 / v143 и Windows SDK
10.0.22621.0. Скрипт ничего не устанавливает и не меняет системный PATH.

```powershell
pwsh -NoProfile -File phone-exit/bots/vampir-headless/build-system-inputs.ps1
python -X utf8 phone-exit/bots/vampir-headless/windows-system-inputs.py --check
```

MSBuild собирает проект `windows/system-inputs.vcxproj` в игнорируемую
`phone-exit/.tools/vampir-runtime-windows/`. Логи, объекты, LIB / EXP / DLL
и receipt не коммитятся. Runtime использует только свою DLL, сборочные SDK
для её загрузки не нужны. Static CRT включён, отдельный VC redistributable
не требуется. Компилятор / linker используют `/Brepro`; две последовательные
пересборки в текущем workspace дали одинаковый binary SHA256.
Это проверка воспроизводимости при текущих путях / toolchain, не гарантия
побайтного совпадения на любой машине.

Собрано без ошибок / предупреждений, DLL — 106 496 байт (104 КиБ).
SHA256: `6a63c280d35ee267e0bea29ab0c64dda2f8a7d8fd07d84115c285144d69b964d`.
SHA256 compiler cl.exe: `fe251ef50a1545b1b0835ee17b1e785459712b38d79e45b5c1d3d28970a36619`.
Receipt содержит версию toolchain / SDK, SHA source / project / build script
и полученного binary. При изменении этих исходных файлов adapter требует
пересборку вместо использования прежнего helper.

## Runtime API и проверка

`vampir_core.windows_cpu.observe_windows_cpu(library_path, expected_sha256=...)`
проверяет Windows / 64-bit, явный SHA, путь DLL, размер не больше 1 МиБ
и содержимое файла до загрузки. Затем вызывает точный C ABI, проверяет return
и NUL terminators. Неподдержанный ASCII input отклоняется; fallback на WMI,
реестр или выдуманную модель CPU отсутствует. SHA берётся из доверенного
локального build receipt, а не из произвольного сетевого ответа.

`windows-system-inputs.py` использует фиксированную папку build output,
проверяет schema / architecture / toolchain и SHA текущих source files.
`observe_inputs()` возвращает VersionCpuInput и WindowsVersion / None.
`bind_observed_inputs(payload)` передаёт их в уже проверенный binding двух
полей Version, сохраняя остальные поля явного immutable template.
AppVersion, device key, callback string, compiled globals, sequence и сервер
этот adapter не назначает.

Реальный `--check` подтвердил CPU observation, vendor длиной 12 байт,
brand длиной 47 байт, корректный CPU text и успешный Windows API. В выводе
только флаги и длины: сами hardware strings не сохранялись и не печатались.
Hash mismatch отклоняется до WinDLL. На платформах без Windows библиотека
не загружается. WindowsVersion по-прежнему описывает API процесса бота,
а не кеш игры или гарантированную kernel version.

Реальные строки дополнительно переданы как CPUID fixtures в существующий
Unicorn replay полного native initializer / getters / trim / formatter.
Результат совпал с CPU text helper. Это сопоставление наблюдения с native
алгоритмом; CPUID самой игры в эмуляторе остаётся fixture. Реальные значения
не включались в JSON reports, логи, документацию или Git.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_windows_cpu.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_cpu_string.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_windows_version.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_context.py
```

Все 19 целевых тестов прошли: пять CPU reader / actual DLL, четыре CPU format /
binding, пять Windows version и пять Login context. Проверены настоящие C ABI
отказы на коротких / null buffers без записи, SHA до загрузки, неподдержанный
текст, сохранение других полей Version и отказ при конфликте контекста.
В тестах без собранной DLL или вне Windows две реальные проверки helper
явно пропускаются, а не объявляются пройденными.

Далее — согласованный профиль AppVersion / конфигурации, реальные параметры
соединения и оставшиеся Login inputs, затем контролируемый обмен с сервером
через HK. Наличие двух подготовленных полей ещё не доказывает готовый Login.
