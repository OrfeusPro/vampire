# Login: поля настроек, режима и SDK-объекта

20 октября 2026. Продолжение [источников полей Login](HEADLESS-LOGIN-PACKET-FIELDS.md).
Источник — код установленного Windows-клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Что подтверждено

| Поле Login | Источник | Поведение |
| --- | --- | --- |
| byte +0x124 | getter 0x145564550 → global 0x14b573398 → object+0x18 | Копируется исходный байт, без нормализации |
| byte +0x130 | getter 0x145cb2f60 → global 0x14b57f360; 0x145cb95e0 | При включённой SDK-ветви: 1, если object+8 равен 3; иначе 0 |
| byte +0x131 | manager+0x68; getter 0x144ff8cd0 | При включённой SDK-ветви и ненулевых manager / object копируется исходный object+0x39; иначе остаётся 0 |
| string +0xd8 | manager+0x48 | Без этого объекта строка остаётся пустой; collector вызывается только при его наличии |

Имена и прикладной смысл этих трёх байтов пока не установлены. Два исходных
байта сохраняют 7 и 255; превращать их в bool нельзя. Байт +0x130 вычисляется
отдельно и действительно имеет значения 0 / 1. Проверка режима не зависит
от наличия SDK manager: она выполняется при включённой общей SDK-ветви.

Конструктор режима 0x145ca7240 записывает singleton и byte object+8 = 0.
Его создание вызывается из SelectionService_DerivedInit по 0x145dc79c6.
Конструктор настроек 0x145556120 записывает другой singleton, но byte +0x18
не заполняет. Три исполнения на объектах с заполнением 0 / 127 / 255
сохранили это значение до поля Login +0x124. Это не доказательство
неинициализированного значения в настоящем клиенте: последующие записи
при настройке ещё нужно связать. Начальный ноль для него не установлен.

Для Login uint32 +0x50 найден конкретный источник: BeginGame по
0x146425acb сохраняет результат `_wtoi` в global 0x14b520cb8;
Login по 0x1467a991b читает тот же global. Перед преобразованием текст
извлекается через 0x141432680 из объекта `[title+0xb78]+0x1b0`.
Связь этого объекта с контролом и его начальным текстом ещё не подтверждена.
Число нельзя объявлять ID сервера: выбранный server ID отдельно идёт в +0xb0.

## Исполнение и границы

[replay-login-policy-inputs.py](../../../replay-login-policy-inputs.py) использует
существующий native replay подготовки Login и заменяет четыре прежние
заглушки фактическими singleton / flag getters. Выполнены 43 сценария:
36 комбинаций policy 0 / 7 / 255, mode 0 / 3 / 255 и SDK byte 0 / 1 / 7 / 255;
четыре проверки SDK / manager gates; три проверки конструкторов.

В каждом сценарии исполняются подготовка Login до handoff, constructor пакета
и getter leaves. Сравниваются поля пакета, входы в getters, сохранение отдельных
NID / SDK token и ветвь metadata. Объекты настроек и режима выделены отдельно;
SDK object +0x39 не перекрывает manager pointer +0x38. Строковые primitives,
collector, request handoff и остальные старые hooks остаются ограниченными
fixtures. Начальные policy / SDK values — тестовые, не значения аккаунта.
Writer, socket, backend initialization и post-send UI здесь не исполняются.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/login-policy-inputs-replay.json`.
SHA256: `84ca97e19ee0d16c5dd321e8390c8d49cdf8091a000b3921d1d60e7f7fb710b3`.

[build-login-policy-state-index.py](../../../build-login-policy-state-index.py)
с готовым PE / RIP indexer находит 15 подтверждённых references в 11 unwind
roots. Поиск кандидатов не является исчерпывающим списком всех записей.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/login-policy-state-index.json`.
SHA256: `39c7b1d75fac7bcd6fa1085ef76b1b71cc07fd4f16e82060d9816fdf08b4eafe`.

Ghidra 12.1.4: 349 функций / 157 предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-53d7341d523d`.
Manifest SHA256: `364deec233c1341fe6d75d77c9e0181e5aefda5527d37e05bad4ca4580eba420`.
functions.json SHA256: `02d7ba276136a114f57e8c95dbff909a2bb285ac6af393d20259479ce6bc0ca7`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-policy-inputs.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-login-policy-state-index.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_policy_inputs.py
```

Четыре новые проверки, три прежние проверки полей Login и три проверки
экспорта Ghidra прошли. Runtime и реальные состояния аккаунта не
менялись, сетевых попыток не было. Далее — записи policy+0x18, источник
wrapper+0x100 и оставшийся контекст Login, затем Version → Login на одном
соединении до списка / выбора персонажа.
