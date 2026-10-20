# Windows suffix и platform context для игрового входа

20 октября 2026. Продолжение [проверки полей Version / Login](HEADLESS-GAME-LOGIN-INPUTS.md).
Windows suffix теперь читается runtime бота и передаётся в NID как osVersion.
Повторный реальный SDK SignIn через HK с этим полем принят сервером.
Игровой Version / Login ещё не отправлялся, персонажи не получены.

## Источники и инструменты

Собранный Windows EXE:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Игра и чтение памяти её процесса не использовались.

Сначала прочитан существующий экспорт Ghidra и исходные связи. Дополнительно
экспортированы enum constructor / singleton и две trim routines.
Всего 293 функции / 121 предупреждение, Ghidra 12.1.4:
`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-afed15ecc141`.
Manifest SHA256: `9e79c6a658f639432580d5b26498be1bb14cc78466de4ce61ec52457bd009689`.
functions.json SHA256: `a90bd985703935018d418de8c8b20692cfae4b0d5be9ad4822d918e673d03aee`.
Предупреждения сохранены; восстановленные типы не считаются исходным C++.

## Полный native getter Windows suffix

`replay-version-windows-suffix.py` исполняет функцию `0x1415c3960` целиком:
TLS guard → GetNativeSystemInfo → обнуление структуры → GetVersionExW →
сбор аргументов formatter → сохранение кеша → FString.

| Формат | Native operand | OSVERSIONINFOEXW field |
| --- | --- | --- |
| 1 | DWORD structure+0x04 | dwMajorVersion |
| 2 | DWORD structure+0x08 | dwMinorVersion |
| 3 | DWORD structure+0x0c | dwBuildNumber |
| 4 | BYTE structure+0x11a | wProductType |
| 5 | WORD structure+0x118 | wSuiteMask |
| 6 | literal 64bit | Постоянная строка этого Windows EXE |

Итог: `%d.%d.%d.%d.%d.64bit`. DWORD передаются в `%d` с исходными raw bits;
например 0xffffffff печатается как -1. wServicePackMajor расположен по +0x114
и в formatter не передаётся. При проверке эта разница уточнена по инструкциям,
структуре ctypes и отдельным sentinel values, а не по имени локальной переменной
декомпилятора. GetNativeSystemInfo вызывается, но показанный путь не выбирает
по его данным другую suffix label.

Семь сценариев: два обычных Windows-профиля, профиль 6.2, нулевые поля,
границы signed DWORD / byte / word, отказ API и уже заполненный кеш.
Повторный вызов в каждом сценарии возвращает тот же результат без повторных
OS / formatter events. При отказе GetVersionExW кеш становится пустым,
инициализация завершается. Guard / TLS, OS APIs, FString constructor,
memset, formatter и cookie — явные fixtures / hooks; CRT formatter не исполнен.
Native argument assembly, ветвления и сохранение / использование кеша исполнены.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-windows-suffix-replay.json`.
SHA256: `ad3e03b5779c8ef53e091985859eaa78936d2f44d65e2a3411a26e322e55e28e`.

## Перенос в runtime и настоящая проверка

`vampir_core.windows_version.WindowsVersion` хранит пять проверенных полей
и форматирует их в том же порядке. Типы и unsigned bounds проверяются до
форматирования; bool вместо int отклоняется. `observe_windows_version()`
лениво вызывает kernel32.GetVersionExW с точной структурой 0x11c, только
в 64-битном Windows-процессе. Отказ API возвращает None; runner передаёт
пустой osVersion без другого fallback. На Android этот reader не вызывается.

Это версия, сообщённая API процессу бота с его manifest / compatibility policy.
Она не объявляется kernel version или прочитанным значением кеша игры.
Фактический результат на этом ПК: `10.0.26200.1.256.64bit`.
NID wrapper `0x1444e64f0` вызывает тот же native suffix getter; связь уже
присутствовала в [исследовании NID](HEADLESS-NID-WEB-CONTEXT.md).
Runner теперь использует новое наблюдение вместо пустого поля source profile.

Для реальной проверки заново подключён личный HK-выход, Cloudflare подтвердил
HK, GMC2 через тот же SOCKS вернул HTTP 200 / 13 777 байт. Manifest:
`F:/PhoneExit Resources/Vampir/public-gmc2-snapshots/bd8606d0bd070a1a03957e195e022b027663377d670dab535783425308e81cb1/manifest.json`.
SHA256 manifest совпадает с именем каталога. С заполненным osVersion получены
NID callback и принятый SDK SignIn, player ID / SDK token присутствуют.
Секреты не выводились и не сохранялись. Временный HK-клиент штатно остановлен,
exit 0; системные маршруты не менялись.

## Platform context: ENnOsType и native lookup

Указатель из `0x1445d23b0` ведёт к construction descriptor `0x14b117630`:
name ENnOsType, пять элементов, member table `0x1494fedf0`.
Переиспользован существующий extractor contiguous name-pointer / int64 rows;
дополнительно проверено, что descriptor выбирает именно этот массив.

| Value | Запись |
| --- | --- |
| 0 | ENnOsType::Unknown |
| 1 | ENnOsType::Android |
| 2 | ENnOsType::iOS |
| 3 | ENnOsType::Windows |
| 4 | ENnOsType::Max |

Native enum constructor читает count+0x2c / table+0x20 и передаёт собранный
массив, bytes+0x2e / +0x2f в virtual+0x2f8. Singleton helper получает
этот enum accessor. Полный reflection backend и virtual+0x2f8 не исполнены;
фактический object+0x50 ещё не объявлен доказанным.

`replay-version-platform-context.py` исполняет настоящий selector вместе
с compiled Windows name getter, затем полный lookup `0x1416d7af0` и value
`0x1416d7a10`. Name pool / сравнение / поиск `::` / substring — hooks;
reflection object построен из source descriptor как явный fixture.
В 12 сценариях проверены оба значения scoped flag и keys 3 / 0 / 1 / 2 / 4 / 99.
Selector возвращает 3. Для key 3 lookup возвращает ENnOsType::Windows при
flag 0 и Windows при flag 1; отсутствующий key даёт пустую строку.
Это не произвольный context store и не ENMPlatformType SDK.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-platform-context-replay.json`.
SHA256: `6ebea4f461c443fd7d73681d5c0b5b801e9d71b81d00a12df3a9df92436423fe`.

Новые Ghidra trim routines подтверждают trailing / leading iswspace loops
для CPU-строк. Их полное исполнение и locale / Unicode semantics остаются
следующим шагом вместе с итоговым форматированием Version+0x38.
Текущий результат не подставляет догадку о scoped flag в готовый Version.

## Проверки

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_windows_version.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_version_platform_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_sdk_runner.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Пять Windows tests проверяют native report / runtime parity, границы,
offsets suiteMask против servicePackMajor, отказ API и платформу.
Отдельный platform test воспроизводит 12 native сценариев и source descriptor.
Шесть runner tests проверяют перенос наблюдения в профиль и пустое поле
при отказе API. Три Ghidra tests проверяют целостность полного экспорта.
Все 15 целевых проверок прошли.
Далее — native enum scoped flag, полная CPU-строка и остальные Login inputs,
затем игровой обмен через HK и список / выбор персонажа.
