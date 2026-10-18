# CDN URL: завершающая сборка строки

19 октября 2026. Продолжение [выбора CDN базы](HEADLESS-CDN-SELECTION.md).
Подтверждена сборка адреса из уже подготовленных ASCII-фрагментов.
Это ещё не получение действующего URL: источник конфигурации и преобразование
AppVersion остаются открытыми зависимостями.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA для image base `0x140000000`; версия Android и её реализация не проверены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-url.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_url.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-url.json`, SHA256
`8267c74f094ec5521f8488c4e4e41f06de20da0c1f5c164926e85c2f2bb2289e`.
Сохранены source/tool/prior-report SHA, 4 unwind roots в 12 fragments,
1131 инструкция, источник имени файла, 16 native сценариев и журнал внешних
операций памяти. Закреплённые Capstone 5.0.6 / Unicorn 2.1.4.
Игра, аккаунты, сеть и память процессов не использовались.

## Исполненная часть

Slice Initialize `0x14563f758..0x14563f9d8` работает с пятью готовыми std::string:

| Фрагмент | Положение в native frame |
|---|---|
| base | rbp+0xc0 |
| platform | rbp+0xe0 |
| prefix | rbp+0x100 |
| filename | rbp+0x120 |
| version fragment | rbp-8 |

Выполняются настоящие инструкции caller, concat/move helper `0x145630d40`
и append/growth helper `0x1445d8310`. Внешние allocator/free/memcpy/memmove —
ограниченные shims в synthetic scratch. Сама конкатенация не заменена shim.
Проверены inline std::string capacity 15, точная heap capacity и запас 1024,
ветви повторного использования буфера, выделения, освобождения и memmove.
Всего в 16 сценариях: 26 allocation calls, 13 free, 91 memcpy и 15 memmove.
Это число вызовов fixtures, не нагрузочная характеристика клиента.

Подтверждённая форма результата:

```text
base + platform + "/" + prefix + "/" + version_fragment + "/config.json"
```

Между base и platform разделитель не добавляется. Если base завершается `/`,
получится обычный путь; без завершающего `/` строки склеиваются буквально.
Двойные слеши, пробелы и query text не нормализуются. Пустые фрагменты дают
пустые части пути. Это правило строковой сборки, не URL validity/server proof.

Имя `config.json` прослежено отдельно: global pointer `0x14b149ba0` содержит
`0x1498b9eb8`, где расположен ASCII literal config.json. Initialize читает
указатель на `0x14563f429`; файл не назван по предположению или строке из браузера.
Bytes pointer/literal и SHA256 literal сохранены в отчёте.

Проверены 8 наборов фрагментов в двух вариантах capacity, включая длинные
строки, пустые части, leading/trailing slash и query text. Native fixture
`https://cdn.invalid/`, `window`, `real`, `1_2_3` даёт
`https://cdn.invalid/window/real/1_2_3/config.json`. Это искусственный адрес.

## Общий код и ограничения

`vampir_core.sdk_config.assemble_cdn_config_url_ascii` повторяет найденную сборку
с обязательными аргументами base/platform/prefix/version_fragment и фиксированным
подтверждённым filename. Локальная политика принимает printable ASCII и
ограничивает каждый аргумент/результат 4096 байт. Не-ASCII отклоняется до изучения
native преобразования, а не кодируется по догадке.

Параметр version_fragment уже подготовлен: helper не преобразует AppVersion.
`1.2.3` остаётся `1.2.3`. В предыдущем участке Initialize найден call
`0x14563f287` → `0x1445daf80` с подготовленными строками точки/underscore;
он сохранён статически, но его преобразование/все случаи ещё не исполнялись.
Нельзя выдавать fixture 1_2_3 за доказанную версию установленной игры.

Platform branch `0x14563f555..0x14563f580` статически связывает return code
1 → ios, 2 → window, остальное → android через getter `0x1445e75b0`.
Активное значение getter и источник выбора ещё не проверены. Runtime helper
не определяет платформу автоматически. Не-ASCII conversion, полное Initialize,
HTTP request и порядок callbacks также не проверены.

Физический источник Game config/реальные bases/prefix остаются неизвестны.
Проверка ограниченных кандидатов ключа для encrypted PAK не дала подтверждённого
ключа: зашифрованные записи не используются как восстановленный config.
Старые offsets не применяются к новым архивам; library baseline не перезаписан.

Продолжение: [native version preparation и compiled platform chain](HEADLESS-CDN-PREPARATION.md).
Version replacement и Windows getter проверены; actual config/HTTP всё ещё неизвестны.

## Следующий шаг

Исполнить version preprocessing и platform getter, продолжить источник Game
config/поздние overrides, затем связать подтверждённые значения с HTTP планом.
Только после подтверждения адреса получать публичный CDN config/Zone и GMC2.
Полный email/password вход и игровая сессия остаются незавершёнными;
network_ready=false.
