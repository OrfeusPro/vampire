# Ключи текущего SignUp: семь целых initializers

22 октября 2026. SHA256 снимка EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [статического разбора SignUp](HEADLESS-RELEASE-SDK-SIGN-UP.md).
Инструмент `replay-release-sign-up-keys.py` исполняет семь целых функций;
авторизация и игровые действия отсутствуют.

| Начало функции | Глобальный FString | Проверенный текст |
| --- | --- | --- |
| `0x1411b0350` | `0x14b564d70` | countryCode |
| `0x1411b0380` | `0x14b564d20` | credential |
| `0x1411b03e0` | `0x14b564d00` | deviceKey |
| `0x1411b0440` | `0x14b564da0` | errorCode |
| `0x1411b05c0` | `0x14b564d10` | nmDeviceKey |
| `0x1411b05f0` | `0x14b564d80` | os |
| `0x1411b06b0` | `0x14b564df0` | resultData |

Адреса найдены по LEA к семи явным глобальным дескрипторам. Проверены
границы инструкций и unwind roots; `prepare` / `collect` получили только
эти семь функций. Повторный `prepare` использовал их полные экспорты.
Ghidra `details/run-618b0a5322d7/details.json` в текущем comparison имеет SHA256
`d138a428d29a6fa58f721767120fbdc73b295df3c05dbae395f968c9087d2153`.

## Исполнение и границы

На каждую функцию выполнены четыре случая с начальным заполнением дескриптора
`00`, `55`, `aa`, `ff`: всего 28. Исполняются настоящий пролог, LEA литерала
и destination, вызов конструктора FString и tail JMP регистрации destructor.
Конструктор FString и atexit — bounded fixtures: первый копирует проверенный
UTF-16 literal из текущего EXE, второй фиксирует переданный адрес destructor
и возвращает управление. Сам destructor не исполняется.

Проверены готовая строка, count / capacity, единственный вызов construction,
единственная регистрация destructor и по 16 байт до / после дескриптора.
Неожиданный backend, literal, форма инструкций или выход за границы останавливают
проверку. Capstone `5.0.6`, Unicorn `2.1.4`; SHA источника и экспорта обязательны.

Content-addressed отчёт находится в текущем comparison:
`sign-up-keys-replay/ec016e31237b71c46fbbe890f7f7439b24f0af43e1946bd97dea83da37de7f60/manifest.json`.
SHA256 отчёта совпадает с именем каталога. Тест `test_vampir_sign_up_keys.py`
зарегистрирован как `release-sign-up-keys` для вопроса `sdk-first-player`.
Зависимости проверки перечислены в `research-checks.json`; запуск offline.

Вместе со статическим caller `0x144506cf0` это устанавливает имена четырёх
начальных полей и дополнительного credential в актуальном запросе SignUp.
Для callback `0x1444d6050` подтверждены имена errorCode / resultData.
Это не native-исполнение сборки тела: значения getters, GetObject,
JSON / map и сериализация здесь не выполнялись. Constructor owner callback
и его ключи playerInfo / player / playerId ещё требуют текущей проверки.
Успешное создание игрового профиля для новой EU-почты не доказано.

Следом проверить constructor owner и полный bounded caller SignUp, затем
одну явную регистрацию SDK после свежего NID callback. Результат неизвестной
попытки нельзя автоматически считать отказом или повторять.
