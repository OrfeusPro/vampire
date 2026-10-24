# VersionResult 1.13.16: текущий reader

24 октября 2026. Источник — собранный Windows-клиент, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [исторического reader/handler](../network/HEADLESS-VERSION-RESULT-HANDLER.md).

## Привязки и проверка

Constructor `1456d7c90` устанавливает table `149926d68`. Её slot `+20`
указывает на reader `1456dc5e0`, slot `+28` — на ID getter `14148a940`,
который возвращает 2. Рядом сохранён literal `PktVersionResult` по `149926db8`.
Constructor и getter — явные короткие инструкции; reader имеет unwind root.

Reader читает `u32 +10`, `u32 +14`, `bool +18`, `u32 +1c`, `u32 +20`.
Тело занимает 17 байт. Выполняются актуальные concrete/base buffer constructors,
scalar/bool/raw IO и bookkeeping из уже проверенного
[input archive](HEADLESS-LOGIN-RESULT-BUFFER-11316.md).
Поля cursor/size после конструктора вручную не подменяются.

Проверены 32 полных случая: result 0/1/58/ffffffff, bool 0/1/2/255,
два исходных заполнения памяти. Проверены все 17 коротких префиксов,
отказ каждой из пяти операций и прекращение дальнейшего чтения.
Native reader принимает лишние байты, потребляя только 17; строгий runtime
decoder по-прежнему требует точный размер. Все полные результаты сопоставлены
с ним. Проверены ABI, границы объекта и неизменность входного буфера.
Отдельно повторены 72 сценария constructors входного archive.

## Воспроизведение и повторное использование

[Context](../../native-contexts/version-result-11316.json),
[verifier](../../../verify-version-result-context.py),
[три теста](../../../../../test_vampir_version_result_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_result_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-result-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-result-11316.json
```

Единственный новый экспорт — `run-c363c26b9abc`; архивные функции использованы
повторно. Отчёт хранится вне Git в
`F:/PhoneExit Resources/Vampir/knowledge/native-version-result-checks/fa8b336e355153dfa03aa8a09b64d250c7cf6359302afc30a50fe693fbe44011/manifest.json`.
Полные SHA экспортов и source-bound bytes хранятся в context и отчёте.

Для этого SHA check `native-version-result-context` подключён к `game-version`.
На следующем патче найти кандидатов constructor/table/ID/reader, сверить slots,
callee archive и порядок операций; затем перенести context и повторить check.
Совпадение соседнего literal не разрешает автоматическое обновление runtime.

## Границы и следующий шаг

Регистрация, dispatch, VersionResult handler и переход к Login здесь не исполнены.
Input allocation остаётся synthetic; исполняется только явно разрешённый набор
инструкций. Сеть, авторизация, список и создание персонажа не запускаются.
Профиль текущей сборки не активирован, готовность `game-version` остаётся partial.
Далее проверить current handler/переход и остальные зависимости профиля; только
после этого выполнять Game Login, свежий список и создание при пустом списке.
