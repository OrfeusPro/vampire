# Выполнение игровых настроек SDK в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [статической цепочки настроек](HEADLESS-SDK-OVERRIDE-LINKS-11316.md).
Исследование выполняет сохранённый код в синтетической памяти Unicorn 2.1.4,
без процесса игры, сети, авторизации и игровых действий. Capstone 5.0.6.

## Исполненная цепочка

`replay-sdk-overrides-11316.py` проверяет полный SHA EXE и четырёх полных
Ghidra exports, затем сверяет каждую экспортированную инструкцию с EXE.
Неизвестный адрес исполнения останавливает replay. Ограничение одного вызова —
30 000 инструкций; heap, строки, копирование и destinations имеют отдельные bounds.

В каждом случае выполняются:

1. Settings constructor `0x1444b3290` до границы prefix `0x1444b3339`.
2. Четыре полных initializers: `0x14125b710`, `0x14125b740`,
   `0x14125b770`, `0x14125b7d0`.
3. Whole game override `0x1456579d0`, включая selector `0x14560aed0`
   и market getter `0x144529d60`, когда проходят проверки singleton / handle.
4. Настоящие короткие comparators `0x14145f1e0`, `0x14145f230`
   и общий хвост `0x144552240`, завершающий override.

Comparators не имеют unwind roots. Для них отдельно проверены точные интервалы
71 и 75 байт: непрерывный decode, финальный RET, все branch targets внутри
интервала на границах инструкций. Таблица преобразования регистра читается
из того же проверенного EXE. Хвост состоит из MOV global и RET, семь байт.
Это не выгрузка новых ролей по старым адресам: CALL / JMP к каждому участку
присутствует в текущих экспортированных инструкциях.

| Участок | SHA256 точных байтов |
| --- | --- |
| `0x14145f1e0`, 71 байт | `591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0` |
| `0x14145f230`, 75 байт | `0f0fe1b437f5ff2398fdd154b8fc18567f6e984818a98ee51ab1aa97cd3ec41a` |
| `0x144552240`, 7 байт | `9a8cf11a18ce9832afd8414af78f122b6b0a6dcb4f9a1ff8e43e25c4ab5c8032` |

## Результаты 106 сценариев

Проверены 13 environment strings × 8 вариантов NMENV и два случая отсутствия
SDK singleton / handle. Environment: real в четырёх регистрах, пустая строка,
dev, alpha, dr, production, пробел до / после real, reals и réal.
NMENV: отсутствует, пусто, nmp / NMP, epicgames / EPICGAMES, gpgpc и unknown.

| Условие | Полученный результат |
| --- | --- |
| Environment real / REAL / Real / rEaL | SDKZone 2 |
| Остальные перечисленные environment | SDKZone 1 |
| NMENV epicgames / EPICGAMES и присутствуют SDK singleton / handle | Market epicgames |
| Остальные перечисленные NMENV, либо отсутствует singleton / handle | Market nmp |
| Все сценарии | GameCode thered, client ID 18e6xn1vuR1lGrvR, BuildCode 0, settings+0xc8 = 0 |

Canaries до / после settings сохранились. Parser fixture вызывается ровно один
раз при наличии обеих SDK предпосылок и ни разу без них. Источник copy thunk
`0x1487f5ab9` отдельно проверен как импорт `vcruntime140.dll!memcpy`.
Результаты не получены подменой comparators или selector готовым ответом.

## Fixtures и границы

Class getter возвращает синтетический class / CDO; SDK singleton и handle
заданы явно. Environment getter возвращает заданную строку. Command-line getter
и FParse Value — fixtures: проверяется реальный ключ NMENV=, но результат
разбора задаётся сценарием. Фактическая командная строка игры не исполняется.

FString constructor / capacity, memcpy, free, base UObject constructor и
регистрация завершения — ограниченные fixtures. Logging отключён.
Часть settings после prefix, lazy UObject registration и полный startup не
проверялись. Это подтверждает вычисление настроек для указанных входов,
но не фактические inputs запущенной игры или совместимость живой сессии.

## Повторная проверка и материалы

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-overrides-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_overrides_11316.py
```

Четыре теста проверяют все 106 результатов, gates / canaries и отклонение
изменённых EXE, export и контракта comparator. Зарегистрирован отдельный
`sdk-game-overrides-native-11316`; статическая проверка ссылок сохраняется отдельно.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Replay: `code-clues/sdk-overrides-11316/eba1cef5cee42df5652d6db3c1918cbeda2eff85f3c34f1410ec683d9356b33a/manifest.json`.
- Три Ghidra exports и их SHA — в [предыдущем доказательстве](HEADLESS-SDK-OVERRIDE-LINKS-11316.md).
- Settings constructor: `ghidra/request-exports/<SHA>/run-d490839a48f4/details.json`,
  SHA `ba186c8e32fccaecc4a5a4dae04b8df9d2c667327bec1309a6d5a9ce04fa0bb1`.

Runtime profile не обновлён по одному этому replay. Следующая проверка —
GMC2 URL builder и HTTP headers текущего SHA, затем сборка полного профиля
с подтверждёнными dependencies. Проверка первого SDK login / игрового входа
остаётся отдельным этапом, когда серверы доступны.

## Что можно повторять автоматически

В `knowledge/release-update-targets.json` у групп sdk-game-overrides и
sdk-defaults-gmc2 добавлено поле automation. Для каждой проверенной функции
указаны полный SHA, адрес, точный объём проверки и required_checks.
Функции с проверенным prefix не помечены как полностью исполненные.

При неизменном полном SHA и хешах dependencies prepare / finish могут
автоматически выполнить зарегистрированные offline проверки или использовать
их актуальный кэш. Новое значение SHA требует поиска кандидатов, проверки
связей и переноса проверок. У game override поиск пока assisted: client ID
не уникален. Для следующих агентов это машинная памятка, а не новый механизм
автоматического выбора override. Общий update сохраняет очередь перепроверки.

Автоматическое продвижение runtime явно запрещено полем
automatic_runtime_promotion=false. Отдельный тест проверяет, что каждому
адресу назначены существующие проверки именно его SHA, а новая сборка
остаётся в состоянии requires_candidate_review_and_check_port.
