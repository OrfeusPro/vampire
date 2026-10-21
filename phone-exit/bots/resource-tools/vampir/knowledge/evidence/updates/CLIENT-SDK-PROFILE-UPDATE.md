# SDK / NID после обновления EXE, 21 октября 2026

Продолжение [аудита выпуска](CLIENT-RELEASE-AUDIT.md). Цель — подготовить
проверяемый SDK / NID профиль для реального входа на новом JP-телефоне.
Старые source checks не отключаются; найденные строки не подменяют доказательство
их использования. Источник — данные и код собранного клиента, не исходный C++.

SHA256 нового EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Все каталоги отчётов ниже находятся внутри
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

## Поиск источников

[InspectVampirSdkProfile.java](../../../InspectVampirSdkProfile.java) ищет
конкретные строки Market / GameCode / client ID / PC / GMC2 base / SDK version
в сохранённой программе Ghidra. Для короткой UTF-16 строки PC требуется граница
после нулевого code unit, чтобы не собирать окончания посторонних строк.
Первый проход `details/run-d64f65dcf0b1` остановился на лимите до этого уточнения.

Завершённый результат `details/run-16dc231b363f/details.json`, SHA256
`2a8d77750893f4f3b04cdb7a8d0014c1fade467ab2a78744bfe01e6d93bc3ed2`,
содержит найденные литералы, но references в частично проанализированной базе
Ghidra пусты. Это ограничение базы, не отсутствие обращений в коде.

[find-release-sdk-references.py](../../../find-release-sdk-references.py)
повторно использует существующий RIP scanner и проверяет candidates по границам
инструкций целых unwind roots. Получены 155 ссылок в 153 roots. Это кандидаты
для дальнейшей проверки, не 153 установленные роли SDK: есть повторные
инициализаторы и посторонние потребители общей строки версии / платформы.
Отчёт `sdk-reference-candidates/1ea334adcd233b46897dc16aefb55ac592274cd0d449ba989cd746f12eee80c6/manifest.json`.
Он сохраняет Ghidra evidence SHA, полные source SHA, код scanner и диапазоны.

Runner `inspect-release-function-candidates.py` получил `--sdk-profile` и
выборочный режим `--sdk-reference-candidates <manifest> --sdk-functions <VA,…>`.
Источник и SHA manifest проверяются, запрошенные roots должны присутствовать
в candidates. Если function object отсутствует, Ghidra выполняет disassembly
и создаёт функцию для исследования по этому адресу; роль и имя SDK ей не
присваиваются. Это изменение аналитической базы, не игрового EXE.

Выборочный export `details/run-1d8612e8e473/details.json`, SHA256
`361f02451d80318880d8f59586c7e54124b52af725aed0e088d60b675a96c74d`,
содержит инструкции и завершённый псевдокод трёх roots ниже. Предшествующий
`run-3a49ede3dcad` остановился на формате comma-separated аргументов .bat;
приём отдельных аргументов исправлен, незавершённый результат не использован.

## Проверенное исполнение

[replay-release-sdk-defaults.py](../../../replay-release-sdk-defaults.py)
исполнил 9 сценариев с закреплёнными Capstone 5.0.6 / Unicorn 2.1.4:

| Участок нового EXE | Что проверено |
| --- | --- |
| 0x1444b4100..0x1444b41a9 | Prefix конструктора SDK settings: 7 строковых полей, BuildCode 0, SDKZone 1, четыре заполнения памяти |
| 0x1444c5080 | Полный GMC2 constructor с явно отключённой диагностикой: source URLs / groups, четыре заполнения, guards объекта |
| 0x14452baa0 | Getter версии SDK: 5.2.11, правильный destination и return |

Settings prefix задаёт GameCode thered, SDKType Global, пустые Market / client IDs.
BuildCode / SDKZone прочитаны из фактических stores. Это начальные значения;
для production нельзя использовать SDKZone 1 без проверки переопределения игры.
GMC2 constructor записывает production base `https://apis.netmarble.com/gc2`
в +0x170, service group netmarbles в +0x190 и netmarbles-v5 в +0x1c8.
Результаты согласуются с прежним кодом в этом ограниченном объёме.

Базовый object helper и FString construction / storage — bounded fixtures.
Выполнены реальные stores / ветвления конструкторов, но не engine lifecycle,
конфигурационные overrides, mode selector и сборка / отправка GMC2 запроса.
Settings проверен только до указанной границы prefix, не весь constructor.

Отчёт `sdk-defaults-replay/cfe20931f09accfe2bd8b61152ee5ba5c84413f8040395cfaafd5abb3652510b/manifest.json`.
Последний каталог — SHA256; записаны source / evidence / tool / dependencies,
native ranges, поля и ограничения. Воспроизведение:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-sdk-defaults.py
```

## Следующая проверка

Нужно связать новые game-specific initializers client ID / market / GameCode
с фактическим InitSetting и production zone write, затем определить нужный
PC initializer по потребителю, а не выбрать один из повторных литералов.
После этого проверить новый GMC2 request path и сформировать отдельный
source-bound профиль. Установленные SDK / NID guards пока прежние; свежий SDK
config, авторизация и Game Login на новом samsung SM-A205F ещё не выполнялись.
Успешный вход, BlockedIp и готовность runtime этим этапом не установлены.
