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

## PC binding и новое игровое переопределение

Выборочный export NID_WebOS 0x1444eddc0:
`details/run-ae24ed5ec4b5/details.json`, SHA256
`967e581e07549de43d4aaa65786d284854375da1346843e4fc97de2ce159844e`.
Он сохраняет default platform byte 3 и передаёт фактический byte в getter
0x144533280. TLS / console override может заменить этот byte; весь caller
не исполнялся. Getter выгружен отдельно:
`details/run-83004e31f0dc/details.json`, SHA256
`bac36d80d0ddb3aa28cad7f51a4396a9b7079f932a1c18add3c08f859dcacbaf`.
Ветка byte 3 копирует FString из global 0x14b565888.

Среди кандидатов PC найден ровно один initializer, пишущий в этот global:
0x1411b5d00. Его Ghidra export:
`details/run-fff9e932d858/details.json`, SHA256
`917b8da0a7a108cb8a7beb2442c0f54ea86d0d3ef02e386ee642723c581826cf`.
[replay-release-sdk-platform.py](../../../replay-release-sdk-platform.py)
исполняет initializer → global FString → getter на четырёх заполнениях памяти.
12 сценариев: byte 3 возвращает PC, неподдерживаемые 2 / 255 дают пустую строку;
проверены return и guards 16-byte destination. Другие platform labels этим не
проверялись. FString construction / allocation, CRT copy и exit registration —
ограниченные fixtures / captures. Runtime TLS / console состояние не установлено.
Отчёт `sdk-platform-replay/034ee9fb7b3f4e4a36792105b6cd8a5e72ff53830edbf57fee9b67e0265286d0/manifest.json`.

### Поиск потребителя client ID и обнаруженное отличие

Поиск прежней diagnostic строки InitSetting в новом EXE не дал результата.
Следующий Ghidra literal report:
`details/run-dcdf0ea2331f/details.json`, SHA256
`74683f635b13c94ec2fa662a2c2aed5d0186121ef8659f749a7be970ad98b9c9`.
Отсутствие этой строки не использовалось как доказательство удаления поведения.

`find-release-sdk-references.py --follow-client-id-globals` автоматически
выделяет короткие initializer candidates, затем ищет обращения к их destination
globals тем же проверяемым scanner. Получены 35 initializer candidates и один
дополнительный root-потребитель вне них: 0x145658ca0, с global 0x14b5e8f88.
Отчёт `sdk-reference-candidates/581565af98c277c9adfe354e6a5b9c03088efd73aa297d60956b4648c1e97213/manifest.json`.
Всего в нём 191 проверенная RIP-ссылка / 154 roots; роль определяется отдельно.
Промежуточный проход `d886d700…` не нашёл initializers из-за неверного ожидаемого
числа инструкций; условие исправлено по целым source-bound roots, старый отчёт
не переписан и не использован для установления связей.

Новый root и initializer client ID 0x14125b800 выгружены в Ghidra:
`details/run-8ffb7dbcdcff/details.json`, SHA256
`4d32fe8932f3121d9155540b737b09137434cc3a67ed023e267bf6beb51539c9`.
По инструкциям / псевдокоду видны записи в тот же settings layout:

- Market +0x28 сначала копируется из global 0x14b5e8fc8. Его initializer
  candidate 0x14125b860 связан с literal nmp, но исполнение этой цепочки пока
  не выполнено. Затем появилась дополнительная условная ветвь: при наличии
  SDK object +0x38 и результате 1 от 0x14560c680 market копируется из другого
  global 0x14b5e8fb8. Источник и смысл альтернативного значения ещё неизвестны.
- GameCode +0x38 копируется из 0x14b5e8f78; initializer candidate 0x14125b830
  связан с thered. Client ID +0x98 копируется из 0x14b5e8f88, для которого
  Ghidra initializer подтверждает прежний публичный literal client ID.
- Environment берётся через 0x141439550, сравнивается helper 0x14145f310;
  результат сравнения записывает settings +0x49 как 2 при равенстве, иначе 1.
  Полный новый comparator и эта ветвь ещё не исполнены. Также видна новая
  запись 0 в settings +0xc8; семантика поля здесь не установлена.

Это статически проверенное **отличие от прежнего игрового override**, а не
готовый новый профиль. Игнорировать дополнительный выбор market нельзя;
простая замена старого SHA в SDK / NID loader не выполнялась.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-sdk-platform.py
```

## Следующая проверка

PC initializer уже связан с потребителем и проверен native-сценариями.
Далее разобрать условный market selector / альтернативный global и выполнить
новый игровой override вместе с initializers / comparator / zone write.
После этого проверить новый GMC2 request path и сформировать отдельный
source-bound профиль. Установленные SDK / NID guards пока прежние; свежий SDK
config, авторизация и Game Login на новом samsung SM-A205F ещё не выполнялись.
Успешный вход, BlockedIp и готовность runtime этим этапом не установлены.
