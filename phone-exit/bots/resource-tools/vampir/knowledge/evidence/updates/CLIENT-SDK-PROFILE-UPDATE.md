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

## Автоматическая проверка market и zone, 21 октября

Следующий проход закрыл неизвестное выше: global 0x14b5e8fb8 заполняет
initializer 0x14125b8c0 строкой epicgames. Selector 0x14560c680 получает значение
через 0x14452abd0 по ключу командной строки `NMENV=`. Сравнение без учёта
ASCII-регистра возвращает 0 для nmp, 1 для epicgames, 2 для gpgpc; пустое или
неизвестное значение даёт 0. Игровой override переключает market только при 1
и наличии SDK object / handle. Это условие командной строки; страну аккаунта
или выхода данная ветвь не проверяет.

Ghidra exports в том же comparison:

- `details/run-f43686dcac55/details.json`, SHA256
  `30fd3276d957fc9dff241c215ba1a4810df7cab6d3b3dec85272819c679f0c65`:
  selector, comparator 0x14145f310 и initializer epicgames.
- `details/run-27454953ad4c/details.json`, SHA256
  `13b6067cbbd5b220ecf0c32183d87fe434120e8b841ef922f0aebf52906320cf`:
  getter и comparator 0x14145f2c0.

Автоматический finder теперь принимает только globals / прямые CALL или JMP
из предоставленных Ghidra instructions. Отчёты `sdk-reference-candidates/`
`048bc050d9ba6dd0be8f3bedbe5dcf25a11fd4e55285e56434f30824179ef326` и
`f18b912a99b2ba84711ccaed7a239f4666f7e05d4c1edcf536314571a82000d9`
содержат соответствующие manifest.json. Опечатка 0x14125b890 была отклонена
selected export `run-ffc0530fa194`: адрес отсутствовал среди кандидатов.
Теперь Python runner проверяет это до запуска Ghidra.

[replay-release-sdk-overrides.py](../../../replay-release-sdk-overrides.py)
исполняет prefix settings, четыре initializers, целый игровой override,
market getter / selector, оба comparator и общий tail 0x1445530b0.
Пройдены 106 сценариев: 13 значений environment × 8 NMENV и два отказа gate.
Market nmp / epicgames, GameCode thered, публичный client ID, build code 0,
zone 2 для real без учёта ASCII-регистра (иначе 1) и raw +0xc8 = 0 совпали;
guards объекта сохранены. Семантика raw +0xc8 за пределами записи не установлена.
Отчёт `sdk-overrides-replay/a38710b3406e7740be44169bf5b861c13c95e299e25ce535a3ad256339313953/manifest.json`.

Class/CDO, singleton objects, environment string, FString storage / growth,
CRT copy, free и exit registration — явные fixtures. Выход FParse также fixture:
настоящий parser и командная строка запущенной игры не исполнялись. Первый
replay остановился на неотображённом общем tail; после проверки двух инструкций
по Ghidra и исходным байтам tail включён в разрешённые диапазоны. Ограничение
на неизвестное исполнение сохранено. Это офлайн-проверка, не доказательство
полного startup, HTTP, авторизации или совместимости сервера.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-sdk-overrides.py
```

## Новый GMC2 Start и путь запроса

Поиск Ghidra дополнен точной диагностикой GMC2 Start и ASCII-литералами
`/template-groups/`, `?game=v5&country=G9&build=` и `&engine=unreal&market=`.
Отчёт `details/run-b117745a1cb0/details.json`, SHA256
`0efe806b4040cf09c3098d6929a434492fb637c3578b628e74a556c782490e8b`.
В этой частично проанализированной базе recorded xrefs по-прежнему пусты;
готовый scanner проверил кандидатов по инструкциям целых roots:
`sdk-reference-candidates/a98470e7ea6325acbc87b4bb34697134ddd6ea6e31c50794994c8e25f432233d/manifest.json`.
Среди 159 ссылок / 155 roots выделены Start 0x144509080 и Refresh 0x1444faff0.
Остальным roots роль не присваивается.

Их Ghidra export `details/run-ae63693173ac/details.json`, SHA256
`e1d4f62cd84ff146340f5f60ed0802dcaad2c68cefac968d7857cb9fa088f599`.
Start читает CDO +0x49, выбирает base из manager +0x150 / +0x160 / +0x170 /
+0x180 для zone 0 / 1 / 2 / 3; прочие byte значения выбирают +0x160.
Копирование в active base manager +0x1e8 идёт через настоящий общий FString
copy 0x141441e40. Start также копирует settings +0xc8 в global 0x14b1890f4;
этот global участвует в условиях диагностики, полная семантика флага не установлена.

Прямой tail target 0x141441e40 получен из Ghidra reference, а не смещением
старого адреса. Его экспорт `details/run-bed7531e5011/details.json`, SHA256
`96a925705bf7e4b90c467df7901dcaf6c4cb4c436b95cef433540397f6817119`;
manifest кандидата `sdk-reference-candidates/b7aeee86e3c5683e4bf28c3c6e80126ddfe3d3d772999d8fe80214db9fb48a69/manifest.json`.

[replay-release-gmc2-start.py](../../../replay-release-gmc2-start.py) исполняет
целый Start и FString copy: 256 zone × два raw flag (0 / 1), всего 512 сценариев.
Проверены итоговая строка, return, FString counts / capacity, перенос raw flag
и guards. CDO, непустые base strings, allocation и проверенный CRT copy — fixtures;
диагностика явно выключена. Адреса base согласуются с ранее исполненным новым
GMC2 constructor, но здесь constructor и override не исполняются непрерывно.
Первый запуск остановился перед неотображённым tail; после его экспорта добавлен
реальный copy body. Страница после allocator fixture также отображена, чтобы
Unicorn мог декодировать блок перед перехватом. Неизвестное исполнение запрещено.
Отчёт `gmc2-start-replay/9409d46095e5113f9929a9e6008f42791e397dbb08ffb0b7ff8b7cac59d8f841/manifest.json`.

Из нового Refresh прослежены прямые calls: версия 0x14452baa0,
build getter 0x144532f30, append 0x141761ae0 и RequestGMC2 0x1444fca30.
Три последних выгружены: `details/run-ff5be244c76f/details.json`, SHA256
`f4caea5a759d9639db82abcfa1298e474a8dcdce29f630879ffaea7245d276d2`.
Manifest прямых targets:
`sdk-reference-candidates/884e89db8e465be46b2e3114ba8bebc83c7a6e9e39d99ffb9d8bd9bffd8f45b5/manifest.json`.
Build getter выбирает globals 0x14b5658e8 при byte 1, 0x14b5658f8 при 2,
иначе 0x14b5658d8. Их initializers и фактические build labels ещё нужно связать.
Наличие ветвей само по себе не подтверждает старые A / B / C.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-gmc2-start.py
```

## Build labels, URL и заголовки новой версии

Globals build labels прослежены из getter по Ghidra references:
0x14b5658d8 / 0x14b5658e8 / 0x14b5658f8 → initializers
0x1411b3350 / 0x1411b3380 / 0x1411b33b0. Manifest кандидатов
`sdk-reference-candidates/89a033de8d7a88f6b48ab42dfa5670a22883edc996e78e3baeee8cbcceb75b92/manifest.json`.
Ghidra export `details/run-e2265b35851b/details.json`, SHA256
`9f6f21bebd5ce191051fe997d1feaf7128492eaa3886b27dedac141b9aa94541`.
Связь строк A / B / C с этими globals проверена исполнением initializers,
затем actual getter: byte 1 → B, 2 → C, остальные проверенные 0 / 255 → A.
Полный диапазон byte этим новым replay не заявляется.

Прямой copy target 0x141453970 из Refresh также экспортирован:
`details/run-379a720f244e/details.json`, SHA256
`d3489b6de5916d4107ef35d7204a2fb746f715b480f0847140b66572f4aa2f02`.
Это переход к проверенному CRT memcpy thunk. Manifest ссылки
`sdk-reference-candidates/ef3e64aecbb350d0456e00b8dfd1931ad452afa3a6897c573c2f3ec5a1566f3b/manifest.json`.

[replay-release-gmc2-url.py](../../../replay-release-gmc2-url.py) выполняет
новый slice 0x1444fb178..0x1444fb48d, три initializers, build / SDK version
getters, native ASCII append 0x141761ae0 и copy wrapper. 27 сценариев совпали
с переносимым helper: разные build bytes, nmp / epicgames, пустые base / group /
market, лишний slash и raw query characters. Включён canonical production URL.
Все строки помещаются в native inline builder; growth не подменён и не проверен.
Отчёт `gmc2-url-replay/ee859f52afb6bc496420d5c0164da52e230bbf7b9d452288452c4d8c9aaef429/manifest.json`.
Ранние отчёты `0d8d67cf…` / `391da90f…` содержат 26 сценариев до добавления
canonical production case / общего harness; для профиля используется последний.

[replay-release-gmc2-headers.py](../../../replay-release-gmc2-headers.py)
выполняет новый GMC2 constructor и RequestGMC2 slice
0x1444fcc70..0x1444fcec1 вместе с initializers / build getter.
17 сценариев: четыре build bytes × два eTag × два accessToken плюс явный
публичный production request без device identity / аккаунтных credentials.
Captured URL, GET и ordered headers совпали с переносимым planner.
Пустой eTag пропускается; playerId / accessToken добавляются только при непустом
accessToken. Значения player / device во всех случаях искусственные либо пустые.
Отчёт `gmc2-headers-replay/ecb52e39f9bd1a3850761761a81e08f1aa88245dd18f17206259b973b537a255/manifest.json`.

HTTP virtual methods — captures. Manager/settings/CDO, FString storage / growth,
free, exit registration и player / device getters — явные fixtures.
Реальная строка / значения, полученные от конструкторов и getters, не заменяются
ожидаемой готовой строкой URL / заголовков. Полный Refresh, создание запроса,
TLS / console gates, HTTP transport и авторизация native-клиента не исполняются.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-gmc2-url.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-gmc2-headers.py
```

## Отдельный профиль recovered-release

[build-release-sdk-profile.py](../../../build-release-sdk-profile.py) проверяет
шесть immutable native reports, их source / tool / dependency SHA и текущий EXE.
Он связывает выбранные результаты initial production settings → PC label →
production base → canonical URL → public header capture и создаёт отдельный
bundle. Старые файлы SDK / NID и их SHA не переписаны.

Профиль `F:/PhoneExit Resources/Vampir/sdk-source-profiles/dd77f0c13f54949999b96de3c753dde608a8521087d83c80de5bbbc5a726c582/manifest.json`.
SHA256 совпадает с именем каталога. В нём SDK 5.2.11, GameCode thered,
market nmp при отсутствующем NMENV, build code 0, PC и публичный client ID.
NID webview type 0 / English — явные локальные параметры; country / osVersion
заполняются runner по текущему источнику. Это initial source profile,
не прочитанный кеш / command line / TLS state работающей игры.

Лёгкий [sdk-source-profile.py](../../../../../vampir-headless/sdk-source-profile.py)
не импортирует инструменты исследования. Он проверяет SHA bundle и установленного
EXE. Fetch и NID runner принимают явный `recovered-release`; выбранный профиль
передаётся из lobby runner. NID отклоняет GMC2 snapshot старого профиля даже
при том же SOCKS-порте. Нет автоматического отката к прежнему профилю.

Пять новых проверок: реальный pinned профиль / public request, повреждённый
manifest, изменившийся EXE, отсутствие / неизвестный выбор, старый SDK snapshot
до decode / auth и передача выбора в runner. Ещё четыре lobby-context теста,
семь launcher-flow тестов и обновлённая проверка передачи route / profile прошли.
Исследовательские native replay не равны проверке реальной сессии.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-release-sdk-profile.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_sdk_profile.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-gmc2-config.py --fetch --profile recovered-release --socks-port 17948
```

## Свежая конфигурация на новом JP

Каталог вновь подтвердил доступный samsung SM-A205F / JP / APK 0.9.6.
Собственный временный SOCKS на 127.0.0.1:17948 подключён к этому телефону;
системные маршруты не менялись. Получены:

- GMC2 HTTP 200, 13772 байта, DECKEY присутствует:
  `public-gmc2-snapshots/ce43eb49be35879a5f583cd743ac38033e156de007d33189f8b234f218d715f0/manifest.json`.
- CDN 1.13.14 / real, 7632 байта:
  `public-cdn-snapshots/f09aa380346cd4bb389a0d9355e8f8a9133ed0f98c36cc827439eb120fd23417/manifest.json`.

Эти два каталога находятся непосредственно в `F:/PhoneExit Resources/Vampir/`.
NID preflight нового профиля прошёл: все три сохранённых device keys совпали
с Windows-хранилищем, текущая страна JP, декодированы 94 SDK constants.
Сами ключи / constants / credentials в документ и Git не включаются.
Первое окно без пароля осталось на manual sign-in; закрыто штатно, SDK POST
не выполнялся. Последующая проверка использует ранее заданный пароль через
скрытый getpass / stdin, без аргументов процесса или сохранения пароля.

## Результат реального входа на новом JP

Ограниченная попытка на bot-hk-test / Franz 2 завершилась:

- SDK launcher token / launcher sign-in приняты; joined country аккаунта HK.
  Это отличается от текущего выхода JP и не подменяется сетевой страной.
- Лобби: IDs 2 / 104 / 4, все result codes 0; 55 групп / 98 серверов.
  Отправлено 766 байт, получено 11466. Выбран server 256 / group 253 / region JP;
  лобби оставалось открытым во время игрового запроса.
- Контекст `windows-sdk-initial-reset`, partial metadata 219 байт, язык 1,
  ClientVersion 261105. Локальный адрес через SOCKS не установлен
  (`socks_bound_unavailable`); адрес не выдумывался.
- Game Version принят: code 0. LoginResult декодирован текущей моделью как
  code 1, body 131 байт. Отправлено 860 байт, получено 94; счётчики полные,
  других packet IDs нет. Клиент закрыл соединение по неизвестному ненулевому
  результату; character list не отправлялся.

Код 1 не называется BlockedIp / InvalidState: метка и соответствие нового
LoginResult reader текущей переносимой модели ещё требуют проверки.
Прежний отказ IP на новом телефоне не воспроизведён как 58, но это не доказательство
отсутствия других ограничений сервера. SDK / лобби совместимость проверена
этим обменом; полного игрового входа нет.

Санитизированное наблюдение из завершённого CLI output сохранено отдельно:
`F:/PhoneExit Resources/Vampir/live-login-observations/a85aa7a538bd24f1d3ce086b84d53ce0800923b16c186619260b267f841a6bee/manifest.json`.
Это summary наблюдаемого вывода, не сохранённые сырые пакеты / body и не полный
machine-captured transcript. В нём нет credentials / device keys / account IDs /
токенов. Полный CLI result не сохранялся. Временный route helper завершился
штатно с code 0; listener 17948 закрыт. Повторного SDK / Game Login после code 1
не выполнялось.

## Следующая проверка
Проверить текущий LoginResult reader и native result-code mapper для кода 1
на SHA 98802d550890… . Затем определить конкретное отличие поля / порядка
обмена, которое оправдает следующую ограниченную попытку. Реальный список,
выбор персонажа и позиция остаются открытыми; не повторять вход без нового
подтверждённого изменения условий.

## Продолжение: код 1 и исправленная compiled строка

[Новый source-bound разбор](HEADLESS-RELEASE-WIRE-TAG.md) подтвердил current mapper
1 → InvalidPacketVersion и устаревшую строку Version / Login у бота. Источник
новой строки проверен в текущем EXE и исполнен native slice; она совпала с
успешным HK-захватом. После исправления код 1 не повторился, но Game Login на
JP и HK дал 16 / InvalidState. Свежие SDK / лобби / Game Version приняты.
List при отказе не отправлялся; текущий следующий шаг и новые summaries находятся
в продолжении. Предыдущие формулировки неизвестного кода 1 выше — история этапа.
