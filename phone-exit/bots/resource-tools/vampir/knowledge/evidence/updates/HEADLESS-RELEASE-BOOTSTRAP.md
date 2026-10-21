# Ранний обмен новой версии: проверка источника предварительного кадра

21 октября 2026. Источник — собранный EXE, не исходный C++ проект.
SHA256 `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Эталон — [4c713eb5, CRC / sequence / Login и границы записи](../network/HEADLESS-LIVE-TCP-CAPTURE.md#полный-запуск-4c713eb5-и-сверка-идентификаторов).
В нём ID 30413, body 0 / sequence 0 предшествует Version / Ping / Login.
Цель этого прохода — установить источник кадра до изменения runtime.

## Инструменты и исходные проверки

Прочитаны общий Ghidra index и ранее проверенные connected / send branches;
реестр исторического EXE по 30413 и OnTcpPeerConnected совпадений не дал.
По GamePeer_Construct найден старый экспорт и связи. Ghidra-correlator дал
кандидаты GamePeer_Construct `0x144aab540 → 0x144ab2a70` и Version_Prepare
`0x1467a9cd0 → 0x1467cfd30`; их роли автоматически не переносились.
Обе пары выгружены отдельно вместе с инструкциями через существующий runner.

Проверенный экспорт:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-75f924e89c43/details.json`,
SHA256 `f4aad199bde6f5d13e642ff6ad57cb1ce3617b9d5c58eeffc8bc3e46f2104d44`.
В каталоге — old / new псевдокод, invocation, tool/source receipts.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-function-candidates.py "F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c" --only GamePeer_Construct,Version_Prepare
```

Новые [Ghidra script](../../../InspectVampirBootstrap.java) и
[runner](../../../inspect-release-bootstrap.py) используют существующий сохранённый
проект новой версии, закреплённые Ghidra / JDK и полный SHA EXE. Runner проверяет
receipt источника, SHA инструментов до / после работы, сохраняет команды, логи
и SHA выходов в новом каталоге. Инструменты остаются вне runtime бота.

## Отрицательный поиск не устанавливает роль кадра

В Ghidra memory найдено 1013 совпадений двух байтов `cd 76`. В имеющихся
разобранных инструкциях нет операнда scalar 30413; отдельный проход с low16
scalar также не дал результата. Сохранённый анализ новой версии частичный,
поэтому это не доказательство отсутствия значения во всём исполняемом коде.
Нельзя объявлять его динамическим, зашифрованным или ненужным только по поиску.

Первый кадр эталона, отдельно проверенный как пустой / CRC-valid, имеет bytes
`0b000082793f25040eb39a`. Поиск полного блока, первых восьми / последних восьми
и последних четырёх байтов в Ghidra memory совпадений не дал. Это не доказывает,
что кадр не формируется обычным writer; повторять эти же поиски без новых
входов не нужно. Адрес или native роль предварительного кадра пока не найдены.

Отчёты под общим каталогом
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/bootstrap/`:

| Run / export/bootstrap.json | Проверка | SHA256 |
| --- | --- | --- |
| run-13d31c5236e4 | Exact scalar | 95c2cb886fde89640e588ca490a5bf1163df84a76e93782ec4d216bf28af584d |
| run-534659e0f60c | Exact scalar и wire fragments | 6f3a76b42589261f127b4c55153d2b4b5d566ceab204c47e2ea40fe4b3af7ef2 |
| run-e0371affce44 | Low16 scalar | 6f3a76b42589261f127b4c55153d2b4b5d566ceab204c47e2ea40fe4b3af7ef2 |

Дополнительный Capstone поиск byte candidates на целых unwind ranges имел
249 корней / 972 text-совпадения, три корня не декодированы целиком. Он не
установил ID getter или отправку кадра. Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/bootstrap-low16-native-candidates.json`,
SHA256 `36275bef83980e21c02bbc7b379104a0ae51f3e91d1821ee044ea796f8fe53bd`.
Это ограниченный список кандидатов с явными failed roots, не доказательство
полного покрытия и не основание приписать роль похожему displacement.

## Привязка уведомлений новой версии

В инструкциях нового конструктора `0x144ab2a70` проверены загрузки / stores
таблиц по `0x1496736c8` в peer+0x50 и `0x1496736f8` в peer+0x200.
Из текущего EXE с полным SHA считаны таблицы:

| Таблица | Slot | Target | Статическая проверка тела |
| --- | --- | --- | --- |
| 0x1496736c8 | +0x10 | 0x1445efc30 | Store state, snapshot / refcount loop, вызов action для живых получателей |
| 0x1496736f8 | +0x18 | 0x144ab37b0 | Reset sequence / key, endpoint conversion, delegate virtual+0x60 |

У peer-table **slot +0x18**, а не +0x10. Это также сверено с сырыми байтами
старой таблицы и существующим replay, где старый target `0x144aac520` находился
в +0x18. Промежуточный экспорт нового +0x10 дал другую ветвь и не принят за
connected callback. Аналитическое сходство имени или одинаковый номер slot
другой таблицы не использовались как доказательство роли.

В Ghidra не было отдельной функции на `0x1445efc30`; script дизассемблировал
адрес из проверенного table target и создал функцию только для исследования.
Этот факт записан в отчёте. Псевдокод включает общий хвост; проверять инструкции,
а не приписывать все блоки одному простому исходному методу.

Полный экспорт этих двух targets:
`bootstrap/run-68aaf7f911b9/export/bootstrap.json`, SHA256
`ef326f05bec8ec833949f198297415ad2d1bf64d203996e40ca5606070cc51c5`.
Есть оригинальные инструкции / байты, таблицы, псевдокод и предупреждения.
После добавления строгой проверки поддерживаемого SHA / режима финальный
script повторно скомпилирован и выполнен: `bootstrap/run-a74a54c89397/export/bootstrap.json`,
SHA256 `5ed8bf23a19a17b1515326b6035c37e51d529b2ec67497de0bad276280f3b0a2`.
Функция к этому моменту уже есть в исследовательском проекте, поэтому отметка
её создания отличается от первого экспорта; источники EXE не менялись.

Это статическая привязка источника; native выполнение всей новой цепочки,
Winsock write, делегат приложения, первый кадр и Ping здесь не воспроизводились.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --scalar-only
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --connected
```

## Дальше

Не повторять исчерпанный literal search без изменившихся входов. Из проверенного
Version callback перейти через table / actual send target к общей отправке;
отдельно установить заполнение и запуск Ping. При необходимости замкнуть
новую native цепочку от уведомления до выходной очереди с явно ограниченными
fixtures. Только после доказанного изменения менять bootstrap бота и выполнять
ограниченный live вход. Runtime не менялся, новая авторизация не запускалась.


## Продолжение: actual send и producer Ping новой версии

Дополнительный source-bound экспорт Network_PeersConstruct:
`details/run-318565bc90d7/details.json` под каталогом comparison выше,
SHA256 `a0d199a7b60fba31c926aedb5862670d061adafb31bf00b3d9bbd78812aa9a22`.
Инструкции `0x1467cda10` устанавливают vtable `0x149dcb358` игровому wrapper.
Считаны текущие таблицы и выгружены targets:

| Slot | Target | Проверенный участок |
| --- | --- | --- |
| +0x30 | 0x1467d0af0 | Подготовка дополнительного контекста и переход в virtual+0x38 |
| +0x38 | 0x1467d0a70 | Packet name / metadata, далее общая сборка / очередь кадра |
| +0x40 | 0x144ab2860 | Отдельный delegate/thunk; не объявлять отправкой Version |
| +0x48 | 0x1467cfd30 | Ранее выгруженный Version preparation |

Экспорт `bootstrap/run-ac10c1b6f433/export/bootstrap.json`, SHA256
`b43c7ab2e35ef2784ed78b8dca0e892e206902b165b4dcb2e2e9e7e36380116a`.
В Ghidra общий tail send-B включён в псевдокод wrapper. Это не исходная C++
граница функции. В покрытом участке ID берётся virtual+0x28 переданного packet,
sequence увеличивается, выполняются writer / CRC / XOR / append.
Отдельная вставка ID 30413 в этом статическом участке не найдена; это не
native-доказательство отсутствия такого кадра во всей цепочке подключения.

Экспорт оставшихся slots +8/+0x18/+0x20:
`bootstrap/run-95aab8fd6252/export/bootstrap.json`, SHA256
`3e5fe1213fb7614254aabcb6bfbc81df0f434f51d2ac058141d368e044257b91`.
Он дал initialize / reset branches, а не найденный по ним отправитель Ping.
Промежуточный общий экспорт был остановлен ограничением 64 owners; runner
сохранён с ограниченным следованием callees только выбранных methods.
Не расширять generic callers до всех пользователей allocator / logging helpers.

### От имени Ping до действительного caller

Ghidra memory содержит ASCII `PktPing` по `0x1499289a8`, bytes
`506b7450696e6700`, но частичный анализ не показывает xrefs. Отчёт
`bootstrap/run-0b6a7952ccc9/export/bootstrap.json`, SHA256
`f7fbef49c81402b1e4dc01a33e3db90ee817cf487eca12f85fd043c5a7c9b829`.
Готовый `find-release-sdk-references.py` проверил RIP candidate на целых unwind
границах: `0x1456e75c9 → literal`, owner `0x1456e75c0`. Manifest:
`bootstrap/sdk-reference-candidates/2b98e85c9a56b1cbee438641ff5fe1cf1d96be579ef4df2bc3678bc97ca3e3e8/manifest.json`.
Выбранный owner выгружен Ghidra:
`details/run-72de4b9ee091/details.json`, SHA256
`8da0b214c7d5903f9ad1345389194bcd81dbee505215df79fb3be346699048e3`.

Проверка current .rdata по алгоритму прежнего packet-binding tool дала один
aligned name-slot, candidate vtable `0x149928958`. Native RIP candidate
`0x1456d8b40` загружает её в RAX и сохраняет в [RCX]; actual constructor затем
обнуляет два uint64 +0x10/+0x18 и byte +0x0a. Единственный проверенный direct
caller найден whole-unwind декодером: `0x1467d0d10`, call на `0x1467d0db5`.
Ни совпадение delta адресов, ни старый constructor при этом не использовались.
Manifest кандидата вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/ping-construct-candidates-20261021/dc47725124309a9eda9e0a4be789d11a8b3e41f023bc5813366cbae7ed418a4d/manifest.json`.
Caller после этого выгружен Ghidra:
`details/run-f85aa67d34d9/details.json`, SHA256
`9e91f4e11664ba34e836c5b33b67ffbcf2a9382055d11434312e908562e959e4`.

### Исполнение целого producer

[replay-release-ping-producer.py](../../../replay-release-ping-producer.py)
исполняет source body `0x1467d0d10`, actual readiness thunk `0x144ab2060`
и target `0x144ab35d0`, clock-pointer getter `0x1445ce230`, Ping constructor
`0x1456d8b40` и ID getter `0x14140d460`. Последний возвращает ID 16.
Readiness / clock Ghidra evidence:
`details/run-396c0efa2fde/details.json`, SHA256
`6f17a039fb74489e8423113816e2cb34cd3c058c6ad77abcec6879f3b36c7d05`.

Producer получает secondary-interface pointer P = wrapper+8. Из clock service
берётся signed raw64 по object+0x10, переводится в double, умножается на
source literal `0x148a0a758` = `0.0001` (bytes `2d431cebe2361a3f`) и
усекается CVTTSD2SI. Это вычисленное значение N, без утверждения об epoch:

- Читается last из P+0x158; вычисляется D = N − last.
- Отправка рассматривается только при **D > 5000**, после двух readiness gates.
- Если raw override byte `0x14b595026` равен 0 и signed counter P+0x164 ≥ 6,
  counter обнуляется и вызывается отдельная recovery routine. Её тело — capture.
- Иначе actual constructor создаёт Ping; поля +0x10/+0x18 получают N / D.
  Virtual send вызывается для wrapper; затем P+0x170+index×8 получает N,
  counter увеличивается, last становится N. Index читается из P+0x160.

Actual readiness проверяет raw helper result != 2 и peer special byte == 0.
Raw helper, base-update, context getter, clock-cache contents, send / recovery
и packet cleanup заданы явными fixtures. Clock-pointer getter и сама числовая
конверсия исполняются. Другая float-timer ветвь producer отключена fixture byte
P+0x110 = 0xff. Вызов Winsock, queue/frame send и actual clock acquisition этим
replay не выполняются. Native branch не доказывает необходимость Ping для Login.

36 native cases: индексы 0 / 1 / 3, порог 5000 / 5001, дробные raw ticks,
отрицательная разница, raw mode 2, два special gates, counters 5 / 6 и override.
Проверены exact body fields, last / counter / tracking slot и соседние slots.
Полный отчёт с исходными bytes / instructions, таблицами, helper hashes и fixtures:
`ping-producer-replay/5ac97472d9c2341f67d003084aefe2625684acb4a7a700ee74d094f5bfe9345f/manifest.json`.
Три [регрессионных теста](../../../../../test_vampir_release_ping_producer.py)
повторно исполняют настоящий код и проверяют payload / gates / recovery boundaries.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --send
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --lifecycle
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-bootstrap.py --ping
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-ping-producer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_ping_producer.py -v
```

### Сопоставление с эталоном и оставшиеся ограничения

В 4c713eb5 записаны пять Ping. У первого оба uint64 равны; у всех последующих
второе поле равно разнице соседних первых полей. Это согласуется с native
producer и reset last = 0, не доказывая полного clock lifecycle.
Если интерпретировать первое поле как Unix milliseconds, время первого Ping
опережает время capture chunk примерно на **32 400 000,426 мс**, то есть 9 часов.
Это наблюдаемое смещение, **не доказательство** fixed timezone / обязательного
UTC+9 или алгоритма получения clock-cache. Не заменять источник одним
`time.time()` и не прибавлять девять часов к боту только по этому совпадению.

Обезличенный отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/ping-reference-consistency-4c713eb5.json`,
SHA256 `3c714e764df0b185a14abfc6252dfe657b051f6193478f03aefdcc2807221b8f`.
Исходящие кадры предварительно проверены существующим Login inspector по CRC
и SHA эталона. Токены / значения ключей не сохранялись и в сеть не повторялись.

Следом — источник заполнения clock-cache (global pointer `0x14b567a40`,
raw64 object+0x10) и источник предварительного кадра 30413. После этого можно
связать подтверждённую политику с runtime и проверить новый живой вход.
На этом проходе runtime и настройки устройства не менялись, авторизация
не запускалась. Формат Ping / timer проверен, живой Login бота ещё не принят.
