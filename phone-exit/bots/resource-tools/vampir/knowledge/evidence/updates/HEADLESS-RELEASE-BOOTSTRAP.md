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
