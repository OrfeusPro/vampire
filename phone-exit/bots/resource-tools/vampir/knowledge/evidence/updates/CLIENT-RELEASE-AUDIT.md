# Проверка обновления клиента, 19 октября 2026

## Завершённое обновление: офлайн-сравнение 21 октября

Пользователь сообщил, что обновление завершилось, но сервер ещё не запущен.
Сетевых попыток и запуска игры при этой проверке не было. Новый полный аудит:
`F:/PhoneExit Resources/Vampir/release-snapshots/d02610a730f323520fdd69b5ddc50cabb20f3768fe69943c0c3b89ac0a454433/manifest.json`.
SHA256 совпадает с именем каталога.

Сравнение именно со снимком 19 октября, а не с первоначальным инвентарём:

| Объект | Результат |
| --- | --- |
| Shipping EXE | 198 145 536 → 198 674 944 байта, новый SHA |
| ProjectRED-Windows.pak | 420 675 245 → 435 258 719 байт, новый SHA |
| 35 остальных архивов | Совпали полные SHA256 из двух снимков |
| Ещё 127 архивов | Совпали размер, mtime и выборочный отпечаток; полное равенство не проверено |
| Состав архивов | Добавлений и удалений относительно 19 октября нет |
| windows.manifestlist | Прежний SHA `4dff7291228f11bd330f80af5a2797a877396e41287fe46a0db8fa4e3e874ffd` |

Новый SHA EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Проверенная копия сохранена в
`F:/PhoneExit Resources/Vampir/client-code-snapshots/98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e/ProjectRED-Win64-Shipping.exe`.
SHA основного PAK:
`df951b448d25169d4a30ff1d853577a20c6c664711bac2a45d38def0b5062290`.
Прежний manifest содержит Revision258392, но его актуальность для нового EXE
и согласованность всей установки не установлены. Номер на снимке лаунчера
не использован как доказательство новой ClientVersion.

Инструмент [compare-release-snapshots.py](../../../compare-release-snapshots.py)
сравнивает current-поля двух проверенных immutable-снимков. Полные хеши имеют
приоритет; выборочное совпадение никогда не повышается до полного. Отчёт внутри
нового снимка: `comparisons/68586bf0bf255f13e556aa778cf4357836b3d25f5377ef577deae16b9995600e/manifest.json`.
Поэтому 35 changed и 1 added в исходном аудите нельзя считать отличиями этого
обновления: это накопленные отличия от первоначального инвентаря.

### Свежий основной PAK

[index-release-archives.py](../../../index-release-archives.py) получил фильтр
`--archive-sha256`, чтобы индексировать только подтверждённый изменившийся архив.
Фильтр сверяется с манифестом; источник и decoder dependencies проверяются как
раньше. Найдены 12 704 записи: 12 576 декодированы, 76 зашифрованных и 52 свыше
лимита пропущены; ошибок декодирования нет. Проход дошёл до каталога, но его
зашифрованный индекс не разобран; 5590 промежутков не покрыты.
Искомых маркеров SDK в декодированной части нет.

Относительно нового снимка индекс находится в
`record-indexes/3d6a816a0783295fe278b455acab54bf4480fcbdcaa9b6f4e34e751049bc74f1/874e34663ae9d246cd2ea152bc1d4f2fa4b38da7b8c9a33e9cb16d55f5b63f8a/manifest.json`.
SHA индекса — последний каталог. Сводка:
`index-summaries/8e733e6859ef62e3f02cc4b748539b335088ce0a067eab2628dae107f4f290a6/manifest.json`.

[compare-release-assets.py](../../../compare-release-assets.py) сопоставил SHA
3325 ранее сохранённых файлов из `pak-extracted/ProjectRED-Windows/entries.json`
с хешами свежих декодированных записей: 3210 точных совпадений, 115 не наблюдаются.
Старые offsets и номера записей для соответствия не использовались. Отчёт внутри
каталога индекса:
`asset-comparisons/1dcb9da5cf4cb966e735fe2cc78d70472099badae8c40bc8f8cd751064427ea2/manifest.json`.
В числе 115 есть файлы с упоминаниями общих окон, настроек и магазина. Это очередь
перепроверки, не доказанные удаления или соответствия новым ресурсам. Совпадение
отдельного uasset также не гарантирует неизменность связанного uexp или всей UI.
Сравнивались сохранённые извлечения, полного старого PAK для побайтового diff нет.

### Воспроизведение и продолжение

`compare-release-snapshots.py` принимает старый и новый release manifest;
`index-release-archives.py` — новый manifest и `--archive-sha256` из таблицы выше;
`compare-release-assets.py` — свежий record manifest и прежний entries.json.
Все отчёты вне Git имеют SHA входов и инструмента; старые данные не заменены.

Следом сопоставить функции входа / списка / выбора персонажа в Ghidra между
сохранёнными EXE. Штатный Version Tracking установлен в Ghidra 12.1.4; его
готовый пример изучен. Отдельный импорт нового EXE сохранён; автоматический
анализ остановился по лимиту 900 секунд. Первый post-script не получил отчёт:
Version Tracking отклонил ещё не сохранённый импорт как read-only. Рабочий каталог:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-8c0fb21ef823/`.
`invocation.json` содержит команду, SHA входов, версии инструментов и лимиты:
heap 8 GiB, 2 CPU, 900 секунд на автоматический анализ файла. `headless.log`
фиксирует фактическую стадию. Таймаут не означает полного разбора EXE.

Runner исправлен: импорт / сохранение и корреляция выполняются отдельными
командами. `--resume-from` продолжает из сохранённого проекта без повторного
импорта / анализа, проверяет SHA источников и сохраняет признак неполного анализа.
Первая попытка продолжения (`run-11112781252d`) выявила неверную сигнатуру API
копирования старого проекта; отчёта не получила. Сигнатура исправлена, Java-скрипт
прошёл отдельную компиляцию с закреплёнными Ghidra / JDK. Текущий запуск:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.
Он использовал сохранённый проект из первого каталога. Историческая программа
скопирована внутрь проекта сравнения; исходный проект открывается только для
чтения. Версии / SHA обоих Program сверены скриптом. Сравнение завершено:
25 кандидатов Exact Function Bytes Match и 226 Exact Function Instructions Match.
Новый анализ неполный; отсутствие совпадения не означает удаления функции.

Корреляторы работали по загруженным адресным пространствам двух Program.
В базе старого проекта 368 723 функции, нового — 374 327; это не число исследованных
функций и не доказательство полного disassembly. Накопленный экспорт содержит
424 выбранные функции. Поле scope первого отчёта неточно называло вход выбранным
набором; фактическая фильтрация по 424 функциям выполнена следующим инструментом.
Текст scope скрипта исправлен для будущих запусков, сохранённый отчёт не менялся.

Для следующего этапа подготовлен
[build-release-function-review.py](../../../build-release-function-review.py).
Он принимает каталог завершённого сравнения, сверяет provenance, SHA обоих
сохранённых EXE, отчёт Ghidra и исторический экспорт. По всем выбранным старым
функциям строится очередь: `not_matched`, `conflicting_candidates` или
`candidate_requires_verification`. Противоречия между correlators и конкуренция
нескольких старых функций за новый адрес выделяются явно. Совпадения вне
выбранного экспорта сохраняются отдельно; они не расширяют доказанное покрытие.
Даже единственный кандидат остаётся на проверку операндов, вызовов, данных и
поведения; роли и адреса в рабочие профили автоматически не переносятся.

Два теста на искусственных отчётах проверили конфликты, пропущенные функции,
границы coverage и отказ при другом SHA / дубликатах. Реальный запуск по
завершённому `run-fd4956a37b3c` дал 239 функций с кандидатами и 185 без совпадения;
конфликтующих кандидатов нет. SHA отчёта очереди:
`ac62bc48943a315d39cfa805841875a57fff1d7eadc80b0e57e38ace15b586a4`.
Он находится в `function-review/<SHA>/manifest.json` каталога сравнения.
Команда:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-release-function-review.py 'F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
```

### Приоритетные пары входа и персонажей

[inspect-release-function-candidates.py](../../../inspect-release-function-candidates.py)
выполнил отдельный Ghidra export без auto-analysis. Сохранены инструкции с байтами,
целями переходов и псевдокод обеих сторон девяти пар; все 18 декомпиляций завершились.
Адреса и имена runtime не менялись, роли автоматически не принимались.
Отчёт: `details/run-d44249673b72/details.json` внутри `run-fd4956a37b3c`;
SHA256 `a36a67359571ec08597700915fedb4eed931140d8541b58803932b854aef6151`.
Рядом provenance.json с SHA скриптов, входов и выгруженных файлов.

| Историческое аналитическое имя | Старый VA | Кандидат нового VA | Инструкций в каждой стороне |
| --- | --- | --- | --- |
| PktLogin_Write | 0x1456e57c0 | 0x1456e9640 | 150 |
| PktLogin_Read | 0x1456d9370 | 0x1456dd180 | 165 |
| Archive_WriteFString | 0x144aa6a30 | 0x144aae660 | 163 |
| PktCharacterListResult_Read | 0x1456d8d80 | 0x1456dcf00 | 71 |
| CharacterList_RecordRead | 0x145781c80 | 0x1457897d0 | 138 |
| CharacterList_RequestA | 0x145dbd4b0 | 0x145daac50 | 30 |
| CharacterList_RequestB | 0x145dbfe50 | 0x145daf070 | 29 |
| PktCharacterSelect_Write | 0x1456e53a0 | 0x1456e9550 | 33 |
| PktCharacterSelectResult_Read | 0x1456d8f80 | 0x1456f1390 | 71 |

У записи Login сохранены обращения к тем же полям: 15 строк, четыре uint32,
пять байтов и uint64, включая metadata +0xd8 и язык +0x124. Прямые вызовы строки
перешли с 0x144aa6a30 на кандидата 0x144aae660. У PktLogin_Read и
PktCharacterSelect_Write также нет иных текстовых различий инструкций после
подстановки кандидатов вызовов и соответствующих внутренних адресов переходов.
Это структурное наблюдение, не исполнение новых методов и не подтверждение
всех операндов / зависимостей. Сам helper строки имеет изменившиеся внешние
вызовы и глобальные адреса, которые ещё не проверены.

У PktCharacterListResult_Read остались три внешние привязки:
0x1456d32e0 → 0x1456d6f70, 0x1420e2ac0 → 0x1420e88c0 и таблица
0x1498d90a0 → 0x14992adf0. У CharacterList_RecordRead шесть вызовов прежнего
helper 0x144aa68b0 ведут на 0x144aae4e0; этот же helper используется в ответе
выбора. Следом проверить эти зависимости, packet ID / vtable и границы чтения,
затем выполнить bounded scenarios новой сборки. Старые profiles / native tests
пока не переведены на новый SHA, успешный live-вход не подтверждён.

Старый реестр и 424 функции остаются историей прежнего SHA. Для поиска добавлен
явный [исторический режим](../../README.md) `--source-snapshot`, сохраняющий
проверки SHA и evidence; база построена в отдельном каталоге
`knowledge/historical/c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8/`
библиотеки ресурсов. Защита обычного текущего реестра сохранена.
После подтверждения новых связей нужны новая ревизия и совместимость codecs;
затем, после технических работ, реальный вход. Серверное состояние, поддержка
новой сборки runtime и полный охват таблиц / карты / интерфейса не подтверждены.

### Callback списка и helper вложенного чтения

Ghidra export с `inspect-release-function-candidates.py --dependencies`:
`details/run-5ca35f2db51a/details.json` внутри `run-fd4956a37b3c`, SHA256
`f76d87c0c5a4f2704246e0b50c2dcf196af888bb10955d4730304840a70e0fd9`.
Псевдокод clear / resize и callback-методов выгружен с обеих сторон.
У части старых функций нет сохранённых инструкций в Listing; пустой массив
instructions не означает пустое тело. Thunk не имел Function в обеих базах.

Метка `StringRead_ThunkCandidate` в этом неизменяемом отчёте неточна:
0x144aa68b0 / 0x144aae4e0 — dispatch чтения вложенного объекта, не decoder строки.
Для следующих запусков метка исправлена на `NestedRead_ThunkCandidate`.

Первые три слова по 0x1498d90a0 / 0x14992adf0:

| Смещение | Старый указатель | Новый указатель | Наблюдение Ghidra |
| --- | --- | --- | --- |
| +0x00 | 0x141b04f00 | 0x141b0ac30 | Освобождение wrapper |
| +0x08 | 0x1456e3ea0 | 0x1456e7cf0 | Очистка, count = 0, resize при иной capacity |
| +0x10 | 0x1456da1a0 | 0x1456de090 | Временная запись, dispatch чтения, добавление при успехе |

Clear проходит элементы с шагом 0x170: 0x1456d32e0 → 0x14577ef70 в старом EXE,
0x1456d6f70 → 0x145786670 в новом. Resize: 0x1420e2ac0 / 0x1420e88c0.
Новый callback чтения вызывает constructor 0x145784b10, helper 0x144aae4e0 и
copy 0x1456d85c0. При успехе увеличивается count и запись копируется по
`base + index * 0x170`; cleanup временного объекта есть и при отказе.
Это статический разбор, не исполнение новых контейнерных helpers.
Соседнее слово +0x18 различается: 0x141b04f00 / 0x1456ee7d0. Граница таблицы
не установлена; объявлять его подтверждённым четвёртым методом нельзя.

[replay-release-nested-read-thunk.py](../../../replay-release-nested-read-thunk.py)
сверил SHA обоих сохранённых EXE и Ghidra evidence. После отсутствия Function
использованы имеющийся PE-reader, Capstone и Unicorn. В обоих EXE совпали байты
helper `488b024c8bc2488bd1498bc848ff6020`: vptr берётся из входного RDX,
RCX становится object, RDX — archive, затем tail jump в virtual +0x20.
На каждой сборке исполнены девять сценариев: три размещения и три результата
fixture virtual reader (0, 1, 0xdeadbeef). Все 18 проверили порядок аргументов,
выход по return и сохранность результата.

Отчёт внутри `run-fd4956a37b3c`:
`nested-read-thunk-replay/2b1fe069924f8820f5cf13ac19eac598f05c9769465abcb24c60d1b6a94b41e0/manifest.json`.
Последний каталог — SHA256. Сохранены source/tool SHA, версии библиотек,
инструкции, байты, file offsets и первые три слова callback-таблиц. Слова
проверены чтением файла, callback в этом replay не исполняется.
Строковый decoder, весь список, packet ID / vtable и live-вход не проверены.
Следом — record vtable → reader, actual archive readers и полные bounded list
scenarios для нового SHA. Runtime пока не объявлен совместимым.

### Конструктор записи → vtable → reader

Дополнительный Ghidra export конструктора, Archive_ReadFString / ReadArray и
вложенной зависимости: `details/run-cb6f5eff23f7/details.json` внутри
`run-fd4956a37b3c`, SHA256
`778cc016dd5b5744ef539045add4502342b263f7c7dac37ebf2947c7e1226d78`.
Промежуточный export `run-356f180aa51c` сохранён отдельно; его SHA256
`e805f131a930ccaea129407d3fb4a67320b70649af6f383a12ab20d09bf7bceb`.

У новой записи constructor 0x145784b10 устанавливает vptr 0x14992a420.
Её slot +0x20 содержит 0x1457897d0 — кандидата CharacterList_RecordRead.
Старая цепочка: 0x14577d3d0 → 0x1498d7ff8 → 0x145781c80.
Новый Archive_ReadArray 0x144aad880 сначала читает uint16 через archive+0x68,
затем вызывает callback+8 для подготовки массива и callback+0x10 для элементов,
прерываясь при отказе. Это статическая проверка Ghidra, не исполнение array IO.

Первая попытка исполнения конструктора остановилась на защите leaf-кода:
вместо старого leaf 0x1457eca60 новая запись вызывает 0x1457a47d0, который
дополнительно вызывает 0x1457fedc0. Новый wrapper выгружен через Ghidra;
базовый leaf не имел Function и затем разобран Capstone: установка vptr,
обнуление qword +8 и возврат объекта. Неизвестный вызов не заменялся заглушкой.
После проверки добавлены actual wrapper и leaf; соседний leaf 0x1457917a0
также исполняется. Старые nested leaves — 0x1457eca60 и 0x145789700.

[replay-release-record-binding.py](../../../replay-release-record-binding.py)
исполнил оба record constructors и перечисленные вложенные методы в Unicorn.
На каждой сборке проверены заполнения объекта 0 / 0x5a / 0xff и два размещения:
12 сценариев. Проверены return pointer, ожидаемый vptr и file-backed slot +0x20;
canaries перед / после 0x170-байтного объекта сохранены. Код ограничен
проверенными constructor ranges и leaves, бюджет — 2000 инструкций на вызов.
Непроверенный выход за эти ranges вызывает отказ; fixtures методов нет.

Отчёт внутри каталога сравнения:
`record-binding-replay/36c7b4365f3ff677f00cfc69c093be450801bc37d39fc33edbacc9d85e9f78ff/manifest.json`.
Последний каталог — SHA256; сохранены SHA источников / инструментов / Ghidra
evidence, native ranges, leaf bytes, результаты и снимки объектов.
Сам reader по slot +0x20 ещё не исполнен. Следом — actual archive IO / UTF-8
и полный body списка с проверкой чтения и отказов на новом SHA. Готовность
декодера всей сессии или runtime этим этапом не подтверждена.

### Новый input archive: constructor и числовое чтение

Ghidra export: `details/run-ecc4c9718f83/details.json` внутри `run-fd4956a37b3c`,
SHA256 `c2e050e62bd50d5bfe0fc5a97bd0047fc3b9d8be223cea79dde03f1747fb4f11`.
Промежуточный `run-a4e4306dd03f` имеет SHA256
`f307b73e920385656c4e5a5d0aedb43f6f2bdc1b45dbdd22c32b6a17ff0a3a92`.
В нём предполагаемый адрес constructor 0x144aad4f0 не имел Function; проверка
PE unwind установила, что это середина функции 0x144aad4e0. Эта гипотеза
отклонена, начало функции повторно проверено Ghidra. Имя пары
Archive_InputConstructCandidate в export не доказывает эквивалентность старому
constructor с буфером: новый 0x144aad4e0 — default constructor без буфера.

Поиск последовательности двух уже найденных reader pointers дал две таблицы:
0x1496726a8 и 0x149672840. Их reader slots совпадают, destructor отличается.
Ghidra показал установку 0x1496726a8 в default constructor 0x144aad4e0;
далее это подтверждено его исполнением. Начальный вызов 0x144aae160 — leaf
инициализации базового archive, проверенный после отсутствия Function в Ghidra.
Пустой список Ghidra references в этом частичном проекте не означает отсутствия
ссылок на таблицы.

[replay-release-archive-input.py](../../../replay-release-archive-input.py)
выполнил actual default constructor, raw reader 0x144aad910 и scalar readers:

| Формат | Reader | Слот таблицы |
| --- | --- | --- |
| uint8 | 0x144aad590 | +0x78 / +0x80 |
| uint16 | 0x144aad5a0 | +0x68 / +0x70 |
| uint32 | 0x144aad5f0 | +0x58 / +0x60 |
| uint64 | 0x144aad7f0 | +0x48 / +0x50 |
| bool | 0x144aad840 | +0x88 |
| raw bytes | 0x144aad910 | +0x90 |

63 сценария: значения 0 / 1 / максимум ширины и каждый доступный префикс от
0 до полной ширины. Проверены code возврата, фактически потреблённые байты и
decoded value при успехе; bool нормализует ненулевой байт в 1. Частичный raw
read потребляет доступный префикс, но возвращает отказ, если он короче запроса.
Swap выключен actual default constructor; big-endian ветви не исполнялись.

После настоящего default constructor буфер и длина задаются явной fixture.
CRT memcpy по 0x1487f7a19 проверен как импорт vcruntime140.dll / memcpy и
заменён bounded copy (до 64 байт, только scratch). Bookkeeping 0x144aae4f0
исполняется, неизвестные code targets отклоняются. Инициализация входного
буфера штатным receive-конструктором этим replay не проверяется.

Отчёт внутри каталога сравнения:
`archive-input-replay/cae9f161880263dd8278116751cefbb6fc90844b410017ac7452cd285f13385d/manifest.json`.
Последний каталог — SHA256. Сохранены SHA EXE / Ghidra / инструментов, версии
Capstone / Unicorn, native ranges, leaves и результаты. UTF-8 / FString,
callback массива и весь список на новом EXE ещё не исполнены. Следующий шаг —
перенести эти зависимости, сохранив исходные ограничения прежних scenarios.

### UTF-8 / FString новой сборки

Ghidra export цепочки строк: `details/run-c49c5bae9fe5/details.json` внутри
`run-fd4956a37b3c`, SHA256
`dd47cf6861dc3872ee93f05d9bcd08849f0a144bcb8c15a7f92c49370790038a`.
Промежуточный export `run-700d46644bc9` сохранён с SHA256
`e7340ba1a7295bb79f713b7e35aa5167965d654da84ce413976aa6fd70c1e20e`.

| Участок | Новый адрес |
| --- | --- |
| Archive_ReadFString | 0x144aae320 |
| Archive_ReadStdString | 0x144aad6e0 |
| UTF-8 length | 0x14144c520 |
| Decode wrapper | 0x141446780 |
| Decode core | 0x14143be10 |
| Decode scalar | 0x14143ba80 |

[replay-release-fstring-input.py](../../../replay-release-fstring-input.py)
исполнил эти методы и actual archive byte IO на новом EXE. Проверены шесть
полных строк: пустая, ASCII, `Ж界🙂`, 16 букв é, 129 ASCII-символов и 130
иероглифов. Декодированный текст совпал; последние случаи охватывают рост
stdstring и UTF-16 scratch свыше 128 units. Все 577 коротких префиксов
возвратили отказ, потребили только доступные байты и не присвоили итоговый текст.
Malformed UTF-8 и embedded NUL не проверялись.

Присваивание FString, рост stdstring, UTF-16 allocation, free и stack cookie
остаются bounded fixtures. Преобразование UTF-8 не заменено Python decode:
Python UTF-16 используется только для проверки уже записанного native результата.
После первого отказа эмулятора проверен прямой thunk 0x141432060 → 0x141483160;
он исполняется до явной free fixture. Неизвестные execution targets отклоняются.

Отчёт: `fstring-input-replay/c76f9bd73126854788ecdafc589d9b525ff5a559eab478da26078b20e52a3ad3/manifest.json`
внутри каталога сравнения; последний каталог — SHA256. Сохранены SHA EXE,
Ghidra evidence и harness, native ranges / leaves, версии инструментов,
результаты и ограничения. Работа со строками не доказывает готовность всего
списка, handler или live-сессии.

Harness [replay-release-archive-input.py](../../../replay-release-archive-input.py)
выделен в `make_harness` для дальнейшего целого reader, с дополнительными
проверяемыми ranges и явными fixture handlers. Повторная проверка его 63 scalar
сценариев прошла после изменения. Новый отчёт scalar regression:
`archive-input-replay/806852fc8cde0897494fc647b8537a2af667cefb492120dc5d4f542928a5fb94/manifest.json`.
Следом — actual list / record readers и callback массива с прежними bounded
container fixtures; переносимость runtime пока не подтверждена.

### Целый body списка: базовый профиль новой сборки

В [replay-release-character-list.py](../../../replay-release-character-list.py)
соединены actual readers packet body / record / вложенных полей, constructors
record, archive IO / UTF-8 и callbacks главного массива. Последний Ghidra export:
`details/run-2cc64357ed05/details.json` внутри `run-fd4956a37b3c`, SHA256
`facdd4d4f5073c63f95ac13f79e5b55dbf0039cf5278658ab377d820e4e57279`.
Предыдущий `run-100be368d878` сохранён с SHA256
`51aedcd17350afd5eb13b5f2bb931a7738ef46223e1cec873cc2004aaae25c3f`.

Проверены file-backed nested vtable slots +0x20:

| Vtable новой сборки | Reader |
| --- | --- |
| 0x1499212d8 | 0x1457fefb0, raw64 через archive+0x28 |
| 0x149922470 | 0x145795e90, четыре uint16 |
| 0x149921fb0 | 0x145788d00, внешний вид |
| 0x149923ba0 | 0x1456c42d0, optional-блок |

Первый запуск остановился на немаппированной таблице вложенного leaf-объекта.
После сверки slot → reader её данные добавлены в эмулятор. Метод чтения не
подменялся. Callback внешности 0x1456bb730 и archive helper 0x144aad7c0
предварительно выгружены через Ghidra и исполняются в общей цепочке.

12 полных bodies: три пустых списка с разными кодами результата; затем
1 / 2 / 4 записи с пустыми строками, Unicode и 128 ASCII-символами. Проверены
нулевые / предельные числа, enum clamps и bool. Заголовок, tail и поля каждой
записи совпали с существующим переносимым decode_character_list. В native
результате явно проверены нулевой count extensions внешности и отсутствие
optional map. Это структурное чтение, не разрешение выбрать персонажа при
ненулевом result_code.

238 коротких префиксов пустого / одноэлементного Unicode списка получили отказ;
выход за доступный input не наблюдался. Native reader допускает хвост, потребляя
только body: поведение проверено отдельно. Переносимый decoder сохраняет
проверку точного потребления; нормализовать хвост как допустимый пакет нельзя.

Packet storage, allocation массива (до 4 записей), shallow copy, cleanup и
string storage остаются явными bounded fixtures. Packet constructor и ID здесь
не доказываются. Непустые appearance extensions и optional map не выполнены.
Общий лимит input — 4096 байт, исполнения — 2 000 000 инструкций на body;
неизвестный code target вызывает отказ. Fixture hooks не читают wire-поля.

Отчёт внутри каталога сравнения:
`character-list-replay/05922d10b2753da6538c66ef3f73a2594f81446dd4d8517de6fcb50095bc6436/manifest.json`.
Последний каталог — SHA256. Сохранены source / tools / Ghidra / portable decoder
SHA, native ranges / leaves, bindings, результаты и ограничения.
Предварительный отчёт `c605340dd7d53c099b7e8bbb5a484baee61c41d1bacf7ac706389b21ee7526ce`
не содержал явной проверки пустых native extensions; не использовать его как
более широкое покрытие. Следом — непустые extensions / optional map и packet
bindings; затем обработчик списка и реальная сессия при готовности сервера.
После выделения string harness повторно прошли его шесть полных строк и
577 префиксов. Отчёт regression:
`fstring-input-replay/3d1f021f36a2f1e5af3a0ddd5e8799d1f6525bb5690d94d45e10e31098f6c29a/manifest.json`.

### Непустые appearance extensions и optional map

[replay-release-character-extensions.py](../../../replay-release-character-extensions.py)
продолжает whole-list harness на новом SHA. Ghidra export новых зависимостей:
`details/run-c835a4433cde/details.json` внутри `run-fd4956a37b3c`, SHA256
`f80a7771f06e6b888c00df5b093de6521ffa2fe96bd0bfba3867fbf36e5ae34b`.
Первый export callback / pair constructor сохранён отдельно:
`details/run-92602aee7309/details.json`, SHA256
`fb8ee4b49b9fc0f89b7b4fd477ddf5c0db050365e5d10bd9b4d6e6c3b7d60f66`.

| Участок | Новый адрес |
| --- | --- |
| Appearance callback | 0x14573cc90 |
| Appearance item constructor / reader | 0x145783f30 / 0x145787660 |
| Optional callback | 0x1456c8140 |
| Native optional insert | 0x1456bea70 |
| Pair constructor | 0x1456bcea0 |
| Value constructor / reader | 0x145785490 / 0x14578a680 |

Callback внешности по таблице 0x149941770 создаёт и читает 0x10-байтный item.
Native item reader проверяет `<IBH>` с clamp enum до 45. Optional callback
по таблице 0x149926e38 читает key byte, ищет его по bucket chain и использует
существующий node при совпадении. Только отсутствующий ключ идёт в native insert.
Pair constructor устанавливает value table 0x149923a38; value reader читает
enum / три uint32 / raw64, enum ограничивается 9. Эти пути исполняются,
а не заменяются portable decoder в hooks.

31 полный whole-list body совпал с portable decoder по полям записей:
appearance arrays с 0 / 1 / 2 / 8 элементами; absent / empty / nonempty optional
map; 1 / 2 / 4 персонажа. Есть максимальные значения, enum clamps, восемь
коллидирующих ключей и повтор ключа после заполнения map. Проверка insertions
подтвердила отсутствие дополнительного node при повторе; последнее значение
заменяет прежнее через actual callback. Отдельный body с разными appearance и
map у двух соседних записей проверил отсутствие общего тестового хранилища.
Все 489 коротких префиксов двух bodies с extensions получили отказ без чтения
за доступный input.

Storage / reset массива и map, bitvector capacity, unseen-key insert predicate,
bucket rehash, shallow copy, cleanup и string storage остаются bounded fixtures.
Реальный поиск повторного ключа / overwrite выполняются native-кодом, но это не
доказательство штатного allocator и времени жизни контейнеров. Fixture узлов map
не переиспользуется между скопированными записями; разные соседние данные явно
проверены. Лимиты — 4 персонажа, 8 уникальных узлов map и 8 appearance items
на запись; portable decoder получает aggregate budget 128. Пакетный constructor,
ID binding, handler и live-вход этим этапом не проверены.

Отчёт внутри каталога сравнения:
`character-extension-replay/3628a3d66034a7169de8493419a108c2b9a22982585e35051e585d2375ffe67c/manifest.json`.
Последний каталог — SHA256. Сохранены source / Ghidra / tool SHA, native ranges,
leaves, результаты и ограничения. После выделения whole-list harness повторно
прошли базовые 12 bodies / 238 префиксов; regression report:
`character-list-replay/5d02b503ad727f35da5d85d4116bed6d21020f576baf6a3543a5fc884b786d61/manifest.json`.
Дальше — packet ID / vtable binding и обработчик списка, затем выбор персонажа
и реальная сессия после проверки актуальной ревизии и готовности сервера.

### ID 102: constructor, vtable и регистрация handler

По уникальному указателю на уже проверенный reader 0x1456dcf00 найдена таблица
0x14992a968. По LEA этой таблицы установлен кандидат leaf constructor
0x1456d84f0; единственный прямой call-кандидат находится по 0x1467b6973
в factory root 0x1467b62f0. Совпадение байтов поиска само по себе не принято
как роль: constructor / getters и участок фабрики затем проверены исполнением.

Ghidra export фабрики: `details/run-36c407109687/details.json` внутри
`run-fd4956a37b3c`, SHA256
`1d414ee4ce052123a9cfa6a833bcacd5b3576a2c6b2224c1e7ab90e2aa778e17`.
Декомпиляции целых old/new factories остановились по timeout, что сохранено
в отчёте. У новой фабрики есть 19 000 инструкций Listing, использованных для
сверки конкретного участка; полнота фабрики этим числом не доказывается.
Constructor не имел Function в Ghidra и проверен как bounded leaf.

Выборочный export register / handler / getters:
`details/run-ab4ca396be23/details.json`, SHA256
`64a07328ba5dc14b901dc01005a8515a0a102a893eb750d4e3fa309a92040767`.
Runner получил `--only` для выбора нужных dependency pairs без повторного
экспорта всей фабрики. Первый запуск `run-8f2cc3538ac2` отчёта не получил:
Ghidra разделил comma-список на отдельные аргументы; Java parser исправлен.

| Привязка новой сборки | Адрес / значение |
| --- | --- |
| Constructor | 0x1456d84f0 |
| Vtable | 0x14992a968 |
| Writer +0x10 / reader +0x20 | 0x1456e9390 / 0x1456dcf00 |
| ID getter +0x28 | 0x1456e5ee0, возвращает 102 |
| Name getter +0x38 | 0x1456e70b0 |
| Compiled name | PktCharacterListReadResult |
| Handler vtable / method +0x10 | 0x149dc8800 / 0x146797990 |
| Register call / function | 0x1467b6986 / 0x1467ccd50 |

[replay-release-character-packet-binding.py](../../../replay-release-character-packet-binding.py)
исполнил factory slice 0x1467b6940..0x1467b698b с allocator/backend fixtures.
Три размещения подтвердили передачу RCX=factory context, RDX=packet,
R8=handler. Vptr обоих объектов установлен actual-кодом; constructor не
повредил canaries 0x48-байтного packet и 8-байтного handler.
ID getter исполнен и дал 102. Name getter передаёт compiled ASCII-литерал
по 0x14992a9b8 в 0x141426a30 и возвращает destination. Helper построения
строки заменён capture fixture; его layout не выдуман и не считается проверенным.
Первоначальное предположение о UTF-16-литерале отклонено по фактическим байтам.

Отдельно исполнен prefix регистрации 0x1467ccd50..0x1467ccd9c: actual call
virtual +0x28 и запись AX как uint16 в ключ. Во всех трёх размещениях ключ 102
совпал с ID пакета. Backend-вставка 0x1467b5a90, весь dispatcher и handler
не исполнялись. Новый handler выгружен: в нём видны result gate 0x1467cee40,
predicate 0x145c9c0d0 и применение списка; их новый bounded replay ещё впереди.

Отчёт внутри каталога сравнения:
`packet-binding-replay/9da68c98aab2b6cefa9ef9821b03b7d63aff272c619db1c6cc851e0dfaedb6a2/manifest.json`.
Последний каталог — SHA256. Сохранены SHA EXE / Ghidra / инструментов, версии
Capstone / Unicorn, code bytes / slices, bindings, результаты и ограничения.
Прежний отчёт `873105a2e577081385a0326c6527d3a63cd0c71195d5b01a36809270800aaa89`
предшествовал добавлению версий библиотек и dependency SHA.
Подтверждён ID 102 и его reader, не совместимость всех packet bindings клиента.

### Подготовка проверки handler новой сборки

Выборочный Ghidra export завершён в `details/run-7862c6b69a2a/details.json`
внутри каталога сравнения. SHA256:
`9d9837e711ae068aff760f3b5efe743c78d1d944e18de2be167b807274712f25`.
Он содержит инструкции и псевдокод result gate 0x1467cee40 и predicate
0x145c9c0d0, вызываемых новым handler 0x146797990. Это подготовленные входы
для проверки исполнения, а не доказательство прохождения условий в игре.

Harness непустых extensions выделен в `make_harness`, чтобы reader и handler
можно было проверить в одном эмуляторе. Передаётся адрес декодированного packet;
его constructor и жизненный цикл этим изменением не подтверждаются.
Повторная проверка сохранила результат: 31 полный body совпал с переносимым
decoder, 489 коротких префиксов получили отказ. Новый immutable-отчёт:
`character-extension-replay/997f120a5a058a2c3cce7510bba5cada8e3ac036fa3b08239d7d78598aafd7a2/manifest.json`.
Границы fixtures прежние. Следом — исполнение handler с gate / predicate,
проверка применения списка и выбора начального индекса.

### Новый handler списка: совместное исполнение

[replay-release-character-handler.py](../../../replay-release-character-handler.py)
исполняет body / record / extension readers, затем handler 0x146797990,
result gate 0x1467cee40 и predicate 0x145c9c0d0 в одном Unicorn-эмуляторе.
Входы привязаны к новому SHA EXE `98802d550890…`; SHA двух Ghidra exports
проверяются перед запуском. Packet vptr устанавливается fixture из независимо
проверенной таблицы 0x14992a968; ID getter 0x1456e5ee0 исполняется настоящим кодом.
Проверены фактические аргументы gate: код ответа и packet ID 102.

50 сценариев подтвердили поведение в проверенных ветвях:

- Код 0 проходит gate. Коды 1, 14, 22, 37, 54, 9400, 9818, 9819, 90021 и
  0xffffffff отклоняются; handler вызывает controller virtual +0x38 и сохраняет
  прежний список. Это не классификация всех возможных кодов gate.
- После gate список применяется только при predicate == 1. Проверены policy
  0 / 2 / 4, отключённый поиск policy и отсутствующий policy object.
- Передаются прежний count в cleanup, новый count в allocation / copy;
  состояние +0x70 / +0x78 получает записи. После fixture copy совпадают все
  байты записей, включая непустые вложенные extensions / optional map.
- Native stores переносят packet +0x30 в state +0x80 и младшие 32 бита
  packet +0x28 в state +0x84. Packet +0x40 передаётся helper 0x145ca6570.
  Отрицательное signed-значение packet +0x28 вызывает warning capture.
- Предпочтение packet +0x38 сравнивается с record +8; берётся первое совпадение.
  Sentinel по данным нового EXE 0x149672698 равен 0. Для sentinel, отсутствующего
  ключа и пустого списка UI получает индекс 0. Проверены повторные и нулевые ключи,
  первое / среднее / последнее совпадение и отсутствующий UI.
- Проверенный путь вызывает owner virtual +0xa00 при наличии owner, завершение
  UI, selection event с младшим байтом аргумента 6 и transport setter с 0.
  Замена непустого списка, очистка пустым ответом и сохранение прежних записей
  при отказе проверены отдельно; gate state 1 проверен при успехе и ошибке.

Engine objects / type metadata / policy virtual, singleton getters, диагностика,
state allocation / shallow copy / cleanup, UI / owner / events / transport setter
остаются явными fixtures или captures. Вторичная engine-проверка получает null
fixture; реальный engine lifecycle не исполняется. Неизвестные execution targets
отклоняются. Это проверка применения списка и начального индекса, не отправка
запроса выбора персонажа и не доказательство позиции или сетевой совместимости.

Воспроизведение:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-character-handler.py
```

Отчёт внутри каталога сравнения:
`character-handler-replay/0b93ec2b7986a449cc789873e7af6965ed9efc4c7f4970f9c0631187c3472503/manifest.json`.
Последний каталог — SHA256 отчёта. Сохранены SHA источника, Ghidra / scripts /
dependencies, проверяемые диапазоны, trace инструкций gate, fixtures и результаты.
Следом — источники полей и отправка запроса выбора в новой сборке, затем её
ClientVersion и реальная сессия. Старые адреса выбора пока остаются историей.

## Автоматизация следующих обновлений

Требование пользователя от 21 октября: разработать автоматическое обновление
и сверку; вручную доправлять то, что система не смогла установить. Это требование
к будущему процессу, не заявление о готовой автоматизации.

Единый запуск должен последовательно выполнять:

1. Проверить завершённость установки, снять версии и SHA EXE / manifest / архивов,
   сохранить снимок и сравнить с последним принятым выпуском. Выборочные отпечатки
   подходят для первичного обнаружения; подтверждение неизменности требует SHA.
2. По изменившимся источникам повторно извлечь индексы, таблицы, ресурсы и код.
   Неизменившиеся результаты использовать из проверенного кеша по SHA источника,
   инструмента и зависимостей. Сохранять старые данные и возможность продолжить
   прерванный запуск с последнего проверенного этапа.
3. Сопоставить таблицы и ресурсы, получить кандидатов соответствия функций через
   Ghidra, вычислить затронутые codecs, ссылки, UI, карты и сценарии. Одно имя,
   схема таблицы или совпадение инструкций не подтверждает всю связь.
4. Автоматически запустить проверки структуры, ссылок, границ и поведения для
   затронутых компонентов. Принятый результат должен сохранять доказательства,
   SHA входов, версии инструментов и воспроизводимую команду.
5. Сформировать отчёт: что подтверждено автоматически, что изменилось, какие
   проверки не прошли и что требует ручной работы. Для каждого нерешённого пункта
   указать источник, прежнюю связь, причину неопределённости, затронутые функции
   бота и следующую проверку. Ручное исправление включать в повторный запуск,
   чтобы не повторять уже подтверждённые этапы.
6. Подготовить согласованный пакет данных и профиль совместимости для лёгкого
   runtime. Применять его только после обязательных проверок соответствующих
   возможностей; нерешённые зависимости явно отмечать как недоступные. Хранить
   последний принятый пакет для возврата. Реальную сетевую проверку учитывать
   отдельно: офлайн-сверка не доказывает успешный вход на сервер.

Первые составные части уже есть: аудит, сравнение снимков, свежие индексы,
сравнение CSV / сохранённых файлов и поиск функций с привязкой к SHA.
Ещё нужно объединить их в управляющий инструмент, хранение состояния этапов,
граф зависимостей, очередь ручной доработки и проверку совместимости пакета.
Для каждого этапа нужны машинные статусы: ожидает, выполняется, проверен,
ошибка или нужна ручная доработка. Запись должна включать SHA входов,
инструмента и зависимостей, путь и SHA результата, выполненные проверки.
Продолжение допускается только при совпадении этих входов и проверке результата;
после ручного исправления повторяются затронутый этап и зависимые проверки.
Нерешённый пункт должен указывать конкретную недоступную возможность runtime,
чтобы частичный успех не выдавался за совместимость всего бота.
Текущий разбор двух EXE должен дать первый реальный набор правил и нерешённых
случаев для этого процесса. Исследовательские инструменты остаются вне runtime.

## Подготовка к следующему обновлению, 21 октября 2026

Пользователь подтвердил реальные технические работы, совпавшие с ответом лобби
10036 / IsInspect. Новый захват
`C:/Users/Валентин/.phone-exit/diagnostics/29e2bf9fd9e760d9a0b7eb26f0fe423b/traffic.jsonl`
прошёл `capture-inspect.js`: 479 байт файла, штатное ручное завершение, 0 потоков
и 0 байт данных. SHA256
`f1d0fabd52e598337430fed2dc326e2684374002a341f40275e950e24541d45a`.
Это отсутствие совпадений с игровым фильтром, не доказательство отсутствия
трафика лаунчера или расшифрованная запись технических работ.

На предоставленном затем снимке лаунчера: Updating Game 53%, Downloading
293.84 MB / 443.04 MB, видимый номер 1.13.14. Обновление игры ещё шло;
завершённая установка и принадлежность номера к конкретному компоненту
пока не проверены по файлам. Полный аудит изменяемых архивов не запускался.
Снимок пользователя сохранён вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/user-maintenance-update-d20a4970.png`,
SHA256 `b0238c88901e0ee182e4003ba13cd415e3f192613141e53b08adf0a2624e34e0`.

Перед этим чтение установленного EXE и patch manifest дало прежние SHA256:

- EXE: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`;
- windows.manifestlist: `4dff7291228f11bd330f80af5a2797a877396e41287fe46a0db8fa4e3e874ffd`;
- ClientVersion: Revision258392, прочитан существующим строгим parser.

Прежний EXE сохранён вне Git:
`F:/PhoneExit Resources/Vampir/client-code-snapshots/c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8/ProjectRED-Win64-Shipping.exe`.
Рядом в `patch/4dff7291228f11bd330f80af5a2797a877396e41287fe46a0db8fa4e3e874ffd/`
сохранены windows.manifestlist и baseline.json. SHA256 baseline.json:
`9b52a961b285fa3b4b993d973776dea9b2ec7e395b9f39987eb07634504264c3`.
Копия EXE проверена полным SHA, повторно сверён исходный EXE; старые экспорты
и извлечения не менялись. Полные хеши всех архивов этим снимком не покрыты.

После окончания обновления: повторно проверить EXE / manifest / ClientVersion,
затем выполнить существующий аудит архивов ниже. При новом SHA EXE прежние
адреса, native scenarios и codecs остаются историей старой сборки до проверки
затронутых связей. Совпадение EXE само по себе не подтверждает неизменность
таблиц, карты или UI. До сверки версии новые live-входы не выполняются.

Во время этой же работы установленный EXE уже изменился: последующее чтение
дало SHA256 `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Patch manifest пока сохранил прежний SHA256. Это промежуточное наблюдение
обновляющейся установки, не подтверждение завершения или согласованности версии.
`function-registry.py --build` штатно отказался: `Installed client changed;
old registry is historical`. Защита не обходилась; старый реестр теперь относится
только к сохранённому EXE. После завершения нужен новый source-bound аудит.

## Результат предыдущего аудита

Пользователь подтвердил небольшое обновление игры. Проверка установленного
клиента обнаружила 34 изменённых архива и один новый; 128 остальных совпали
по размеру, mtime и выборочному отпечатку. Это не полное сравнение содержимого.
Проверено 163 архива, включая CEF `.pak`; 107 относятся к UE PAK версии 11.

EXE `ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe` сохранил SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Статические адреса и native fixtures остаются привязаны к этому EXE; совпадение
кода не подтверждает актуальность таблиц, карт, конфигурации или сервера.
Версия выпуска игры и версия Android неизвестны.

## Снимок и воспроизведение

### Повторная проверка после сообщения пользователя об обновлении

19 октября аудит установленного клиента выполнен повторно. Получен тот же
манифест `0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114`:
состав 163 архивов, метаданные и выборочные отпечатки совпали с сохранённым
снимком, полные SHA256 35 изменённых/новых архивов и EXE также совпали.
Дополнительных отличий от уже учтённого обновления не обнаружено в этом объёме.
Для остальных 128 архивов по-прежнему нет полного сравнения содержимого.
Это не основание сбрасывать U02 или считать карты и связи обновлёнными.
Номер версии выпуска из этого аудита не определяется.

Инструмент: [audit-client-release.py](../../../audit-client-release.py).

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-client-release.py
```

Параметры `--install` и `--resources` позволяют явно выбрать установку и библиотеку.
Базовый инвентарь должен принадлежать той же установке. Поиск ограничен
расширениями `.pak/.utoc/.ucas` в известных каталогах архивов, Content/Paks
и Saved/PersistentDownloadDir/Patch/Install. Файлы аккаунтов, предпочтений,
кеш браузера и процессы игры не читаются. Сетевых обращений нет.

Результат вне Git:
`F:/PhoneExit Resources/Vampir/release-snapshots/0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114/manifest.json`.
SHA256 манифеста совпадает с именем его каталога. Он содержит SHA256 инструмента,
исходного pc-pak-inventory.json, EXE, старых source.json/entries.json и полные
SHA256 всех 35 новых/изменённых архивов (9 025 734 163 байта).
Исходный инвентарь и прежние извлечённые данные не перезаписаны.
Повторный идентичный результат использует тот же снимок; изменённый результат
получает другой каталог. Повреждённый существующий снимок вызывает ошибку.

Продолжение: [новые индексы 35 архивов и сравнение CSV](CLIENT-RELEASE-INDEX.md).

## Что требует обновления

34 прежних индекса отмечены `stale`. Изменились pakchunk0, 1, 100, 1000,
200, 2000, 2300 и его s1–s18, 3000, 3000_s1, 301, 3100_s1, 400,
400_s2, 500, 501, 501_s1. Добавлен `pakchunk2300_s19-Windows.pak`.
Полные имена, старые/новые размеры и отпечатки находятся в манифесте.
Некоторые архивы изменились при прежнем размере: одного размера недостаточно.

72 старых UE-индекса имеют статус `sample_only_unverified`. Совпадение
SHA256 первых и последних 64 КиБ не исключает изменения середины файла.
Для них не заявляется полная идентичность или готовность игровых данных.
Метаданные без изменения образца также требуют проверки и полного хеша.

Не применять старые offsets/entry IDs к 34 изменённым архивам. Не запускать
старый scan-resources.py для обновления этой библиотеки: он заменяет базовый
инвентарь и кеш извлечения. Следующий этап U02 — новые индексы в отдельном
снимке с полным SHA256 источника, затем сравнение ресурсов/связей и повторная
проверка затронутых таблиц, геометрии и SDK settings. Старые результаты
сохраняются как исторические доказательства своего источника.

`compatibility=not_established`, `full_archive_coverage=false`,
`network_ready=false`. Это аудит источников, не завершённый compatibility gate
бота и не подтверждение совместимости с сервером после обновления.

Три теста проверяют обход выборочного хеша изменением середины, классификацию,
неизменяемость снимков, обнаружение нового архива, stale index, полные хеши
изменённых файлов и сохранность старых данных. Используются искусственные файлы.
