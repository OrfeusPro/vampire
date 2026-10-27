# Native lookup записи окружения и производная инициализация

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [derived environment](HEADLESS-QUEST-DERIVED-ENVIRONMENT-11316.md).
На установленную 1.13.18 результат не переносится автоматически.

## Источник записи без fixture lookup

Whole wrapper145C79950 записывает u32 ID в handle+0, вызывает provider145C545B0,
передаёт ID в lookup145C53E30 и сохраняет полученный pointer в handle+8.
Provider в проверенном уже инициализированном TLS режиме возвращает14B1C8CF0.
TLS epoch и index задаются явно; ветвь первоначальной CRT-регистрации не выполняется.

Lookup не имеет unwind root. Его полные118 bytes до последнего RET закреплены
явным leaf в tool. Capstone проверяет полное декодирование, отсутствие CALL и
то, что каждый прямой переход остаётся внутри набора инструкций. Harness
дополнительно сверяет каждый байт с EXE и запрещает непросмотренную цель.
Границы Ghidra не расширялись.

Проверенные поля singleton (hex offsets):

| Поле | Участие в lookup |
| --- | --- |
| +20 и+4C | При равенстве сразу возвращается missing |
| +18 | Массив записей с шагом158 hex байт |
| +58 | Внешние buckets либо null для inline+50 |
| +60 | Число buckets; hash использует key & (count-1) |
| row+0 | Сравниваемый u32 key |
| row+150 | Следующий индекс collision chain либо FFFFFFFF |
| row+8 | Возвращаемый адрес inline value |

Названия полей и семантика счётчиков сверх этих операций не предполагаются.
Record pointer передаётся в уже проверенный derived B8; он читает value+0C.
Provider, lookup wrapper, leaf hash, handle getter и B8 выполняются в одном
эмуляторе; table lookup fixture из предыдущего сценария здесь удалена.

## 28 поисков и четыре инициализации

Матрица: inline2/external8 buckets × разные/равные счётчики × семь ключей.
Пять записей имеют keys0/1/10012/10020/FFFFFFFF и разные synthetic value+0C,
включая ноль. Проверяются hits, коллизии нескольких keys, missing2/10028,
ранний missing при равных счётчиках и корректное отличие найденного нулевого
поля от отсутствующей записи по самому pointer. Исходные map header, rows и
buckets остаются побайтно неизменными. Handle возвращает исходный output pointer
и сохраняет запрошенный u32 key, включая UINT32_MAX.

Перед каждой группой целиком исполняются фабрика145D9C7C0, базовый constructor
1456001D0 и производный virtual+10 initializer145DA3540. Последний вызывает
exact base initializer14560E670, затем selection145E0F840 с0 (fixture),
обнуляет поля+108/+158. После возврата phase+30=7, committed+40/pending+44=0,
derived vptr149A3DAC0 сохраняется. Четыре варианта initialization проверены
с памятью A5 и намеренно ненулевыми полями+108/+158.
Это source initialization contract; его фактический вызов engine не наблюдался.

## Источники и проверка

| Экспорт | SHA256 |
| --- | --- |
| run-430fed1bb906 | 6e162d6a5056ba52dbfe8bf50bec54e02b66ab2271c8c4d489e5c2f54a68bd06 |
| run-ca617b011bc3 | 6d544a194b99d1597156d3e4b8280ecb9d3979090789b5a450c0b884911f902c |
| run-9c3aa7f1a5cd | 2d5b59ea71478e48a63a172ef313f20c379e5d7ace470b041c5fa3ce9a0eb78e |
| run-eadbefe5996b | 5716c3cce601b7a762f2c9332f4e5aa41bfb3ef5621d7bb24add49b0a0699b05 |

Exports проверяются по source/bytes/block/direct-flow coverage и conditional
fallthroughs. Leaves lookup/init/handle getter/world getter заданы явно.
Tool `replay-quest-world-record-11316.py`, тест
`test_vampir_quest_world_record_11316.py`, check `native-quest-world-record-11316`.
Артефакт: `code-clues/quest-world-record-11316/16f1acdbd8e92a33f2a4c4335c11c21daa06d94645fc03e0ce69063563a295a7/manifest.json`.

## Границы

Allocator, base registry и selection callback — fixtures. Hash map и record+0C
синтетические; native loader реальных записей не выполнен. Строковый путь A8/C8
не включён в эту композицию. Field+0C не назван Type/GroupId по похожему порядку
CSV колонок: для такого вывода ещё нужен source loader/store.

Найденная локальная старая World CSV имела другой content SHA, чем свежая таблица
в проверке проекции; она не используется этим replay и не выдаётся за актуальные
входы. Свежий PAK/CSV для реальных строк нужно связать отдельно с native record.

`native_execution=true`, `network_used=false`, `action_admitted=false`.
Начальная phase7 не доказывает завершение загрузки: после ID204 writer оставляет
phase3, а дальнейшее завершение всё ещё не установлено. Нужны загрузчик записи,
имена/поле+0C и source переход после world completion, затем composition с Time.
Сессия ранее закрылась после обрыва интернета; новая авторизация и игровые
команды в этой проверке не выполнялись.
