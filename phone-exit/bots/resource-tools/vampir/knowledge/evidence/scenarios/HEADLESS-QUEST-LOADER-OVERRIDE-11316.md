# QuestTask: совместная native загрузка и русские overrides

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`b1c15a8631338577fe29fc2193a2f20cd6856f0e725f424bc8e4671bf558a3b1`.
Все explicit roots уже экспортированы, новая collection не запускалась.
Контекст закрепляет 19 roots в 10 exports с полными SHA. Harness budget
расширен с 9 до 10 individually pinned receipts; limit 24 explicit roots
сохранён, recursive discovery отсутствует. Это только offline research harness.

## Совместная цепочка

[Base loader и numeric getters](HEADLESS-QUEST-SCALARS-11316.md) теперь вызывают
настоящий override `145b69ca0` вместо прежнего no-op fixture, а тот — настоящий
[localization transform](HEADLESS-QUEST-LOCALIZATION-11316.md) `14585e070`.
Whole loader, tokenizer, record construction/copy, primary/group FindOrAdd /
insert/growth/rehash, field stores, override lookup и group iteration выполняются
в одном Unicorn harness, от входа base loader до возврата.

Из current PAK прочитаны исходные физические строки шести задач 110120:
110120005, 110120010, 110120020, 110120030, 110120040, 110120070. Основной CSV:
entry 2983, SHA `6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Русский QuestTask_Name: entry 2359, SHA
`88efc2a29c7a52a4148ef916689b77044b25b4c028ad4feea96d0b4782ee57b7`.
PAK SHA `15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Record index / actual PAK / reader/Oodle / decoded payload hashes проверены.
Строки не пересоздаются через CSV writer. Named path binding дополнительно
установлен [отдельным inspector](HEADLESS-QUEST-OVERRIDE-DATA-11316.md).

В каждом из двух запусков — прямой/обратный порядок строк — native tokenizer
читает 1220 bytes основной таблицы и 423 bytes русской. Main parser достиг EOF,
вложенный override parser использует отдельный stack object. File fixture
передаёт source bytes и header mappings; actual file/header code не исполняется.

Override ищет существующие records по task ID в настоящей primary collision
chain. Проверены шесть записей TaskName в record+78. Bounded assignment fixture
отклоняет запись в любое другое поле. Необязательный Param отсутствует в
русском header: column fixture возвращает -1, native ветка пропускает обновление
record+90. Исходный полный Param, flags, scalars, XYZ/radius совпадают с main CSV
после завершения обеих функций. Group array сохраняет шесть тех же record
pointers в insertion-slot order, русский слой их не переставляет.

Названия: три «Идите ко входу», два «Подойдите к связанному», одно «Преследуйте
врага»; обратный запуск даёт обратный порядок. Каждая последовательность
использует 19 header lookups, 6 reads Untranslated и 6 TaskName assignments.
Actual CRT calls: 48 atoi, 24 _atoi64, 12 strtoul, 24 pow; Windows DLL SHA/locale
проверены до/после. Три node resize / два group-array resize происходят native
call flow, guards оставшихся allocations сохранены.

## Оставшиеся fixtures

File/header setup, named Untranslated read, UTF8/wide/FString storage,
assignment, prefix extraction/compare, string cleanup, settings getter,
allocation/free, fresh map clear, bit append/hash/duplicate check — явные
ограниченные fixtures. Для шести source rows Untranslated пуст; fixture
проверяет это и возвращает empty descriptor. Settings flags +1E4/+1E5 = 0;
locale descriptor empty, file fixture явно выбирает русский CSV по запросу
пользователя. Это не active settings/locale proof работающего клиента.

Source TaskName проходит настоящий transform, но Unicode conversion/storage
реализации остаются fixtures. Нет непереведённых/пустых переводов в этом
совместном сценарии; их native ветви проверены отдельно в 336 transform cases.
Source root для overrides больше не fixture, однако это не вся файловая
система и не whole game. Main numeric getters и decimal parser настоящие;
ненулевой service policy на этих шести пустых service-group rows не вызывается.

Missing/duplicate localization IDs, whole 5944-row main / 8461-row ru load,
current service policy и actual file/header/active flags требуют отдельной
проверки. `order_admitted=false`, runtime/owner/gameplay не меняются.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_loader_override_11316.py
```

Общий `replay-quest-loader-11316.py`, explicit context
`knowledge/native-contexts/quest-loader-override-11316.json`, registered offline
check `native-quest-loader-override-11316`; прежние main/scalar режимы сохраняются
и проверяются отдельно. Артефакт:
`code-clues/quest-loader-override-11316/5e419402ffb3e16b7f1f6f6feae6ad281388b181c198f45d9985be15abac785d/manifest.json`.

Следующая проверка — native missing/duplicate IDs перед whole catalog admission.
Действующая сессия сохранялась без Stop / relogin / изменения owner.
