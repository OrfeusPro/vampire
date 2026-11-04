# Именованные CSV: историческая база и автоматическое сохранение

Сравнение теперь использует точный slot архива и canonical path. Схема CSV,
порядок записей и совпадающие строки не назначают имя. При следующем патче
штатный resource pipeline сам сохраняет проверенную базу; ручной разбор
неизменных таблиц для получения имён больше не требуется.

## Источники и границы исторической базы

Текущий EXE: 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f, версия 1.13.22. Ресурсный патч Revision268356.
Текущий pakchunk1: 2f2517ff83865ac13021f96d9babd8407e4fbee512ff29806106844e5d7d7ed3.
Доступная историческая база: 15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4; её EXE:
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960. Это более старая сохранённая база.
Непосредственно предыдущий pakchunk1 7c186d92... не имеет сохранённого
авторитетного каталога; переносить на него имена по схемам запрещено.

Цепочка historical directory → encoded prefix → exact record offset → decoded
SHA проверена заново по сохранённым файлам. Две старые record inventories
совпадают; каталог связан с полным release audit. Старого PAK для свежего
чтения нет: область результата — captured evidence, без заявления о свежем
SHA исторического архива. Payload найден только по точному decoded SHA.

| Исторические CSV | Количество |
| --- | ---: |
| Проверенный payload | 2721 |
| Проверенный record hash без payload | 377 |
| Нет decoded SHA из-за прежнего лимита 2 MiB | 9 |
| Всего именованных таблиц | 3107 |

2721 payload-привязка использует 2565 разных проверенных файлов. Старый producer
48f9af09... восстановлен из Git и зарегистрирован явно; AST decoder definitions
совпадают с текущим 08dbfde3... . Проверены полные SHA reader и Oodle. Старый
Python-код не исполняется, старые PAK и capture receipts не перезаписываются.

## Сравнение настоящих данных

В текущем pakchunk1 есть 3122 CSV-имени: 3109 разобранных payload и 13 записей
с точным decoded SHA, не принятых BOM CSV-парсером. Полнота имён проверяется
отдельно от наличия payload. Дополнительный CSV-подобный PathFindingGolden.txt
находится в pakchunk0; он не превращается в CSV-файл по расширению.

| Состояние относительно доступной старой базы | Таблиц |
| --- | ---: |
| Не изменились по SHA | 2074 |
| Изменились по SHA | 1024 |
| Новые имена | 15 |
| Удалённые имена | 0 |
| Старый SHA неизвестен | 9 |

Сравнение строк прошло для 634 таблиц: добавлено
4980 строк, удалена 101 строка,
изменено 6888 строк. Для 22
таблиц первая колонка неоднозначна, для 4
изменился header; сравнение строк там не выполняется. Ещё 364 изменённые
таблицы сравниваются только по SHA из-за отсутствия старого payload.
Это текстовый row diff; игровая семантика ключей, выбор resource layer и
совместимость из этих чисел не следуют. Девять неизвестных остаются открыты:

- L10N/it/Achievement_Name.csv
- L10N/jp/Achievement_Name.csv
- L10N/ru/Achievement_Name.csv
- L10N/th/Achievement_Name.csv
- L10N/th/Dialog_Name.csv
- NpcSpawn.csv
- Reward.csv
- StaticOperation.csv
- ToolNpcSpawn.csv

## Штатный путь, кэш и будущая база

Новый selector resource-named-tables-engine.json регистрирует точный legacy
reference и узкие producer bridges. Update definitions учитывают selector,
оба helpers и их зависимости; aggregate проверка включена в on_update.
Pipeline заменяет schema-only comparison точным named report, когда база
доказана. При отсутствии базы сохраняет fallback и готовые текущие CSV.
Ошибка proof и неизвестный historical hash дают конкретные review reasons.

База неизменяема и назначается только после общего SHA owner barrier.
Порядок задаётся явным rank; тёплый повтор сохраняет исходный predecessor,
а новый патч и возврат старого SHA сравниваются с последней назначенной базой.
Равные последние ranks, порча bytes, смена runtime или inventory блокируют
назначение. Ключ сравнения включает named proof, baseline, код, selector и runtime.
Полный directory lookup используется для выбранных table paths: файл .txt,
переставший проходить CSV-парсер, не становится ложным удалением, если имя
осталось в архиве. Все assets при этом не объявляются таблицами.

Первый компонентный проход уже сохранил девять capsules. После исправления
учёта полноты их original proof повторно проверен по узкому exact SHA bridge;
старые capsules не менялись. Разрешено изменение только собственного producer,
остальные producer dependencies обязаны совпасть. При смене иного helper
требуется отдельное доказанное правило либо новая база; доверия к старому
результату по одному имени нет.

Финальный проход: 211.254794 с, 9 сравнений и 0 новых capsules.
Тёплый повтор: 178.382609 с, 9 cache hits, 0 сравнений и 0 capsules.
В обоих сохраняются fresh source/output/alias/runtime barriers. Это две проверки
компонента обычного pipeline; полный ordinary CLI update не запускался.
Native replay, CSV extraction, новые JVM и игровой вход не выполнялись.

## Проверки и следующий шаг

Добавлены 36 автоматических случаев: 15 historical reference и 21 capture /
pipeline. Набор из 1666 тестов завершён с тремя прежними пропусками; шесть
дополнительных checks прошли. Проверены порча proof, SHA и AST, повреждённый
producer, неизвестные hashes, разные имена одинаковых bytes, следующий патч,
rollback, точный predecessor, cache publication после owner и смена runtime.

Дальше открыты девять старых неизвестных SHA, отсутствие ближайшей prepatch
named базы, encrypted / size и resource semantic gaps. Потребуется отдельно
связать named delta с selective impact потребителей; сейчас план остаётся
консервативным. Admission, prepared-next и текущая игровая сессия не менялись.
Watcher выключен; 59 frozen native inputs и 44 прежних fact objects сохранены.

- [Машинный отчёт](AUTO-RESOURCE-NAMED-BASELINE-V1-268356.json).
- [Канонические пути PAK](HEADLESS-RESOURCE-MOUNT-JOIN-V2-268356.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
