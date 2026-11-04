# Канонические пути PAK: соединение mount / directory / name v2

Один общий случай закрывает 5276 прежних пробелов. Полные имена не выводятся
из склеенной строки: адаптер сохраняет исходные directory и name отдельно.
Новая структура читается из тех же проверенных raw directory bytes; проекция
на прежние path / encoded-offset и counts обязана точно совпасть со старым
parser. Старый parser, literal-key helper и исторические receipts не менялись.

## Правило и независимая проверка

В [исходнике закреплённого CUE4Parse](https://github.com/FabianFG/CUE4Parse/blob/1e3293d4b3ecaf6ef3d73641b9ffe47fa4cf1562/CUE4Parse/UE4/Pak/PakFileReader.cs#L393-L408)
ReadIndexUpdated удаляет ровно один начальный slash только у directory,
когда mount уже заканчивается slash, и соединяет mount, directory и name.
Коммит связан с установленным NuGet package через nuspec; SHA256 пакета,
SHA256 исходника и Git blob SHA1 проверены. Source хранится вне Git,
малый machine receipt фиксирует URL, commit и контрольные суммы.

На девяти настоящих PAK все 5276 прежних slash-случаев происходят из
directory='/', а filename с начальным slash не встречается. Независимый
проход установленным CUE4Parse 1.2.2.202610 получил те же 53 299 имён.
Кандидат ключа передан только через stdin, в файлы/логи не записывался;
исключения стороннего reader выводятся только как тип, без secret message.
Это проверка reader и формата, а не исполнение текущего игрового EXE.

## Обновление и результат

Selector schema2 включает path_rule=pak-directory-mount-join-v1; schema1
сохраняет прежнее строгое поведение. Неверный вариант, missing components,
traversal, абсолютный filename, двойной separator или canonical collision
оставляют конкретный отказ/пробел. Исходные raw path и components сохраняются.
Без подтверждённого разделения directory/name вырезать slash запрещено.

| Архив | Имена каталога | Закрытые прежние пробелы |
| --- | --- | --- |
| pakchunk0-Windows.pak | 7114 | 0 |
| pakchunk1-Windows.pak | 3122 | 0 |
| pakchunk1000-Windows.pak | 7694 | 0 |
| pakchunk2300_s18-Windows.pak | 8348 | 0 |
| pakchunk500-Windows.pak | 9788 | 2 |
| pakchunk501-Windows.pak | 6876 | 5178 |
| pakchunk501_s1-Windows.pak | 7414 | 86 |
| pakchunk502-Windows.pak | 2032 | 10 |
| pakchunk502_s1-Windows.pak | 911 | 0 |

Все 53 299 записей имеют canonical path; пробелов и коллизий — 0.
Прежние 3110 CSV-подобных привязок сохранили точные поля и payload SHA.
В этом числе 3109 CSV-файлов и одна PathFindingGolden.txt. Новая версия
правила получает собственные receipts/cache keys; старые результаты не
перезаписываются и не объявляются новыми доказательствами.

Первый компонентный проход занял 78.737383 с и назначил 9 результатов.
Тёплый повтор занял 39.369499 с: 9 cache hits, 0 новых результатов.
Сохраняются fresh source/alias/runtime/output barriers и отложенная cache
publication общего SHA owner. SHA клиента прежний. Native replay, CSV extraction,
новые JVM, полный ordinary update и игровой вход не выполнялись.

## Проверки и остаток

Добавлены 22 автоматических случая: 14 parser/path и 8 orchestration/cache.
Проверены совместимость components со старым parser, точные root/subdirectory
joins, UTF-16, truncation/counts, negative offsets, filename-leading slash,
missing provenance, alias collision, schema1 fallback, unknown schema2,
смена rule и тёплый повтор. Зарегистрированный набор завершил 1630 тестов
с тремя прежними пропусками; шесть дополнительных checks прошли.
Новая проверка включена в on_update и зависимости кэша.

Далее нужны точные старые named baselines для сравнения ресурсов по именам.
Каноническое имя не подтверждает выбор resource layer, игровую семантику,
совместимость или admission. Текущий owner и prepared-next не переключались.
Watcher не включался. 59 frozen native inputs и прежние facts сохранены.

- [Машинный отчёт](AUTO-RESOURCE-MOUNT-JOIN-V2-268356.json).
- [Предыдущая приёмка с пробелами](HEADLESS-RESOURCE-DIRECTORY-V1-268356.md).
- [Инструкция обновления](../../RESUMABLE-UPDATE.md).
