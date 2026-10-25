# Полный source audit и explicit ScrollBoxSlot.Size

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Запрос `8a46e1c8b324b9429cf45d73bcc0da85a42b247f4f3a032387da21d798001c19`
содержит прежние пять getters и новый struct getter `143572e20`.
Получен только недостающий Ghidra export `run-dd1808e3392e`.
Псевдокод сопоставлен с полным unwind-фрагментом и точными RIP references.

## Статическая связь структуры

ScrollBoxSlot.Size descriptor `148ff12b0` имеет struct GenFlags low byte 25.
Его qword +56 указывает на `143572e20`. Этот getter при пустом кеше передаёт
metadata `14b102d08` в `1417d2560`, затем возвращает кеш `14b50cd98`.
Инструкция `143572e30` адресует именно metadata, вызов `143572e3e` ведёт
в указанный helper. Helper / struct constructor в этом исследовании не исполнялись.

В metadata +24 расположен ASCII SlateChildSize (`148fc7500`), +32 указывает
на массив `148fc7150`. В нём проверены два именованных дескриптора в порядке:

| Индекс | Поле | GenFlags low byte | Кандидатное чтение |
| --- | --- | --- | --- |
| 0 | Value | 10 | float32 |
| 1 | SizeRule | 0 | byte |

Новый запрос, явно включающий getter, открывает bounded чтение explicit Size.
Прежний ограниченный запрос без getter продолжает отклонять ненулевой Size.
Значения defaults, enum semantics и алгоритм регистрации не объявлены проверенными.

## Реальный экземпляр и границы

`pakchunk500-Windows-8848.json`, export 281 / ScrollBoxSlot был единственным
отказом нового полного прохода providers. Его 19 байтов:
`00020305010301180100000f01000000000000`.
Полный SHA экспорта: `3f90cdbcdb43f9c3a9514a77d832923d4d1b403f3e4447e0d3f086eab42ea294`.

Чтение даёт Size.SizeRule=1, Parent=280, Content=271 и полный нулевой suffix.
Size.Value отсутствует; он сохраняется в omitted_properties, не получает 1
из старого reader или ноль. Ненулевой explicit Value проверен отдельным
bounded fixture 2.5f; это проверка parser branch, а не native default / runtime.

Исторические cooked / current native совместимость, полное наследование
Parent/Content и применение к геометрии остаются неизвестными. Все проверки offline.

## Охват исходников

`audit-ui-sources.py` теперь поддерживает ui-names / dependencies / all.
На данном snapshot выборки составили 551 / 952 / 1970 ресурсов и
635 / 1186 / 2376 вариантов. Dependency closure сохраняет все альтернативные
версии выбранного ресурса, циклы и unresolved; это class candidates, не bindings.

Для полного каталога сверены 117916 control exports, 72153 decoded slots и
2783 excluded slots. Ошибок SHA / provenance / схемы / прямых class candidates нет.
2195 вариантов прошли все семь source checks; у 181 остаётся дополнительный
кандидатный разбор 964 ранее неучтённых *Slot exports. Эти числа не подтверждают
полноту UObject properties, реализацию окон или runtime поведение.

Четыре виртуальных catalog variants с root 181/182 ссылаются на два физических
пакета RegionSelect. Provenance правильно сохраняет имя физического файла;
проверка теперь разрешает только manifest variant или фактический package.file /
source_file при совпадении полных SHA. Для учёта source slot types / SHA / offsets
переиспользован audit-ui-slot-coverage.py, а не ослаблена проверка.

Все control/slot данные этих четырёх вариантов имеют whole-package scope:
в пакете два WidgetBlueprintGeneratedClass. Source audit, reconciliation и слой
сохраняют оба корня и unknown multiple_blueprint_roots_share_package_scope.
Активный / видимый root не выбирается, данные чужой ветви не выдаются за геометрию.

## Результаты полного конвейера

Все отчёты находятся в `F:/PhoneExit Resources/Vampir/ui-property-scans/`:

| Отчёт | SHA256 |
| --- | --- |
| ui-all-source-audit-02.json | 09bd5af2c1dad0c6fd72fde1e004eaeaab5d0c8bfe5799ba9690d60fbca1cfc6 |
| basic-slot-candidates-all-02.json | 88694894e80ab221a019ee563c9bb8d5e5aad5eeb6fb527296eb0598c83db106 |
| ui-slot-evidence-reconciliation-all-01.json | eb338aed22670d216863db30bf668f053c435fc6642ae3fc27a7486552f8f6bd |
| candidate-layer-verification-all-01.json | 2104065775590c0ac6f48715fefe2874b388c548ff4fa40a6578d44474fb98e1 |

Providers: 472 GridSlot, 432 PanelSlot, 8 ScrollBoxSlot и 8 UniformGridSlot —
920 полных кандидатных чтений; ещё 44 NamedSlot классифицированы как контейнеры
с непрочитанными унаследованными данными. Source aliases учитываются отдельно.

Слой `8ded226119edbc34a5d3bbf45c64e5eb994b5b7405a57584fa6d1f9eaa38c614`:
964 узла, 25 свойств, 3512 наблюдений, 2640 пропусков и 1884 отношения.
Полный verifier заново построил слой по источникам и сравнил каждый файл / индекс.
Все geometry_verified / implementation_verified остаются false.

41 тест охватывает scope selection / cycles / historical siblings, aliases и
slot provenance, bounded декодеры, Size schema gating, отсутствие выдуманного
Value=1, перенос whole-package scope / unknowns, индексы и immutable публикацию.
Базовая матрица, каталоги, runtime prototype и реальные профили не изменены.

Следующее: разделить source Outer-ветви двухкорневых пакетов с проверкой выбранного
класса; подтвердить defaults / archetypes / inheritance и NamedSlot payload перед
применением свойств. Полный имеющийся каталог не объявлен всеми данными клиента.
