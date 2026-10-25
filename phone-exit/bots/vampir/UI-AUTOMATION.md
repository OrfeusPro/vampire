# Автоматизация разбора и сборки интерфейса

Повторяемый разбор переносится в скрипты: извлечение → проверка источников →
свойства / связи → применение подтверждённых правил → сборка → проверки.
Ручной разбор нужен для конкретных неизвестных; его подтверждённый результат
становится общим правилом и проверкой для всех подходящих потребителей.

Текущий проход охватывает **1970 записей / 2376 вариантов всего имеющегося каталога**.
Получены 920 кандидатных разборов и 44 классификации NamedSlot с непрочитанным
payload; все 964 кандидата имеют provider. Это не готовность геометрии и не
полнота всех свойств клиента. Прежние результаты выборки 551 UI имён ниже
сохранены со своими SHA; текущие отчёты — ui-all-source-audit-02.json,
basic-slot-candidates-all-02.json, ui-slot-evidence-reconciliation-all-01.json;
слой — 8ded2261… .

Подтверждённые проверки закрываются автоматически в машинном отчёте. Проверка
привязана к полным SHA источников, версии инструмента и своим критериям. Например,
совпадение export SHA закрывает проверку байтов экспорта; оно не закрывает проверку
его поведения. Целое окно можно автоматически объявить готовым после прохождения
всех обязательных критериев UI-W .01–.06. Неизвестное не подменяется успехом.
Ручное подтверждение уже доказанной логики при каждом запуске не требуется.

## Уже автоматизировано

- `inventory-ui-names.py`: точный отбор заглавных UI в имени, постоянные UI-W ID,
  сохранение вариантов и unresolved; сверка manifest / registry / каталогов.
- `scan-ui-properties.py` и `verify-ui-property-scan.py`: вложенный каталог
  свойств, прямые / обратные индексы и сверка переноса извлечённых данных.
- `scan-ui-candidate-layer.py`: дополнительный слой source-bound кандидатных
  данных поверх матрицы, наблюдения / пропуски, parent / content / outer и
  обратные индексы. Входы повторно проверяются; готовая матрица переиспользуется
  без изменения базового набора, Native defaults или renderer.
- `ui_composition_graph.py`: кандидаты дочерних классов и обратное влияние
  изменений; активный вариант из совпадения имени не выбирается.
- `audit-ui-sources.py`: пакетная сверка исходных UAsset / UExp, exports,
  происхождения слотов, опубликованной структуры, повторного построения локальной
  схемы и прямых class candidates. Для каждого варианта — отдельные `checks`,
  автоматический результат и список `unknowns`. Ошибка одного варианта не скрывает
  остальные; код выхода 1 требует проверить отчёт.
- `build-ui-prototype.py`, verifier и тесты: воспроизводимая сборка, проверки
  поддержанных правил / модели. Закрытая фаза аудита продолжает действовать;
  проверочная пересборка не означает готовность всех окон.

## Пакетный запуск по всей выборке UI

Из корня репозитория, с явным существующим snapshot и новым именем результата:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-ui-sources.py --snapshot 'F:/PhoneExit Resources/Vampir/maps/ui-prototype/snapshots/4ceec6f214cbe9d28e35d1a05d5a3c4731d45296e15336575075202793d0cde9' --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-auto-source-audit-next.json'
```

Для ограниченного прохода добавить `--family Achievement --family Archive`.
По умолчанию scope ui-names: 551 запись / 635 вариантов, включая unresolved.
`--scope dependencies` расширяет seed-выборку по class candidates, сохраняя все
версии и циклы (952 ресурса / 1186 вариантов). `--scope all` проверяет весь
каталог: 1970 записей / 2376 вариантов. В dependencies family ограничивает только
seeds, в all — полный путь ресурса; unresolved без установленной family не угадываются.
Предыдущий отчёт, snapshot и Markdown статусы окон не перезаписываются. Скрипт
не запускает игру и не отправляет команды. Он работает при подготовке общего
набора, а не отдельно в каждом из 50 окон ботов.

## Проверенный результат

Отчёт `F:/PhoneExit Resources/Vampir/ui-property-scans/ui-auto-source-audit-04.json`,
SHA256 `5e76cdc35f97d4c2647ffa85e264dc48b0ae8b06737bb0538e3eee021d7c4ab4`.
Обработаны все 635 вариантов: исходные hashes / exports / происхождение учтённых
слотов / перенос каталога / локальные схемы / class candidates совпали. Семь
автоматических проверок полностью прошли для 583 вариантов. У остальных 52
открыта проверка учёта всех slot candidates: 440 exports не вошли в slots или
excluded_slots прежнего каталога. Поэтому запуск вернул 1, сохранив полный отчёт.

Состав остатка: GridSlot 300, PanelSlot 117, NamedSlot 11, UniformGridSlot 8,
ScrollBoxSlot 4. Суффикс Slot является кандидатом, а не доказательством роли:
NamedSlot может быть виджетом. Эти записи нужно классифицировать по schema /
наследованию. Для GridSlot использовать уже полученные [проверки инициализации](../resource-tools/vampir/knowledge/evidence/interface/UI-GRID-INITIALIZATION-REPLAY-11316.md)
и оставшиеся UI-25 задачи, не начинать исследование заново и не угадывать defaults.

Итого: 40562 записи controls, 23700 разобранных и 1245 исключённых слотов.
У 333 вариантов неоднозначные дочерние варианты, у 246 отсутствуют дочерние
классы, у 9 есть issues локальной схемы. Это отдельные открытые критерии;
успешная сверка структуры не скрывает их. Наличие styles / событий в самом
клиенте по отсутствию поля в прежнем декодере не отрицается.

Тесты проверяют отказ на изменённых байтах, неверной provenance / зависимости,
устаревшей схеме и неучтённом slot; успешный результат сохраняет неизвестные
bindings и `implementation_verified=false`. Ограниченный автоматический проход
Achievement / Archive воспроизвёл [результат двух независимых заданий](UI-FAMILY-SOURCE-AUDIT.md).

## Дальше автоматизировать

### Повторное использование разбора GridSlot

`reconcile-ui-slot-evidence.py` связывает остаток source audit с готовым
`grid-slot-candidates-02.json` по полным SHA пакетов и конкретным exports.
Перед применением проверяются полный SHA текущего EXE, fingerprints прежних
декодеров, manifest / каталожный index / ID окон и ссылки на варианты snapshot.
Для каждого GridSlot повторно читаются actual bytes и explicit properties;
Parent / Content сверяются с исходными exports. Прежний native поиск не повторяется.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/reconcile-ui-slot-evidence.py --audit 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-auto-source-audit-04.json' --grid-evidence 'F:/PhoneExit Resources/Vampir/ui-property-scans/grid-slot-candidates-02.json' --grid-evidence-sha256 6c19285248436c5adf271abe6fab554b920b24ede37b74ac9f40ba97ddb61340 --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-slot-evidence-reconciliation-next.json'
```

Получены 300 `candidate_evidence_reproduced` и 140 `no_reviewed_provider`:
PanelSlot 117, NamedSlot 11, UniformGridSlot 8, ScrollBoxSlot 4.
Первое автоматически закрывает проверку воспроизводимости **кандидатного**
разбора, сохраняя `geometry_verified=false` и `implementation_verified=false`.
Наследование, defaults и совместимость остаются открытыми. Старый source audit
и его 52 неполных варианта не переписываются. Код выхода 0 здесь означает
успешную сверку отчётов без source mismatch, а не отсутствие unknowns.

Проверены 5 тестов переноса evidence и 3 прежних теста GridSlot: чужой package /
тип / parent / результат, неполные fingerprints и дубли отклоняются;
пропущенные Span сохраняются неизвестными. Отчёт:
`F:/PhoneExit Resources/Vampir/ui-property-scans/ui-slot-evidence-reconciliation-04.json`,
SHA256 `cb4c309a9ab143bac2e575817d11aa8b04f9edd74a786ec8acc5120707813adc`.
Его SHA не переносится на будущие запуски.

### PanelSlot и UniformGridSlot

Добавлены `decode-basic-slot-candidates.py` и дополнительный provider общего
reconciliation. [Статическое доказательство](../resource-tools/vampir/knowledge/evidence/interface/UI-BASIC-SLOT-CANDIDATES-11316.md)
связывает именованные getters текущего SHA с metadata / массивами собственных
свойств. Скрипт повторно проверяет эти связи, полные SHA исторических экземпляров,
explicit values и object links. Наследование UniformGridSlot, defaults и совместимость
остаются отдельными критериями; генерация геометрии не включена.

Разобраны 117 PanelSlot и 8 UniformGridSlot без ошибок. Четыре теста нового
декодера и семь тестов переноса evidence с тремя прежними GridSlot прошли.
Отчёт `ui-property-scans/basic-slot-candidates-02.json`, SHA256
`68648f2c2436c7af9b30d8feac97aa057897c31f79708fefa978150f202280a1`.

Для повторного reconciliation добавить к команде выше:

```powershell
--basic-evidence 'F:/PhoneExit Resources/Vampir/ui-property-scans/basic-slot-candidates-02.json' --basic-evidence-sha256 68648f2c2436c7af9b30d8feac97aa057897c31f79708fefa978150f202280a1
```

Указать новый `--output`. Результат с двумя providers:
`ui-property-scans/ui-slot-evidence-reconciliation-05.json`, SHA256
`230e7405fcc83025532aa3cf228f5d40334f8488f224961da05f19eab29458ab`.
В этом наборе воспроизводились **425 / 440** кандидатных интерпретаций; оставалось
15 без provider: NamedSlot 11 и ScrollBoxSlot 4. Это дополняет старый отчёт,
а не переписывает его и не закрывает проверку внешнего вида.

### Остаток ScrollBoxSlot / NamedSlot

Новый [проход по исходникам](../resource-tools/vampir/knowledge/evidence/interface/UI-SCROLL-NAMED-SLOT-CANDIDATES-11316.md)
установил точный четырёхэлементный массив ScrollBoxSlot через его class metadata.
Четыре тела полностью разобраны как кандидаты, включая явный Padding и object
links; отсутствующие значения сохраняются неизвестными. Ненулевой explicit Size
в том проходе отклонялся до подтверждения inner schema; теперь он доступен запросу
с проверенным SlateChildSize getter, см. полный проход ниже.

NamedSlot имеет отдельный именованный getter, metadata с нулевым собственным
массивом и переданный thunk к getter ContentWidget. Все 11 exports находятся
в WidgetTree. Provider подтверждает только классификацию контейнера: сохраняет
сырые bytes, `decoded=null`, `candidate_parse_complete=false` и
`inherited_properties_decoded=false`. Поля экземпляров ещё нужно разобрать.

Результаты вне Git:

- `ui-property-scans/basic-slot-candidates-04.json`, SHA256
  `5296b4ffac632dbde60134b11e956dbaabf75a9e082e815ac348a87ff78f420f`.
- `ui-property-scans/ui-slot-evidence-reconciliation-07.json`, SHA256
  `5078276570f13d9adaaa0eb06f073690803d63d2f4e8a1efe33e6374521f70eb`.

Для reconciliation использовать basic-04 и его SHA с новым output; grid evidence
остаётся прежним. Метаданные новых классов воспроизводятся скриптом, неверные SHA /
Parent / outer / opaque payload отклоняются. Прошли 23 теста. Следующий шаг —
отдельный кандидатный слой сканера и открытые проверки наследования / defaults,
которые не закрываются отсутствием `no_reviewed_provider`.
Скрипт сохраняет ограниченный проход по явным roots запроса: прежний запрос
PanelSlot / UniformGridSlot отдельно повторно дал 125 записей без ошибок
(`basic-slot-candidates-subset-01.json`). Новый класс не расширяет старое задание
скрытно; неподтверждённые или отсутствующие зависимые roots отклоняются.

### Подключение к матрице свойств

Построен и повторно проверен [отдельный слой сканера](UI-PROPERTY-SCANNER.md#дополнительный-слой-кандидатных-свойств):
440 узлов, 25 свойств, 2077 наблюдений и 1529 пропусков, 869 прямых / обратных
отношений. Идентификаторы не зависят от значения или позиции массива.
Поля с нулём наблюдений сохранены неизвестными; compound values не раскладываются
на якобы подтверждённые числовые поля. Есть [отдельный чеклист свойств](UI-CANDIDATE-PROPERTY-TASKS.md).
7 тестов нового слоя и 23 прежних теста декодеров / source audit прошли.
Verifier повторно сверил всю базовую матрицу и кандидатные источники.
Это подготовка общих данных; каждый бот не запускает сканер и не читает EXE.

### Полный имеющийся каталог

Расширен [конвейер всех вариантов и зависимостей](../resource-tools/vampir/knowledge/evidence/interface/UI-FULL-CATALOG-SIZE-11316.md).
Scope all проверил 1970 записей / 2376 вариантов без ошибок source SHA /
provenance / local schema. Из них у 181 варианта в старом каталоге не учтены
964 suffix candidates. Providers повторно проверили 920 кандидатных разборов
и 44 классификации NamedSlot. Это дополняет прежние результаты, не переименовывает
исторические отчёты и не выбирает активную версию ресурса.

Проверена структура SlateChildSize: запрос с getter 143572e20 допускает explicit
Size, прежний запрос без getter отклоняет его. В единственном новом случае Value
пропущен; значение 1 не подставляется. Whole-package scope двухкорневых пакетов
и список обоих корней перенесены в узлы, чтобы не выдавать смешанный пакет за
геометрию одного окна.

Текущий слой `8ded226119edbc34a5d3bbf45c64e5eb994b5b7405a57584fa6d1f9eaa38c614`
прошёл полный verifier: 964 узла / 25 свойств / 3512 наблюдений / 2640 пропусков /
1884 отношения. Все 25 ID свойств сохранены; чекбоксы остаются открытыми.
41 тест прошёл. Полные SHA отчётов и команды — в доказательствах и README сканера.

### Исходные Outer-ветви

Добавлен [автоматический проход исходных корней](UI-OUTER-SCOPES.md): 2374 пакета,
200125 exports, 2376 вариантов. Двухкорневые RegionSelect / TitleRegionSelect
разделены по точным Outer цепочкам. Из выбранных схем изолированы 188 foreign
controls / 168 decoded slots / 8 excluded slots; unowned объект Enchant сохранён
в quarantine. Для каждого варианта сформирована отдельная source-scoped схема.
Полный verifier и 48 тестов прошли. Runtime root не выбирается и геометрия
не подтверждается этой классификацией.

Очередь с чекбоксами — UI-27 в [общем плане](UI-TASKS.md). Следующие блоки:
учёт оставшихся slot types / defaults, декодирование Brush / styles / состояний,
подтверждённые delegates / handlers, применение правил геометрии, тестовые сценарии
окон и сравнение после обновлений. Уже подтверждённое применять автоматически;
остаток выводить с источником, причиной и недостающей проверкой.
