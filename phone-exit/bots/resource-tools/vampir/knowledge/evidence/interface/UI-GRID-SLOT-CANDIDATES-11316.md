# GridSlot: дескрипторы и ограниченное чтение кандидатов

Текущий EXE SHA256: d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960.
Запрос: 49c73274f673bee1940c18632cdd52eb3f0c94b07e9a4cdf4a3d96ce4323e703.
Явный адрес 0x148fdbbf0 — данные массива дескрипторов, не функция.
Ghidra collect для этого data address не запускался.

Повторно использован extract-ui-properties.py: поиск имени RowSpan →
выравненные указатели на дескриптор → массив указателей, затем проверка всего
порядка имён / low-byte GenFlags. Получен единственный полный массив:

| Индекс | Имя | GenFlags low byte |
|---|---|---|
| 0 | Padding | 25 |
| 1 | HorizontalAlignment | 0 |
| 2 | VerticalAlignment | 0 |
| 3 | Row | 3 |
| 4 | RowSpan | 3 |
| 5 | Column | 3 |
| 6 | ColumnSpan | 3 |
| 7 | Layer | 3 |
| 8 | Nudge | 25 |

Имена, типы и порядок массива подтверждены байтами текущего EXE. Независимая
связь UGridSlot registration metadata → этот массив ещё не установлена.
Parent / Content на индексах 9 / 10 — observed-кандидат superclass: ссылки
сопоставлены с реальными экспортами, Parent должен быть GridPanel.
Это не доказательство всего inheritance / класса / активной совместимости.

Новый decode-grid-slots.py применяет header reader прежнего декодера, читает
margin / byte alignments / signed int fields / double-vector Nudge, требует
полного покрытия тела и нулевого UObject suffix. Пропущенные поля перечислены
отдельно и не получают defaults. Native schema несовпадение / другой SHA EXE
останавливают запуск. Сырые uasset / uexp проверены по полным SHA каталогов;
исторические пакеты не объявлены совместимыми с текущим EXE.

По уникальным source_file каталога прочитаны 472 GridSlot, ошибок разбора нет.
В меню pakchunk500-Windows-1707.json — 39. Например:

- export 180 / CanvasPanelCharacter: Row и Column отсутствуют; оба Span явно 1.
- export 183 / CanvasPanelFollower: Row 4, Column 1, оба Span явно 1.
- export 207 / CanvasPanelArena: Row 7, Column 4; оба Span отсутствуют.
- export 210 / CanvasPanelMatrix: Row 3, Column 5; не временная третья колонка демо.
- export 213 / CanvasPanelEngraving: Row 3, Column 1.

Все числа — кандидаты интерпретации исторического экземпляра с указанными
границами, не геометрия live Slate. Разбор не меняет ui-catalog / граф / renderer
и опубликованный snapshot. Значения по умолчанию, nudge struct association,
родительский GridPanel, fill rules, desired sizes, runtime visibility и порядок
children ещё не подтверждены. Нельзя сжать строки с пробелами только по кадру.

Команда:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-grid-slots.py --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/grid-slot-candidates-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_grid_slots.py
```

Три теста прошли: absent Row/Column сохраняются unknown; explicit Row/Column не
создают Span defaults; truncation / extra bytes / ненулевой suffix отклоняются.
Fixtures основаны на сохранённых байтах exports 180 и 207 меню; тесты ветвей
декодера не доказывают native класс или актуальную совместимость.

Отчёт: F:/PhoneExit Resources/Vampir/ui-property-scans/grid-slot-candidates-01.json.
SHA256: 3690b1087f995af8477d1d51135ae742922ea167b182a2066997ca4954670768.

Следующая проверка: metadata registration UGridSlot / superclass PanelSlot,
структура Nudge и constructor defaults; затем повторный импорт с provenance
и применение к grid renderer. Не снимать ButtonSlot parent-type guard без
отдельного подтверждения NkButton inheritance.
