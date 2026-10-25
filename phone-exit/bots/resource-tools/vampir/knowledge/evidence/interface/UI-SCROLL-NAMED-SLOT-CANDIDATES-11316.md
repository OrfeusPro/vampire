# ScrollBoxSlot и NamedSlot: оставшиеся кандидаты

Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Запрос `a12cde3da6223ce22e33816c2268f32fc966b1ad7cc86eb143e8e572ef71c2f4`
включает getters PanelSlot / UniformGridSlot прежнего прохода и новые
NamedSlot `143579140`, ScrollBoxSlot `143583190`, ContentWidget `1435b5080`.
Новые Ghidra exports: `run-bbd91461ab67` и `run-f1db1bcac3c5`.
Псевдокод сверен с полными unwind-фрагментами и RIP references текущего файла.
Все проверки offline, игра и generic registration helper не исполнялись.

## ScrollBoxSlot

Getter `143583190` адресует UTF16 ScrollBoxSlot (`148ff1292`) и /Script/UMG.
В metadata `148ff14e0`: qword +0 → этот getter; qword +0x28 → `148ff13f8`.
Именно этот массив содержит четыре собственных свойства:

| Индекс | Имя | GenFlags low byte |
| --- | --- | --- |
| 0 | Size | 25 |
| 1 | Padding | 25 |
| 2 | HorizontalAlignment | 0 |
| 3 | VerticalAlignment | 0 |

Поиск трёх последних имён давал 12 массивов, поэтому сопоставление по одному
набору имён было недостаточно. Новый decoder проверяет весь именованный массив
по точной class metadata, а не выбирает первое совпадение.

Все четыре экземпляра из source audit прочитаны полностью. Parent / Content
на индексах 4/5 остаются наблюдаемыми кандидатами наследования, сверенными
с exports; Parent во всех четырёх имеет тип ScrollBox. Нулевой suffix и конец
тела обязательны. Padding читается существующим порядком margin-компонентов,
пропущенные вложенные поля сохраняются отдельно. Например export 24 из
pakchunk500-Windows-289 имеет явный Padding.Right=20, Parent=23, Content=20;
Size / оба alignment и остальные margin-компоненты отсутствуют.

Ненулевой explicit Size пока отклоняется: его внутренняя struct schema этим
исследованием не подтверждена. Serialized zero сохраняется маркером без defaults.
Нечисловые margin, truncation, лишние байты и неправильный Parent отклоняются.
Это кандидатное чтение исторических пакетов, а не подтверждение совместимости
их property ordinal с текущим EXE или native геометрии.

## NamedSlot

Getter `143579140` адресует UTF16 NamedSlot (`148fd552a`) и /Script/UMG.
В metadata `148fd58e0`: qword +0 → getter, qword +0x28 = 0. В этой форме
metadata собственного массива свойств нет. Getter передаёт pointer
`14356aad0`; пять байтов `e9aba50400` ведут к `1435b5080`, адресующему
ContentWidget (`148fdfa02`). Это статическая цепочка кандидата родителя,
не исполнение generic registration или доказательство полного superclass contract.

У всех 11 exports NamedSlot outer имеет тип WidgetTree. Они классифицированы
как **container_class_candidate**. Сырые bytes, SHA и outer сохранены;
`decoded=null`, `inherited_properties_decoded=false`. Payload экземпляров
не интерпретирован и не превращён в Parent / Content layout slot по суффиксу.
Нужны отдельная проверка наследования, схемы и связей с PanelSlot.

## Автоматический результат

Расширен `decode-basic-slot-candidates.py`: 140 записей, из них 129 кандидатных
разборов (117 PanelSlot, 8 UniformGridSlot, 4 ScrollBoxSlot) и 11 классификаций
NamedSlot без чтения унаследованных полей; ошибок нет.

Отчёт `F:/PhoneExit Resources/Vampir/ui-property-scans/basic-slot-candidates-03.json`,
SHA256 `dbcca8c9050f7c1be948f88d7501d2898187c70d61458bdef2fb39f4cb2c030e`.

Общий reconciliation с 300 GridSlot:
`F:/PhoneExit Resources/Vampir/ui-property-scans/ui-slot-evidence-reconciliation-06.json`,
SHA256 `4b34d21ddb16188a4203f4d21ba353f7ebf9619883594704674634daad80663d`.
Все 440 кандидатов имеют provider: 429 `candidate_evidence_reproduced`,
11 `container_candidate_classified`. Вторая отметка подтверждает только
классификацию; `candidate_parse_complete=false`. Во всех 440 случаях
`geometry_verified=false` и `implementation_verified=false`.

23 теста декодеров / переноса / source audit прошли; проверены raw fixtures
ScrollBoxSlot, сохранение omissions, отказ explicit Size / nonfinite margin,
проверка ScrollBox Parent и непрочитанный payload NamedSlot. Прежние проверки
GridSlot / PanelSlot / UniformGridSlot также прошли. Native class links проверены
отдельным запуском скрипта на полном SHA текущего EXE.

## Повтор

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-basic-slot-candidates.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/a12cde3da6223ce22e33816c2268f32fc966b1ad7cc86eb143e8e572ef71c2f4/manifest.json' --audit 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-auto-source-audit-04.json' --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/basic-slot-candidates-next.json'
python -X utf8 -m unittest phone-exit/bots/test_vampir_basic_slot_candidates.py phone-exit/bots/test_vampir_ui_slot_evidence.py phone-exit/bots/test_vampir_grid_slots.py phone-exit/bots/test_vampir_ui_source_audit.py
```

Прежние отчёты, source audit и snapshot сохранены. Следующий шаг — связать
кандидатные данные со сканером в отдельном слое, сохраняя unknowns; подтвердить
NamedSlot inherited fields, явный Size, superclass/defaults и совместимость до
применения к renderer. Полнота данного остатка не означает полноту UObject
properties или восстановление внешнего вида всех окон.
