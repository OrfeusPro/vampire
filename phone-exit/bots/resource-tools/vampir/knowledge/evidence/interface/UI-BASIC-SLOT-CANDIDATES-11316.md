# PanelSlot и UniformGridSlot: схема и кандидатный разбор

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Запрос `369c0f32d6f56b02f59a444a90c0129adac11ffd2c74a3112a642d8d358e4903`:
явные getters `1435b51e0` и `14357f1d0`. Для второго получен только недостающий
Ghidra export `run-1986df0b8b91`; первый переиспользован из `run-da7c703fc108`.
Псевдокод сверен с полными unwind-фрагментами и RIP references текущего EXE.

## Статические связи

`decode-basic-slot-candidates.py` использует существующий extractor массивов
именованных property descriptors. По полному порядку имён и low-byte GenFlags
каждый из следующих массивов найден однозначно:

| Класс | Массив | Порядок собственных свойств | Flags |
| --- | --- | --- | --- |
| PanelSlot | 148fdd840 | Parent, Content | 82, 82 |
| UniformGridSlot | 148fe5080 | HorizontalAlignment, VerticalAlignment, Row, Column | 0, 0, 3, 3 |

В блоке `148fddad0`: qword +0 → `14356ab00`; qword +0x28 → `148fdd840`.
Пять байтов thunk `e9dba60400` ведут в `1435b51e0`, который адресует UTF16
`PanelSlot` (`148fdd7aa`) и `/Script/UMG` (`148fbc818`).

В блоке `148fe51a0`: qword +0 → `14357f1d0`; qword +0x28 → `148fe5080`.
Этот getter адресует UTF16 `UniformGridSlot` (`148fe4f6a`) и `/Script/UMG`.
Generic registration helper не исполнялся. Остальные поля блоков и полный
superclass contract здесь не объявляются проверенными.

## Чтение экземпляров

Для PanelSlot индексы 0/1 читаются как явные local object links Parent/Content.
Для UniformGridSlot первые четыре индекса соответствуют собственному массиву;
Parent/Content на индексах 4/5 — наблюдаемые кандидаты наследования. Обязательны
полное покрытие тела, нулевой UObject suffix, локальные exports и родитель
UniformGridPanel для UniformGridSlot. Пропущенные свойства остаются неизвестными.

Выборка взята из source audit всех имён с UI: 117 PanelSlot и 8 UniformGridSlot,
все 125 приняты, ошибок нет. У PanelSlot Parent имеет тип NkCheckBox (102),
InvalidationBox (9), NamedSlot (4), RetainerBox (2). Это реальные ссылки exports,
а не доказательство runtime расположения или алгоритма контейнера.

Все каталоги / UAsset / UExp / exports сверены по SHA и с immutable snapshot.
Исторические cooked пакеты не объявлены совместимыми с текущим native EXE.
Default Row/Column, alignment omissions, desired size и видимость не применяются.
Импорт схем, renderer и исходный каталог не изменены.

Отчёт: `F:/PhoneExit Resources/Vampir/ui-property-scans/basic-slot-candidates-02.json`.
SHA256: `68648f2c2436c7af9b30d8feac97aa057897c31f79708fefa978150f202280a1`.

Общий reconciliation с прежними 300 GridSlot повторно проверил 425 из 440
кандидатов; 15 остаются без providers: NamedSlot 11 и ScrollBoxSlot 4.
Отчёт `ui-property-scans/ui-slot-evidence-reconciliation-05.json`, SHA256
`230e7405fcc83025532aa3cf228f5d40334f8488f224961da05f19eab29458ab`.
Автоматический успех относится к воспроизводимости кандидатного разбора;
`geometry_verified` и `implementation_verified` сохраняются false.

## Повтор и следующие проверки

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-basic-slot-candidates.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/369c0f32d6f56b02f59a444a90c0129adac11ffd2c74a3112a642d8d358e4903/manifest.json' --audit 'F:/PhoneExit Resources/Vampir/ui-property-scans/ui-auto-source-audit-04.json' --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/basic-slot-candidates-next.json'
python -X utf8 -m unittest phone-exit/bots/test_vampir_basic_slot_candidates.py phone-exit/bots/test_vampir_ui_slot_evidence.py phone-exit/bots/test_vampir_grid_slots.py
```

14 тестов: четыре новых bounded byte fixtures, семь проверок переноса evidence
и три прежних GridSlot. Неверный класс / parent / SHA / suffix / truncation
отклоняются; пропущенные Row / Column не получают defaults.

Следующий шаг: NamedSlot как виджет отделить от layout slot по подтверждённому
классу / сериализации. Для ScrollBoxSlot набор Padding / HorizontalAlignment /
VerticalAlignment найден в 12 массивах: сначала установить getter / metadata /
конкретный массив, затем добавить provider. После этого проверить наследование,
defaults и применение к импорту / геометрии всех потребителей.
