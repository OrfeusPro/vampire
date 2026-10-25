# GridSlot: статическая связь класса с массивом свойств

Текущий SHA256 EXE: d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960.
Продолжение [кандидата декодирования](UI-GRID-SLOT-CANDIDATES-11316.md).
Только offline чтение EXE; helper / игра / процесс не исполнялись.

## Источники и явные roots

Запрос 52880dd4071122c26f8ae29066fbce297040f4dacaea5fb759afeed86ac74a0e
явно включает getter 143579900, metadata getter 14357b7a0 и getter 1435b51e0.
Коллектор переиспользовал готовые функции и выгрузил только недостающие roots.
Экспорты Ghidra:

- run-92f10f431ac2: getter 143579900;
- run-da7c703fc108: 14358e000, 1435b51e0, 1435d6ea0;
- run-d87aa01439fa: metadata getter 14357b7a0.

Общий путь: F:/PhoneExit Resources/Vampir/ghidra/request-exports/
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/.
Псевдокод сопоставлен с полными unwind-фрагментами. inspect-grid-class-links.py
повторно проверяет SHA EXE, явные roots, инструкции / RIP references, литералы,
leaf bytes и метаданные. Не запускает Ghidra или native-код при проверке.

## Статическая цепочка

143579900..1435799ae возвращает кеш 14b50d810. При пустом кеше передаёт
GridSlot (UTF16 148fdb8da), /Script/UMG (148fbc818), адрес кеша и дополнительные
аргументы в 1416ab8d0; затем повторно читает кеш. 0x78 — переданный аргумент,
не доказанный размер live UObject. Helper здесь не исследовался.

14357b7a0..14357b7cf возвращает другой кеш 14b50d818; при пустом кеше передаёт
в 1417d1b20 RCX=&кеш, RDX=148fdbe50. В этом точном блоке метаданных:

- qword +0 = 143579900, тот самый getter с именем GridSlot;
- qword +0x28 = 148fdbbf0, массив девяти дескрипторов предыдущего исследования.

Это подтверждает статическую связь блока / getter / массива. Раскладка остальных
полей блока, порядок обработки helper и результирующий UObject не объявлены
проверенными. Точное содержимое 64 байтов и SHA сохранены в отчёте.

Getter 143579900 передаёт также 14356ab00. Этот leaf не имеет unwind;
его пять байтов e9dba60400 задают переход к 1435b51e0, далее 11 int3 до соседней
границы. Целевой getter содержит PanelSlot (UTF16 148fdd7aa) и /Script/UMG.
Это подтверждает pointer chain к именованному getter. Семантика generic helper
и весь superclass contract / inherited serialization требуют отдельной проверки.

1435d6ea0 вызывает GridSlot getter, передаёт count 9 / таблицу 148ff5980 и
переходит в ранее разобранный 1416b2c10. Это форма регистрации, а не constructor
по одному положению указателя в getter. В 14358e000 наблюдается инициализация
полей после 1417cba90; она не устанавливает самостоятельно доказанные значения
Row / Column / Span и не подтверждает CDO / archetype copy. Defaults остаются
открытыми; имя или форма функции не заменяют полный контракт конструктора.

## Подключение к чтению

У decode-grid-slots.py появился необязательный --class-request. Он вызывает
source-bound inspector и сверяет, что metadata property_array совпадает с
адресом заново извлечённого массива. Сравнение идёт по полному SHA, а не пути:
workflow хранит проверенную копию EXE отдельно от установленного файла.
Отчёт содержит class_links со всеми native фрагментами и границами вывода.

С class-request повторно прочитаны 472 GridSlot, ошибок нет. Старые отчёты не
перезаписаны. Отсутствующие свойства остаются unknown. Исторические cooked
пакеты не объявлены совместимыми с текущим EXE; schema inheritance, Nudge struct,
реальные defaults / desired size / runtime visibility ещё не восстановлены.
Граф и renderer пока не менялись. Внешний вид существующего snapshot прежний.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-grid-class-links.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/52880dd4071122c26f8ae29066fbce297040f4dacaea5fb759afeed86ac74a0e/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/grid-class-links-d00a-next.json'
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-grid-slots.py --class-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/52880dd4071122c26f8ae29066fbce297040f4dacaea5fb759afeed86ac74a0e/manifest.json' --output 'F:/PhoneExit Resources/Vampir/ui-property-scans/grid-slot-candidates-next.json'
```

Отчёт code-clues/grid-class-links-d00a-01.json SHA256: 4543955d57e7146e5cf11e32be4f0fe4d070d0d7ebcbe8635c20da2db6cc5126.
Отчёт ui-property-scans/grid-slot-candidates-02.json SHA256: 6c19285248436c5adf271abe6fab554b920b24ede37b74ac9f40ba97ddb61340.

Следующая проверка: primary construction / CDO initialization и PanelSlot fields,
затем восстановление пропущенных значений с явным происхождением. Полноту
ButtonSlot / NkButton и активную совместимость проверять отдельно.
