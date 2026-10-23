# Инструменты исследования и границы

## Установлено

Ghidra — основной путь для функций и calls. Последний проверенный export
содержит 408 выбранных функций и 186 предупреждений; это не весь EXE.
Capstone / Unicorn применяются для ограниченных проверок после Ghidra.
[Инструкция](../evidence/tools/HEADLESS-GHIDRA.md).

CUE4Parse собран и проверен на заголовках loose assets; четыре исследованных
PAK имеют зашифрованный индекс. Заголовок не означает разбор всех UObject
properties. Dumper-7 DLL собрана, но разрешённая live-попытка остановилась на
отказе EnumProcessModules до загрузки DLL; SDK / mappings не получены.
[Точный результат](../evidence/tools/HEADLESS-DUMPER7-LIVE.md).

## Открыто

Совместимость Dumper-7 с объектами игры, причина отказа доступа и недостающие
ключи / mappings для отдельных способов чтения ресурсов. Наличие подписанного
XIGNCODE3 подтверждено файлами; оно не доказывает причину Login 16.
Не повторять те же попытки без изменения условий.

[Выбор и закреплённые версии](../../ANALYSIS-TOOLS.md).
Дистрибутивы / SDK / exports находятся вне Git. Лёгкий runtime бота не должен
зависеть от Ghidra, Dumper-7, эмулятора native-кода или полной библиотеки assets.

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Vampir: зацепки в собранном коде](../evidence/tools/CODE-CLUES.md)
- [BinExport / BinDiff: сравнение сборок](../evidence/tools/HEADLESS-BINARY-DIFF.md)
- [Dumper-7: первая разрешённая проверка работающего клиента](../evidence/tools/HEADLESS-DUMPER7-LIVE.md)
- [Ghidra: пакетная декомпиляция вместо последовательного чтения инструкций](../evidence/tools/HEADLESS-GHIDRA.md)
- [Импорт только новых экспортов в базу знаний](../evidence/tools/HEADLESS-INCREMENTAL-INDEX.md)
- [Экспорт явных функций без прежнего comparison project](../evidence/tools/HEADLESS-REQUESTED-GHIDRA.md)
