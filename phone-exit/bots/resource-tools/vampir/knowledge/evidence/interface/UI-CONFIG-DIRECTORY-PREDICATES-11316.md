# Флаги выбора каталога и cached installed predicate

25 октября 2026. Продолжение [directory gate](UI-CONFIG-DIRECTORY-SOURCES-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline replay; настоящая командная строка, файлы и OS security state не читались.

## Источники и границы

Первое задание d54409a55ca65f93c8644902d59165ebaaadaab5bc31f3a11865fc276aabca89
включало 141403ab0 без unwind root. Collect отклонил набор до экспорта;
тот же запрос повторно не запускался. Leaf остаётся неизвестным.
Новое explicit задание
`80c71bb346da715d37afe0eed0d57239da7f80201a658f220a0b1af4b5783e18`
содержит 141533f40 / 141584470 / 1415d7dd0 и готовый compare 14145f4a0.
Collect завершён с пустой очередью; compare использован повторно.
`ghidra/request-exports/<полный SHA EXE>/run-595a84929f72/details.json`, SHA256
`ff9adcec049fe7e4e71985300ed7edcf28693b393af39ec1a285fca606677a00`.
Все три тела сверены с инструкциями. Compare источник —
[предыдущий core replay](UI-CONFIG-PARSER-CORE-11316.md).

## Native flag search 141584470

Тело 141584470…141584603 ищет ключ без параметра значения. Это другой контракт,
чем core parser 14158f1a0 для UserDir= / -saveddirsuffix=.
Для исследованных ASCII ключей совпадение должно иметь отдельный `-` или `/`
перед ключом, перед префиксом — начало input либо whitespace. После ключа —
NUL либо whitespace. Key внутри двойных кавычек пропускается.
Сам input должен быть ненулевым указателем: dereference предшествует null guard.

Используются настоящий compare 14145f4a0 и его file-backed ASCII table.
iswspace по IAT 14899c1f8 подтверждён через PE imports; это fixture с ASCII
whitespace и отдельным synthetic Ж → 0. Остальные не-ASCII ответы CRT /
locale поведение не доказаны. Все восемь nonvolatile GPR и полный возврат проверены.

120 случаев: три точных ключа SaveToUserDir / ExpectLowIntegrityLevel /
ExpectMediumIntegrityLevel, 20 форм input, два варианта ASCII регистра ключа.
Независимый oracle проверяет prefix / boundaries / quoted regions; NUL завершает
input. Bare SaveToUserDir, --SaveToUserDir и -SaveToUserDir=1 дают false,
-SaveToUserDir и /SaveToUserDir дают true в проверенных строках.
Пустые / null keys, null input, escape conventions и универсальный Unicode
не входят в этот контракт.

## Выбор GUID 1415d7dd0

Целое тело 1415d7dd0…1415d7e74 использует guard 14b340544 и byte cache 14b340540.
После header с guard=-1 вызывает PE import GetCommandLineW по IAT 14899a568.
Сначала ищется ExpectLowIntegrityLevel: true сохраняет 1. Иначе повторяется
GetCommandLineW и ищется ExpectMediumIntegrityLevel; здесь обе ветви сохраняют 0.
Это подтверждено инструкциями, включая начальное BL=0 / cmovne, а не только
упрощённым псевдокодом. В обоих случаях вызывается footer, затем читается cache.

20 initialization cases: десять command-line fixtures / два TLS index; при low
флаге один native flag вызов, иначе два. Оба флага вместе дают 1 по первому.
Ещё восемь cached cases: bytes 0 / 1 / 2 / 255 и два TLS index; raw cache возвращается
без нормализации. Guard / GetCommandLineW — fixtures. Никакой фактический уровень
целостности процесса не измерялся и не выводится из имени флага.

## Installed predicate 141533f40

Native cached branch проверен для cache dword 14b0c0900 = -2 / 0 / 1 / 2 / 255:
AL=1 только при значении 1. Пять случаев не вызывают helpers.
При cache=-1 ветвь только статически проверена и replay явно запрещает её исполнение.
Она получает строку от 141586fe0, добавляет точный literal
Engine/Build/InstalledProjectBuild.txt (38 units), вызывает 141584080, затем
объект 141466840 и slot vtable+0x48 с полученным путём. Значение этого вызова
выбирает NotInstalled с инверсией либо Installed через native flag search.
Прочие initialization helpers, vtable target / семантика, путь и значение
runtime global 14b2c4cb0 остаются неизвестными. Не заявляем проверку наличия файла
по одному месту косвенного вызова.

## Общая цепочка gate

Вторая explicit зависимость — прежнее задание
4f1aa73e805e475f5dc50f615c5836052af75de47f41caa16a352c0ad4ef4bee
для gate 141589b30. 64 сценария исполняют gate → cached installed predicate →
native flag search → native compare на общей памяти без готового результата
флага. Восемь command-line fixtures, cache installed 0 / 1, environment fixture
0 / 2, override count 0 / 2. При installed=1 flag не вызывается, иначе ровно один
раз; итог gate совпал с независимым oracle.
Command-line getter 14152d5c0, environment leaf 141403ab0, override getter
141578190 и guard machinery остаются fixtures. Count=2 с null data — branch
probe, не валидный FString. Whole override / fallback ещё не проверены.

## Повтор

`replay-ui-config-directory-predicates.py`, Unicorn 2.1.4 / Capstone 5.0.6.
Проверяются полный SHA EXE, unwind roots, literals, ASCII table, imports и границы
исполнения. Отчёт `code-clues/ui-config-directory-predicates-d00a-02.json`, SHA256
`b00b893ab0456a80f9b5bef5c8250dac628e9ff9e1134e4512d173d4b4d5ba62`.
Реальные path / config precedence / активные настройки и UI не подтверждены.
Далее — cold installed branch, безопасные границы environment leaf, CRT locale,
whole override / fallback и нормализация результата системной директории.
