# Stat values: текущая запись и применение

Source EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это ограниченное исследование кода собранного клиента 1.13.16.

`replay-stat-values-11316.py` исполняет текущие инструкции reader `1457a8030`
и apply `145d8b830` из двух закреплённых Ghidra exports. SHA файлов закреплены
в `knowledge/native-contexts/stat-values-exports-11316.json`.

130 native-сценариев: шесть 20-байтных записей с каждым коротким префиксом
0–19 байт и полной длиной; четыре массива применения, включая пустой массив
и повторный тип. Проверены ноль, отрицательные и крайние signed int64 значения.
Reader читает int32 в native offset `+8`, затем два 64-битных поля `+10` / `+18`.
Apply для проверенных типов 3 / 4 / 5 / 9 / 10 передаёт в setter `1455f10f0`
тип и **второе** значение (`+18`), сохраняя порядок массива. Первое значение
не применяется этим путём. Общие имена «старое значение» / «дельта» ему не присвоены.

Archive scalar IO и setter модели — явные fixtures. Полный внешний ID 322,
array framing / allocation, регистрация, entity lookup и UI units этим replay
не проверены. Отдельная ветвь type 134 с масштабированием исключена из набора.
Runtime HP/MP после этого теста автоматически не включается.

Отчёт:
`F:/PhoneExit Resources/Vampir/code-clues/stat-values-11316/c4193c7f2822d652ba650cd6e353ded8fd0c4de288d708ca931b17d69cfa0537/manifest.json`.
Полный SHA256 равен имени каталога. `test_vampir_stat_values_11316.py` — offline
проверка без сетевого доступа, авторизации и чтения приватных captures.

Статическая цепочка текущего SHA:

- `14679cce0`: lookup по `packet+10`, передача `packet+18` в `145d8b830`.
- `145d8b830`: обход stride 32 и передача type / второго значения в `1455f10f0`.
- `1455f10f0`: slot `+70`, проверки полученного объекта / счётчиков, вызов `1455f0130`.

Exports: `run-7c95e2163ff6`, `run-71c48dcf365c`, `run-6458edef35c9` под текущим
SHA в `ghidra/request-exports/`. Эти три функции не исполнялись общей цепочкой.
Следом — `1455f0130`, полный внешний reader, источник начальных stats и units UI.

Существующий `extract-native-enums.py` отдельно прочитал текущие descriptor pairs
без замены исторического `code-clues/native-enums.json`. Текущий EStat:
Level=3, Hp=4, MaxHp=5, Mp=9, MaxMp=10.
Immutable отчёт:
`code-clues/release-stat-enums/6e78d5ed9523d64e3e771da24da6b9fd2f95fd78c8d308076717918d369d205a/manifest.json`
в библиотеке ресурсов. Descriptor names / values сами по себе не доказывают
единицы отображения и полный сетевой контракт.
