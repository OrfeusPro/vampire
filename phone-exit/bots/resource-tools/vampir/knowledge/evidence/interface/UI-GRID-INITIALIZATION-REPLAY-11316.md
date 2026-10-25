# GridSlot: диагностический leaf и ограниченная инициализация

Текущий SHA256 EXE:
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960.
Продолжение [потока инициализации](UI-GRID-CONSTRUCTION-FLOW-11316.md).
Нет подключения к игре или процессу, ОС DLL и игровые команды не вызываются.

## Точные границы leaf

14174c9f0 не имеет unwind entry. Точный 34-байтовый фрагмент:
803d7c37ba090074184c8d05801c3207baa2000000488d0d241d3207e99f87deffc3.
После него проверены 14 int3 до следующего 16-байтового выравнивания.
Внутренний JE ведёт к RET 14174ca11; альтернативная ветка заканчивается
хвостовым JMP 1415351b0. Других переходов в этом фрагменте нет.

CMP читает byte 14b2f0173. При нуле — возврат без stores и вызовов.
При non-zero — установка трёх аргументов и JMP к диагностике, чьё возвращение
не предполагается. Тело диагностики в replay не исполняется.
Коллектор не запускался для leaf без unwind: границы проверяет сам инструмент.

Запрос b0c939c935b3d16e31f14ccc0196402d5d295357b981c4c5b17d64a971b1f84a
явно задавал leaf. Итоговый запрос f4db90dc0d1b1c3675592506ddd296841c5a2ece519a054e4e55012eb3bef895
включает также unwind roots 1417cba90 и 14358e000; полные прежние Ghidra exports
переиспользованы. Старые адреса иной версии не используются.

## Replay

replay-grid-initialization.py проверяет SHA EXE, явные адреса трёх запросов,
unwind / exact leaf / padding, версии Capstone 5.0.6 и Unicorn 2.1.4.
В эмуляторе исполняются целые native callback 14358e000, base 1417cba90 и leaf.
В нормальной ветви сервисных callbacks нет. Любое исполнение за пределами этих
тел отклоняется; вход в 1415351b0 — явный terminal stop с неизвестным результатом.

Начальные object / context / stack / flag / allocation — fixtures. Четыре
шаблона байтов: 00, 55, aa, ff. Для callback: null / same object в контексте;
для base дополнительно другой ненулевой указатель. Флаг leaf — 0 / 1.
Всего 40 случаев: 20 возвратов и 20 остановок на диагностике.

Во всех 40 проверен сохранённый диапазон object+0x4c..0x5b: он равен
исходному шаблону. Это диапазон кандидатов Row / RowSpan / Column / ColumnSpan
из прежних дескрипторов; интерпретация offsets и defaults не подменяет байты.
На normal callback проверено полное состояние 0x78 байтов: vtable,
все явные нулевые stores и сохранённость остальных байтов. Guards вокруг объекта
сохранены; null callback не меняет объект. Diagnostic ветви не объявлены
успешной инициализацией и не возвращают выдуманное значение.

Следствие ограниченного опыта: эта нормальная цепочка не заменяет входные
байты проверяемого диапазона константой. Нельзя использовать её как источник
zero/one defaults для пропущенных свойств. Реальный начальный объект / CDO /
archetype и предшествующая property initialization ещё не проверены.
Эмулятор не доказывает live runtime или совместимость исторических пакетов.

Два unittest прошли: 40 native случаев и отказ при отсутствии явного leaf.
В research-checks.json зарегистрирован ui-grid-initialization-current;
on_update=false, текущий SHA, offline_reviewed, timeout 30 секунд. Кэш включает
исходники и версии установленных capstone / unicorn. Это отдельная проверка;
прежние UI refresh / installed checks не используются как доказательство
инициализации GridSlot.

Отчёт вне Git: code-clues/grid-initialization-replay-d00a-01.json.
SHA256: 90d90f0e1793cc4e41d1a4ee57e96e4496528f511976cf6f034e59ed0d908d9c.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-grid-initialization.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/b0c939c935b3d16e31f14ccc0196402d5d295357b981c4c5b17d64a971b1f84a/manifest.json' --base-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/fdb6a135dce58a01c541bb724200457e674d19ee3cde768daf6f57a86dab0a6a/manifest.json' --callback-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/b39f3a5af27ef2a222a8784dd99199a7c10a2c3ae12ff7e8791285781e21846d/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/grid-initialization-replay-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_grid_initialization.py
```

Следующая проверка: найти и проверить allocation / property initialization /
CDO copying перед вызовом сохранённого class+0xb0 callback. Пропущенные Row /
Column / Span пока остаются unknown, UI / renderer / реальные профили не менялись.
