# Строковые callable-объекты конфигурационного reader

25 октября 2026. Продолжение [начальной ветви reader](UI-CONTENT-CONFIG-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
В прежней записи слово callback обозначало передаваемый указатель, а не
подтверждённое событие изменения конфигурации. Здесь уточнены локальные роли.

## Явные задания и границы

Запрос `b8e7b31fc90965f4f2bbd1bb433fb4531f7e465d1759f073953ed36d607c114f`
содержал 1445c1f50 / 1445c78d0 / 1445c7970. Collector отказал до выгрузки:
1445c7970 не является unwind root. Повтора этого запроса нет.
По точным байтам установлен leaf thunk: 11 байтов
`488b12488b09e935fee5fc`, SHA256
`cfb536d4b18ca528ee21ab7ce408890f4e409bd774528a0f48ad121435452860`.
Инструкции: `mov rdx,[rdx]; mov rcx,[rcx]; jmp 1414277b0`; далее пять INT3.
Границы leaf проверяются отдельно, unwind metadata для него не выдумывается.

Новый запрос `e70778582e57118ddd4c10a1a01276e0d73ba8f9b86794763767f555d15e6666`
исключил leaf и добавил точный callee 1445c67a0 из wrapper 1445c78d0.
Collector завершился с collected и пустой очередью. Ghidra выгрузил три roots:
1445c1f50…1445c2139, 1445c67a0…1445c681a, 1445c78d0…1445c78f0.
Материал `ghidra/request-exports/<полный SHA EXE>/run-b25bb2ea1a0f/details.json`,
SHA256 `336bf3091a16da247a3f7162f5ae6f1bb3d7a02bddf3d9a40a9e620d8ec2e047`.
Инструкции и псевдокод сверены; остальные функции не выгружались.

## Проверенные локальные роли

1445c78d0 меняет порядок аргументов и вызывает 1445c67a0, возвращая output.
1445c67a0 разыменовывает захваченный указатель на строковый объект, читает
data / count и копирует ровно count × 2 байтов во вновь выделенный буфер.
При count 0 выдаёт нулевые data / count / capacity. Это копирование объекта
по сохранённой длине; поиск terminator в этой функции не выполняется.

`replay-ui-config-callables.py` исполнил оба полных тела в 32 сценариях:
семь UTF16 payloads и нулевой count, два значения добавочной capacity fixture,
вход через helper или wrapper. Есть строка из одного terminator, кириллица,
surrogate pair, путь и встроенный NUL. Native сохраняет count / capacity,
возвращает output, оставляет исходные поля / bytes и границы output прежними.
28 непустых payloads вызвали allocation / copy по одному разу; четыре
нулевых count обошли оба вызова. Allocation 141436ed0 и byte copy
1487f5ab9 — fixtures; native allocator / ownership не проверялись.

Leaf 1445c7970 проверен в трёх сценариях: нулевой и два различных указателя
на строку. Он разыменовывает оба входных аргумента и передаёт их в 1414277b0.
Этот последний helper заменён fixture без записи destination; проверено
только tail forwarding / return, а не фактическое присваивание строки.

1445c1f50 статически показывает sparse-container insertion: шаг элемента
0xb0, выбор свободной записи / увеличение count, bitmap, перенос строкового
ключа с обнулением источника, вызов 1445c4f60 для оставшегося payload,
hash helper и работу с bucket links. Это форма контейнера, не доказательство
типа source C++, события настройки или фактического dispatch. Ни контейнер,
ни вызываемые им storage / hash / payload helpers не исполнялись.

## Воспроизведение и ограничения

Unicorn 2.1.4 / Capstone 5.0.6, полный SHA источника, три unwind roots,
leaf bytes / padding и выбранные call edges проверяются до replay. Исполнение
вне двух native тел, leaf и явных fixtures отклоняется. Игра не запускается,
профили / конфигурации не меняются; зависимости аналитические, вне runtime.

Отчёт `code-clues/ui-config-callables-d00a-02.json` вне Git, SHA256
`b0b998e5d9645b5a13bb8743ea63203012f8479dae0912e8d07ffd8adf018fc2`.
01 — предыдущий пробный отчёт; не перезаписан. Все шесть tests tile refresh
прошли, включая 32 clone / 3 forwarding случая. Проверки зарегистрированы
в source-bound плане обновления; следующий EXE требует переноса и сверки.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-callables.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/e70778582e57118ddd4c10a1a01276e0d73ba8f9b86794763767f555d15e6666/manifest.json' --leaf-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/b8e7b31fc90965f4f2bbd1bb433fb4531f7e465d1759f073953ed36d607c114f/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-callables-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — 1445c4f60: как два callable-объекта сохраняются в payload и где
используются. Полный reader / cleanup, lifetime, источник обновлений,
config precedence и active resource / Brush остаются неизвестными.
Дефектные counts / aliasing здесь не проверены. Эти локальные результаты
не открывают генерацию внешнего вида и не означают событие для реального бота.
