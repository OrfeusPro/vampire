# Общий прогон чтения настройки и сохранения привязок

25 октября 2026. Продолжение [переноса payload](UI-CONFIG-PAYLOAD-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверка offline, на synthetic памяти Unicorn; игра, профили, реальные
конфигурации и действующий UI snapshot не изменяются.

## Повторное использование источников

Задание `a6a470d8b35d32cddd3482c50455299da09825d30b62f849db7495c227e609fd`
явно содержит roots 1445c2c30 / 1445c1f50 / 1445c4f60 / 141421b80.
Все четыре уже ready; collect вернул reused / addresses=[], новых exports нет.
Receipt: `knowledge/collections/c9ec36f69a60b7ff132f732cb58b036537916a9a06fff3064fe074aa35749605/manifest.json`
во внешней библиотеке ресурсов.

Использованы сохранённые Ghidra details того же полного SHA:

- Reader: `run-40f646b1556a`, SHA256
  `7e531a5bd23c58ae8711644f28467b7ff0701183f1b3718da4b8703760cfc869`.
- Insertion: `run-b25bb2ea1a0f`, SHA256
  `336bf3091a16da247a3f7162f5ae6f1bb3d7a02bddf3d9a40a9e620d8ec2e047`.
- Payload copy: `run-218ed676dfab`, SHA256
  `b2d468647ed1c90a3eb8ce6967ec78eed53f99fa0b4156dd031b98154c969c43`.
- Capture destructor: `run-21a346cf8c62`, SHA256
  `64bfd80ae3d7bb109d26e5a61b00b6cf53ace539670542618db43b938ae9daed`.

Пути относительно `ghidra/request-exports/<полный SHA EXE>/`; файл details.json.
Три ранее проверенных leaf bodies и четыре slots таблицы 1489e4448
переиспользуются с exact bytes / границами из replay-ui-config-payload.py.
Новые leaf функции по похожим байтам не назначаются.

## Что исполнялось вместе

`replay-ui-config-reader.py` исполняет исходные тела reader, insertion,
payload copy и inline cleanup в одной памяти до полного возврата reader.
Каждая последовательность добавляет три разных synthetic ключа в один
предварительно выделенный контейнер, без сброса между вызовами.
Первый ключ — ContentSubName / NnCoreSetting; остальные явно демонстрационные.

48 последовательностей / 144 полных вызова покрывают все восемь сочетаний
found / missing для трёх настроек, три группы значений и два первых RCX.
Есть RED, другое значение, пустой payload с terminator, FString с нулевым
count / data, кириллица, surrogate pair, slash и длинная строка.

Проверены:

- Global lookup получает section / key и адрес filename object; временная
  строка перед ним обнулена. Assignment helper вызывается только при found.
- Native reader продолжает после missing, создаёт и сохраняет две привязки
  к destination. На выбранных путях последующих вызовов этих операций нет;
  destination остаётся прежним либо результатом assignment fixture.
- Ключ переносится в новую запись: pointer / count / capacity сохранены,
  исходный временный FString обнулён и не передаётся в free fixture.
- Поля payload содержат собственный destination и два capture objects.
  После возврата они ссылаются на destination, а не на временный stack.
- На каждый reader приходятся два native capture-copy и два native cleanup.
  Free fixture получает только временную lookup-строку с ненулевым data,
  включая payload из одного terminator. FString с нулевым data не
  освобождается. Cookie аргумент проверяется.
- Последующие вызовы сохраняют поля, key bytes и destination всех предыдущих
  записей. Проверены guard bytes и отсутствие записи в четвёртый элемент.
- Native count и occupied bitmap меняются для трёх записей; при одном bucket
  реально записанная цепочка прочитана обратно как 2 → 1 → 0 → -1.
  Source ключ очищается native кодом, без host перезаписи после вызова.

## Явные fixtures и границы

Global config присутствует. Модель контейнера начинается с нулевым count,
четырьмя выделенными slots, одним bucket и inline bitmap. Growth / reuse /
rehash не выполняются. Uniqueness helper всегда возвращает false — сценарий
новых записей. Повторяющиеся ключи, замена, отказы и возврат свободных slots
не проверены. Native hash алгоритм не исполняется.

Fixtures: virtual lookup, конструирование ключа FString, assignment FString,
append-bit service, hash key, uniqueness, temporary free и cookie service.
У каждого проверяются аргументы / допустимые побочные записи. Bit-count
в модели обслуживается fixture; это не восстановленная схема всех bit-array
полей. Assignment fixture записывает отдельный synthetic результат в destination:
его дальнейшая сохранность проверена, native строковая реализация — нет.

Фактическое последующее исполнение сохранённых операций, источник обновления,
container lifetime, config precedence и active resource / Brush не доказаны.
Отсутствие callback на этих путях не доказывает отсутствие событий позже.
Эти ограничения не разрешают генерацию внешнего вида или действия бота.

## Воспроизведение

Unicorn 2.1.4 / Capstone 5.0.6; полный SHA EXE, unwind roots, exact leaf bytes,
padding и table slots проверяются до исполнения. Вызов вне выбранных тел и
восьми явных fixtures отклоняется. Полный возврат проверяется по RIP / RSP.

Отчёт `code-clues/ui-config-reader-d00a-02.json` вне Git, SHA256
`ef9b09226584fbd78038d19cef15e912f5faf87993aeded12e35b29536af8706`.
01 — пробный отчёт, сохранён отдельно. Все восемь tests tile refresh прошли,
включая общий reader / insertion / capture-copy / cleanup. Новый тест входит
в source-bound registry и план повторной проверки после обновления клиента.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-reader.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/a6a470d8b35d32cddd3482c50455299da09825d30b62f849db7495c227e609fd/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-reader-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Следующий шаг — найти потребителей сохранённых invoke pointers и условия
их вызова; отдельно проверить uniqueness / replacement. Подмена lookup или
одного DefaultGame.ini снимка не подтверждает приоритет источников настроек.
