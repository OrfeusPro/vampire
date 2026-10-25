# Первичная ветвь installed predicate и точная цепочка dispatch

25 октября 2026. Продолжение [cached predicate](UI-CONFIG-DIRECTORY-PREDICATES-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline native replay; файловая система игры, реальные профили и командная
строка ОС не читались, игровые команды не отправлялись.

## Источники

Explicit request db3019e93fd394dc49088353b91a4462062dc21ddbc39ee7cdaa9ebdcd7ff6ce
добавил helpers 141466840 / 141586fe0 / 1415351b0 к готовому 141533f40.
После проверки file-backed объекта новое explicit задание
`71df82b6d0f0e46764a58acdd13a3bfb221795e1c889c79c56797d4684c8ac38`
добавило точный slot target 141465720; готовые экспорты использованы повторно.
Обе коллекции завершены с пустой очередью. Ghidra details:

- `ghidra/request-exports/<полный SHA EXE>/run-d0f01414a99f/details.json`, SHA256
  `193e4cdfbd910be61e7a883ae9f9f542294d03aa5bd52c367e235bb11005d759`.
- `ghidra/request-exports/<полный SHA EXE>/run-ccbca26b013d/details.json`, SHA256
  `6ed3eabc4fdb9a6958b119f73228923078ed8dfbbd6ce46e44823c3d48c5fbc0`.

Псевдокод сверен с инструкциями. Native join 1414324d0 берётся из explicit
814acd8766fb1ce262d877abd3de9ed0879b36d61aedc2a95bc9c85931a0eab8;
native flag / compare — из explicit
80c71bb346da715d37afe0eed0d57239da7f80201a658f220a0b1af4b5783e18.

## Нормальная первичная ветвь

При cache 14b0c0900 == -1 исполняется целое тело 141533f40.
141586fe0 теперь настоящий wrapper: получает строковый pointer от 141459960,
передаёт его в copy 141426b30 и возвращает output object. Copy — fixture.
Первичный predicate перемещает поля FString из temporary в рабочую строку,
обнуляет source и при необходимости резервирует capacity. Затем настоящий
join добавляет 38 units Engine/Build/InstalledProjectBuild.txt.
141584080 вызывается для рабочей строки, пока является отдельным no-op fixture.
Реальная нормализация не доказана, итоговый synthetic путь не выдаётся за путь игры.

141466840 возвращает адрес статического объекта 14b0bf650. В replay его guard
14b2c1168 находится в готовой ветви; ленивый header / cleanup здесь не исполнялись.
File-backed qword объекта указывает на vtable 1489f7798, её slot+0x48 — на
141465720. Эти bytes читаются из EXE, проверяются перед исполнением и после;
объект / таблица не подставляются host-кодом.

Целое тело 141465720 получает manager через 1414833a0, передаёт его в
1414891c0 и tail-jump делает вызов slot+0x78 полученного platform object.
Native сохраняет исходный path в RBX и передаёт его вторым аргументом дальше.
Manager / resolver / второй объект / slot+0x78 — явные fixtures. Поэтому
подтверждена первая цепочка dispatch, но не фактическое существование файла.
Ghidra предупреждение о восстановлении indirect jump сохранено; инструкцией
является JMP, не придуманная новая сигнатура с третьим аргументом.

Ненулевой AL backend выбирает NotInstalled с XOR 1; нулевой — Installed.
Оба ключа ищутся настоящим 141584470 / compare в synthetic global command line
14b2c4cb0. Результат сохраняется в cache, рабочая строка освобождается, затем
AL возвращает cache == 1. Во всех нормальных прогонах byte 14b2c4ca0 =1.

## Неготовая командная строка — отдельная диагностическая ветвь

Нулевой byte 14b2c4ca0 вызывает 1415351b0. Важно уточнить прежний unknown:
это не обычный helper инициализации. Caller передаёт ASCII source-file pointer
148a0d8f0 (CommandLine.cpp), число 0x32 и точный UTF16 текст
Attempting to get the command line but it hasn't been initialized yet.
Тело 1415351b0 вызывает 14153e230 с literal LowLevelFatalError, устанавливает
14b2e4d84=1, сохраняет return address по global context+0x10 и вызывает 141582d20.
Это только статическая проверка; реальная диагностика / завершение / возврат
callee неизвестны. Не подставляем returning fixture и не выдаём эту ветвь за
успешную инициализацию. В отчёте она явно исключена из native исполнения.

## Проверки и границы

`replay-ui-config-installed-cold.py`: 128 полных cold сценариев и 128 повторов
из cache на той же памяти. Четыре base-directory fixtures (пустой, с slash,
без slash, кириллица с surrogate pair), два capacity, backend AL 0 / 2 и восемь
command-line fixtures. Native выполняет source wrapper / transfer / join /
manager getter / первый dispatch / flag search / compare / cache / cleanup.

Проверены итоговая counted строка после native join, file-backed vtable,
обе forwarding ABI, один backend query / один flag search / один free,
очистка moved source, RIP / RSP и все восемь nonvolatile GPR. После первого
вызова fixture backend result меняется; повтор сохраняет результат и не вызывает
никакие services. Внешние base directory / copy / reserve / byte-copy /
normalization / platform manager / resolver / backend / free / ASCII iswspace —
fixtures. Overflow, ошибки allocation, aliases, неготовая command line и
ленивый filesystem guard не проверены.

Отчёт `code-clues/ui-config-installed-cold-d00a-01.json`, SHA256
`459707e1621d0f0767aeb9fc2a99f72de23bc4e14819198738401f49b5391f95`.
Unicorn 2.1.4 / Capstone 5.0.6 закреплены. Actual path, file visibility,
config precedence и UI применение всё ещё неизвестны.

Проверка вынесена в test_vampir_ui_installed_config.py / отдельный source-bound
check ui-installed-config-current с собственным кэшем и dependency closure.
Один тест занял 2.205 с; он проверяет все 128 сценариев, а не один sample.
Накопленный ui-nktileview-refresh-current не изменён; его прежний результат
26 tests остаётся применимым только при прежних dependency SHA. Добавление
нового check не означает перепроверку новой версии клиента. Automatic promotion
и фоновое расписание не добавлялись.

Далее — 141459960, 141584080, 1414833a0 / 1414891c0 и настоящий slot+0x78;
отдельно диагностический контракт, environment leaf и whole base-path / loader.
