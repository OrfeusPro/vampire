# Ghidra: пакетная декомпиляция вместо последовательного чтения инструкций

## Selection state dependencies, 20 октября

Пакет расширен до 48 функций/32 warnings: base reset/SetState/state label,
auth guard и deferred callback. [Native проверки и ограничения](HEADLESS-SELECTION-STATE-TRANSITION.md).
Общий INDEX указывает на последний успешный run, предыдущие exports сохранены.

## Selection service, 19 октября

Пакет расширен до 43 функций/30 warnings: base singleton ctor, derived
constructor и virtual40/50 targets. [Native evidence и границы](HEADLESS-SELECTION-SERVICE.md).
Последний export указан в общем INDEX, прошлые runs сохранены.

## WaitingEndNotify caller, 19 октября

Пакет расширен до 39 функций/26 warnings. Caller 0x146768540 получил
аналитическую метку CharacterList_RequestCaller; diagnostic доказывает
PktWaitingEndNotifyHandler. Predicate 0x145c85d90 экспортирован отдельно.
[Native связь с requestB](HEADLESS-WAITING-END-CHARACTER-REQUEST.md).

## CharacterList boundary, 19 октября

Текущий пакет: 37 функций, 19 warnings. Добавлены constructor global-object
после LoginResult, actual virtual+0x28 reset и две CharacterList request routines.
[Связи и native-проверки](HEADLESS-CHARACTER-LIST-BOUNDARY.md). Предыдущие
sections описывают прошлые immutable runs, latest INDEX обновлён verifier.

## LoginResult post-state, 19 октября

Добавлена аналитическая метка Login_PostState 0x1467259c0: последний экспорт
содержит 33 функции, verifier подтверждает 15 warnings. Native handler
достигает этой функции, backend пока capture; прямой запрос персонажей
не доказан. Предыдущие sections сохраняют результаты прежних immutable runs.
[Источник, SHA и проверки](HEADLESS-LOGIN-RESULT-HANDLER.md).

## Расширение для LoginResult, 19 октября

Текущий manifest/export содержит 32 функции, verifier: 15 warnings.
Добавлены LoginResult constructor/writer, FString/StdString reader,
nested TimeBase/PeriodServerDate и UTF-8 decode helpers. Исходный пакет
из 22 функций ниже описывает первый запуск. Общий ghidra/INDEX.md
указывает на последнюю успешную immutable run; команды прежние.
[Связи с native-проверками и SHA](HEADLESS-LOGIN-RESULT-READER.md).

19 октября 2026. Общий [указатель функций](../../vampir/FUNCTION-INDEX.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Полученный результат

Подключена **Ghidra 12.1.4**, отдельный **Temurin JDK 21.0.12.1+1**.
Закреплённые URL и опубликованные SHA256 находятся в
[ghidra-tools.lock.json](ghidra-tools.lock.json):

- Ghidra archive: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
- JDK archive: `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e`.

Официальные источники: [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build),
[Temurin release](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1).
Requirements самого выбранного Ghidra release требуют Java минимум21;
имеющийся JDK17 для Android не заменён. Системные Java/PATH не менялись.

Фактически импортирован EXE и выгружены **22 из 22 функций**: Login Prepare,
constructor/writer/reader/LoginResult, Version Prepare/constructor/writer/
VersionResult, result gate, request handoff, send wrapper/send-B, SDK getters,
FString writer, BeginGame/connect и SDK sign-in response.

Три запуска (первичный импорт и два повторных process) дали побайтно одинаковые
22 файла `.c`. Это восстановленный C-подобный псевдокод, не исходные C++ файлы.
Имена заданы по уже собранным связям; `name_origin` явно отмечает analyst hints.

## Где читать

Стабильный вход: **`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`**.
Рядом **latest-export.json** указывает конкретный успешный export directory.
Текущий проверенный запуск:

`F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-0ea6cdec7ca3/`.

- `INDEX.md` — ссылки на каждый `.c`, адрес, число инструкций и calls.
- `functions.json` — машинный call graph, состояния decompiler, версии.
- `provenance.json` — SHA source/manifest/Java script/runner/tool archives и файлов.
- `headless-export.log` — полный лог конкретного запуска.

functions.json SHA256: `11598a0308d1681b88138b8c6bff47a83cfa0febc2779aee0f31b5038303c342`.
provenance.json SHA256: `11c27210206714a7a5e7fb5bcfabeb16f9e81599c42436937c6e63c74479677f`.
entry-manifest.json SHA256: `e6b6fb046f24b452d4870208f33ebcbc8c7e4c6ee71ac758ac82871d2ee9eb41`.

Projects, downloads, JDK, caches и decompiler output находятся вне Git в общей
библиотеке/игнорируемой `.tools`; в репозитории только инструменты и справочники.

## Повторение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/install-ghidra-tools.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
```

Для первого импорта вместо `--reuse` выполнить runner без этого флага.
Runner не перезаписывает имеющийся проект автоматически. Каждый export получает
отдельную `run-*` папку; неуспешный запуск не может принять старый functions.json
за свежий результат. latest-export.json обновляется только после полного успеха.
Проект хранится в `ghidra/projects/Vampir_<source SHA prefix>`.

[Manifest builder](build-ghidra-manifest.py) проверяет full EXE SHA и upstream
evidence, сверяет seeds с PE unwind roots и сохраняет hash каждого chained range.
Адреса/имена закреплены за конкретным source SHA. При обновлении игры нельзя
просто переиспользовать старые offsets: builder отклоняет другую сборку до
проверки и обновления mappings. Автоматическое межверсионное сопоставление
функций пока не реализовано.

[Java exporter](ExportVampirFunctions.java) проверяет SHA импортированной программы,
создаёт известные function boundaries/names, ограниченно дизассемблирует ranges,
декомпилирует и выгружает call edges. `-noanalysis` отключает полный проход
auto-analyzers; это **не** отсутствие disassembly/decompilation выбранных функций.
Импорт всё равно читает PE и обрабатывает его структуру/импорты. Первичный импорт
тяжелее повторного process сохранённого проекта.

[Runner](run-ghidra-export.py): JVM heap2G, max-cpu2, decompile timeout45s/function;
user.home Ghidra изолирован в игнорируемой `phone-exit/.tools/vampir-ghidra-home`.
Это ресурсы инструмента анализа, не будущего runtime бота. Игра не запускается,
инъекция/чтение процесса/профиля не используются.

## Что уже стало проще

`PktLogin_Write.c` сразу показывает полный порядок строк и virtual archive slots;
теперь не требуется отдельное ручное чтение каждой LEA/CALL для предварительной
схемы. Размеры primitive slots всё равно подтверждать существующими archive
bindings/native vectors, а не угадывать по восстановленному C type.

`Request_Handoff.c` показывает статический путь: проверка записи в контейнере
по raw short kind, при совпадении ранний return; timeout0 заменяется полем
объекта+0x30; затем container helpers и вызов transport virtual+0x38.
Это **статическая подсказка Ghidra**, пока не native replay всего handoff.
Kind4 из Login preparation не следует путать с packet ID3.

`VersionResult_Handler.c` читаемо показывает вызов Result_Gate и Login_Prepare.
Именно этот edge дополнительно сверяется с прежней native проверкой.

## Ограничения и новый порядок работы

У всех22 decompilations completed=true, но есть **13 warnings**:
12 о перекрывающихся global symbols и 1 `Type propagation algorithm not settling`
у SDK_SignInResponse. Предупреждения оставлены в `.c`; completed не означает
корректность всех типов/параметров/ветвей. В коде остаются undefined types,
числовые offsets и нераспознанные indirect callees.

Дальше сначала искать функцию и соседние calls в этом batch, затем по нужным
фрагментам расширять именование/типы и проверять serializer/handler целиком
native fixtures. К отдельным инструкциям возвращаться при неоднозначности,
ошибках decompiler и проверке критичных wire boundaries. Ранее подтверждённые
результаты не заменяются предположениями декомпилятора.

[Три tests](../../test_vampir_headless_ghidra_export.py) проверили manifest byte
hashes, все exports/provenance и известные call edges VersionResult→Login,
Login→constructor, Login writer→FString writer, Version→constructor.
Три новых tests и три смежных Login field tests прошли; runtime не менялся,
поэтому полный headless suite379 из последнего runtime milestone не повторялся.
Runtime бота не менялся. Декомпиляция не доказывает wire compatibility,
живую авторизацию или Android parity.
