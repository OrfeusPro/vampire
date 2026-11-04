# Входы статической подготовки native-контекстов v2

[Selector v2](../../native-materialize-inputs.json) закрепляет 11 модулей
действия materialize и общий helper определения runtime. Ключ инструментов
содержит эти 12 файлов вместо context-группы из 197. В него также входят
SHA selector и helper самого правила, portable / native runtime и штатный
native-release-registry. Выбор проверен по фактически вызываемым методам:
native.TOOLS сохраняется полностью, включая два digest-only модуля,
чьи SHA записываются в proof и declaration.

Definitions исключают только research-checks.json и посторонние Python
файлы внутри canonical bots. Сохраняется точный allowlist закреплённого
кода, controller и helper. Все данные / JSON, Java, DLL и код вне bots
сохраняются. Совпадение basename в другом каталоге не даёт исключённому
файлу места в allowlist. Source, contexts, function reuse и generated index
остаются прежними входами stage.

Сужение работает только при совпадении всех 12 code guards и штатном
knowledge. Изменение кода, пропавший модуль либо custom knowledge возвращает
полные definitions и общую context-группу. Explicit files и runtime
продолжают входить в ключ fallback. При отсутствии selector v2 действует
старый v1; отсутствие обоих selectors сохраняет полный прежний путь.
Fresh definition / execution inputs и source barriers не ослаблены.

На текущем дереве полная опись содержит 1256 входов. Прежний scope v1
оставляет 832, новый — 272. Это число выбранных файлов ключа, а не число
подтверждённых функций. Все исключённые входы перечислены в immutable
receipt. Остальные данные и внешние зависимости пока консервативны.

На сохранённом EXE 1.13.22 статическая materialize выполнена один раз.
Неизменный повтор и повтор с моделируемой правкой постороннего
login-backend-wire-runtime взяли Journal cache. Broad context key в этом
случае изменился, scoped key сохранился. Настоящие файлы не менялись;
после результата проверены все полные SHA, source store и frozen59.
Declarations сохраняют прежние доказательства и границы допуска.
Здесь выбран готовый контекст того же SHA; новый PE-разбор или перенос
функций этой приёмкой не подтверждаются. SHA сохранённого EXE проверен
отдельно до и после action.

Добавлены 19 автоматических случаев: 14 правил входов и пять ordinary
updater fixtures. Проверены exact allowlist, сохранение данных и внешнего
кода, same-basename, code/missing/custom fallback, неизвестная схема,
runtime и native registry. Обычный engine подтверждает warm reuse
после чужого Python / broad-tool изменения; JSON, generated index,
собственный код, runtime и rule bytes вызывают новый stage. Старый путь
без selector сохранён. Fixtures не выполняют настоящую native семантику.

Зарегистрированный набор завершил 1569 тестов с тремя прежними пропусками.
Шесть дополнительных checks прошли; controller suite содержит 40 случаев.
Новый helper, selector и обе проверки входят в штатный on_update и его
ключ кэша. Полный installed updater, Ghidra, native suites, watcher
и игровой вход приёмкой не запускались. Следующий пакет профиля не назначался.

- [Машинный отчёт](AUTO-NATIVE-ACTION-INPUTS-V2-11322.json).
- [Предыдущая подготовка](HEADLESS-AUTO-NATIVE-PLAN-KEYS-V1-11322.md).
- [Ключи проверок и профиля](HEADLESS-AUTO-ACTION-TOOL-KEYS-V1-11322.md).
