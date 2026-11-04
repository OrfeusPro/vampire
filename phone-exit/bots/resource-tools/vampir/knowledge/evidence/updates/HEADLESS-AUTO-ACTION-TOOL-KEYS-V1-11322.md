# Ключи инструментов отдельных действий обновления

[Реестр](../../stage-action-tools.json) закрепляет SHA кода для трёх действий.
Legacy version-login-tag и packet-writer-projection получают по 14 файлов
вместо общей context-группы из 197. Profile builder получает шесть файлов
вместо profile-группы из 200. Shared SDK / GMC2 helpers входят в builder key;
native harness / admission helpers входят в context keys. Проверены именно
вызываемые методы: остальные функции этих модулей не объявлены независимыми.

Каждый ключ содержит SHA selector и собственного helper. Portable runtime
на текущей машине включает десять файлов: Python, используемые стандартные
модули и доступные DLL / extensions. Context keys дополнительно сохраняют
native runtime и штатный native-release-registry. Изменение закреплённого
кода либо custom knowledge возвращает старую полную группу и явные входы
действия. Отсутствующий selector оставляет прежний путь. Frozen engines
не изменялись. Definition и заключительные fresh barriers учитывают правило.

При моделировании изменения login-backend-wire-runtime старые context /
profile ключи меняются; три новых ключа остаются прежними. Отдельно
смоделированы изменения собственного tag / writer verifier, portable HTTP
helper и native registry. В каждом случае меняются только ожидаемые роли.
Подстановки digest не меняют настоящие файлы; immutable receipt сохраняет
полные inputs, SHA инструментов и результаты пяти случаев.

В обычном обновляторе scoped keys используются и в journal stages, и в
affected plan. Старый journal без новых полей сохраняет консервативное
сравнение. Проекции Version / Login уже имеют собственные полные inputs;
их путь не меняется. Broad groups сохраняются у других потребителей,
включая native-materialize и пакет следующего входа.

Исправлены три пропущенных входа profile stage: полный contexts, checks
всех passed контрактов и исходный / resolved путь EXE. Эти данные
сериализуются в профиль, поэтому их изменение требует пересборки даже
при неизменных selected reports и собственном контракте. Fresh resolver
проверяет источник и evidence перед обращением к кэшу. Bundle admission
и публикация сохраняют свои проверки.

Добавлены 24 автоматических случая: 15 tool-key, пять ordinary updater
и четыре affected-plan. Fixture updater подтверждает reuse после чужого
broad-tool изменения и пересчёт после собственного scoped изменения.
Профиль пересобирается после изменения чужого passed report, чужой
binding metadata и пути установки с тем же EXE SHA. Проверка selected
profile inputs выполняется и при попадании в кэш. Affected-plan suite
теперь содержит 14 случаев, включая прежние десять.

Общий зарегистрированный набор завершил 1550 тестов с тремя прежними
пропусками. Шесть дополнительных checks прошли; controller suite содержит
40 случаев. Tooling checks включены в on_update и ключ зависимостей,
результаты переиспользуются штатным research cache.

Приёмка не запускала полный установленный updater, native suites, Ghidra
или вход. Fixture-профили не назначались для реальной сессии. Эти результаты
подтверждают инфраструктуру ключей, а не поддержку целого игрового входа.

- [Машинный отчёт](AUTO-ACTION-TOOL-KEYS-V1-11322.json).
- [Предыдущая подготовка и план](HEADLESS-AUTO-NATIVE-PLAN-KEYS-V1-11322.md).
