# Автоматическое обновление Vampir

Один проход связывает полные SHA, извлечение ресурсов, перенос функций,
проверки, кэш и подготовку пакета следующего входа. Скрипт использует JSON
реестры и manifests. Markdown объясняет порядок, но не задаёт адреса и допуски.

## Запуск и остановка

Ярлык **«Обновление Vampir»** в корне проекта вызывает `start-update.ps1`.
Он запускает наблюдатель через одноразовую задачу текущего пользователя Windows.
Наблюдатель переживает закрытие Codex; автозапуска Windows нет. Повторный запуск
использует существующего владельца. Установка игры и данные аккаунтов не меняются.

Из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --auto
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch start
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch status
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch retry
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-watch stop
```

`update --auto` выполняет один проход. `update-watch start` наблюдает за файлами
каждые 15 секунд и ждёт 120 секунд стабильности перед обработкой. Patch manifest,
file version и пауза служат сигналами; целостность подтверждается полными SHA
и контролем входов до / после работы. Незавершённая установка остаётся в ожидании.

`stop` прекращает новые проходы; текущая работа дренируется с сохранением журнала.
Статус `draining` означает, что владелец ещё ждёт свой дочерний процесс.
Stop обновлятора не останавливает игру. Не удалять lock работающего владельца.
Одинаковая ошибка не повторяется каждый цикл; `retry` разрешает новый проход.
Изменение клиента или правил также создаёт новый повод для проверки.

Явные команды сохраняются:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline '<manifest.json>' --plan-only
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline '<manifest.json>'
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --resume '<run.json>'
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update-status --run '<run.json>'
```

`--install` задаёт установку. `--auto`, `--baseline`, `--resume` взаимоисключающие.
`--plan-only` / `--audit-only` ограничивают работу планом. Без подходящей полной
описи автомат выдаёт конкретный блокер; старый адрес или чужой baseline не берёт.
`update-status` читает сохранённый журнал, не подтверждая свежесть установленной игры.

## Базы, зависимости и повторное использование

Полная опись файлов и последняя доказанная база роли выбираются отдельно.
Опись текущей версии может существовать до извлечения ресурсов: недостающие
артефакты всё равно требуют обработки. Совпадение samples недостаточно.
Для роли с новой проверенной базой отсутствие proof не разрешает откат к старой.

Нативные источники и явные проекции описаны в
[native-release-registry.json](native-release-registry.json). Рецепты и возможности —
в [update-contracts.json](update-contracts.json), проверки — в
[research-checks.json](research-checks.json), ориентиры — в
[release-update-targets.json](release-update-targets.json).
Дополнительные проверенные semantic drivers описаны в
[native-check-adapters.json](native-check-adapters.json); каждый имеет фиксированный
кодовый адаптер, строгую область выполнения и свой кэш.

Общие функции, checks и missing exports объединяются по полным источникам.
Ghidra собирает только недостающие явные roots партиями до 32, последовательно.
Полный анализ EXE и холодный BinExport не являются обязательными.
Независимые расчёты могут выполняться двумя workers; публикацией владеет координатор.

При переносе проверяются границы, инструкции, вызовы, данные и зависимости.
Generic adapters создают target-bound контексты по зарегистрированным правилам.
У нового SHA нет автоматического общего разрешения: неизвестное семейство,
layout, косвенный вызов или несколько кандидатов оставляют точный блокер.
Готовые native сценарии новой версии исполняются в своей области проверки.

Кэш зависит от реальных материалов, рецептов, fixtures, инструментов и runtime.
Повтор того же прохода проверяет целостность и использует завершённые результаты.
SHA и PE-разбор переиспользуются внутри одного замороженного прохода.
Изменение правил создаёт новую identity; прежние неизменные этапы доступны выборочно.
Подмена файла по одному mtime не становится доказательством.

## Пакет следующего входа

Пакет объединяет контексты, обязательные semantic checks, конфигурацию и профиль.
Готовность считается отдельно для launcher, world-session, карты, квестов и UI.
Функциональное соответствие не закрывает целый контракт. Fixtures сохраняют границы:
неисполненные OS / engine / network effects не объявляются проверенными.

Только полный проверенный набор соответствующей возможности назначается для
следующего явного запуска. Текущий owner сохраняет свой пакет. Admission заново
проверяет точный SHA EXE, данные, правила и runtime; при втором патче неподходящий
пакет отклоняется. Старый SDK-профиль не служит fallback новой версии.
`live_verified` остаётся false до фактического результата входа.
Обновлятор не авторизуется и не отправляет игровых команд.

Для следующего запуска владельца выбирать `--profile prepared-next`; перед
подключением можно выполнить `run-live-sessions.py --profile prepared-next --check-source`.
Явные исторические профили сохраняют свои ограничения и не переключаются скрытно.
Сейчас общие semantic adapters реализованы для UTF-8, полного string writer
и archive IO / Version / Login wire, VersionResult с input buffer, базовой
подготовки Version / Login и интеграции Login SDK-getters. Для writer требуются
подтверждённый target UTF-8 и настоящие exports; archive driver использует
опубликованный writer того же SHA. Базовая preparation использует явные
OS / SDK / helper fixtures. VersionResult
подтверждает только ID 2 / scalar input и конструкторы; другие ответы и strings
требуют своих проверок. [Точные области](evidence/updates/HEADLESS-AUTO-VERSION-11322.md).
Login SDK исполняет три getters и шесть returning leaves над синтетическими
данными; настоящий backend остаётся за границами. Metadata pipeline подключён
отдельным семейством с последующей интеграцией.
[Точные области Login и проверка кэша](evidence/updates/HEADLESS-AUTO-LOGIN-PREPARE-11322.md).
Отсутствие адаптера другого семейства — отдельный блокер, а не доказанное изменение
его кода в новой игре.

Version helpers (NM, CPU, Windows, combiners, platform) и четыре cumulative
preparation уровня обслуживаются общим `version-helper-v1` с отдельными базами,
checks и кэшем каждой из девяти ролей. Integration использует доказанные target
helpers и сравнивает их с собственной базой. OS / SDK / storage / CRT effects
сохраняют явные fixture границы.
[Области и повтор](evidence/updates/HEADLESS-AUTO-VERSION-HELPERS-11322.md).

Login metadata использует общий lifecycle `portable-native-family.py`:
неизменяемые contexts / proof / reports, точные inputs кэша и атомарный index.
Standalone collector / selector / loader / writer / copy / move и интеграция
с SDK проверяются как две отдельные роли. Fixtures map / variant / strings /
backend сохраняют собственные границы; настоящий SDK результат не подразумевается.
[Области, отчёты и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-METADATA-11322.md).

LoginResult использует две роли `login-nested` / `login-strings-buffer`: первая
проверяет whole nested layout с fixture primitives, вторая исполняет настоящий
scalar / string / UTF-8 input и buffer construction. Shared VersionResult input
служит проверенным seed, без расширения прежнего scalar report. Полный input
зависит от собственного target nested proof и semantic report. Source-bound
harness разрешает только 6 / 20 явных roots после проверки proof.
[Точные области и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-INPUT-11322.md).

Continuation/reset и четыре ранние ошибки LoginResult доступны отдельными
`login-handler-v1` ролями. Они проверяют только свои 8 / 14 сценариев, без
исполнения общего gate и успешной ветки. Публикации хранятся в
`generated-login-handlers/<family>/index.json`.

Повтор публикации готовых native contexts использует отдельный
`native-publication-validations` receipt после обычного полного adapter publish.
Driver каждый раз сверяет актуальные context / report / selected index rows,
транзитивные доказательства, tools / runtime и полные SHA исходников. Только
после финального барьера квитанция разрешает пропустить повторный transfer;
повреждение остаётся блокером, отсутствие строки восстанавливается полной
публикацией. Метрики `publication_cache` различают reused / validated и source
reads / PE builds. [Области, отказы и замер](evidence/updates/HEADLESS-AUTO-LOGIN-HANDLERS-11322.md).

Общий result gate и post-state доступны как независимые `response-v1` роли.
Для gate специальное правило отделяет 251 инструкцию от inline таблиц и
проверяет две indexed displacements; 227 остановок перед выбранной веткой
не подтверждают её внешние effects. Post-state использует свою последнюю
проверенную базу 18, gate — базу 20. Новые публикации сохраняются в
`generated-responses/<family>/index.json`.
[Области и повтор](evidence/updates/HEADLESS-AUTO-RESPONSE-11322.md).

Метрики публикаций из driver сохраняются также в
`native_contexts.publication_cache` обычного update journal. Они включают reused /
validated / receipts_written и source-store counters. Поле seconds — время
всей сессии driver, включая его этапы; это не таймер одного publish.

Целый current LoginResult handler доступен как `login-full-v1` /
`login-full-handler`: два native roots (handler и gate), synthetic packet 352 байта,
48 точных сценариев. Разовый legacy import не означает неизменность handler;
обязателен новый target report. Дальнейший перенос использует весь проверенный
current handler и независимые target dependencies. Указатель публикации —
`generated-login-full/index.json`. Интеграции reader / post-state / continuation
и регистрация подтверждены отдельными пакетами ниже. Допуск онлайн остаётся
отдельным результатом.
[Правило и замеры](evidence/updates/HEADLESS-AUTO-LOGIN-FULL-11322.md).

Same-packet композиция доступна как `login-composition-v1` /
`login-response-composition`: 22 roots объединяют native buffer / reader и
handler / gate. 77 сценариев проверяют общий packet, source strings и cursor;
при отказе reader handler не вызывается. Прямой вызов управляется координатором,
native dispatch этим не подтверждается. Новая опубликованная роль заменяет
начальный seed при выборе базы. Указатель — `generated-login-composition/index.json`.
[Границы и повтор](evidence/updates/HEADLESS-AUTO-LOGIN-COMPOSITION-11322.md).

Регистрационный `registration-v1` / `login-registration` переносит проверенную
базу 18 на 22: полный helper (101 инструкция / 395 байт) и настоящий ID 4 leaf
исполняются в native стенде; окно owner из 75 байт проверяется статически.
Адреса конструктора и handler связываются с опубликованными target contexts
`login-nested` и `login-full-handler` и их semantic reports. Запрос выделения
в исходном окне составляет 344 байта; `packet_bytes=352` означает область хранения
проверочного стенда. Эти величины сохраняются раздельно, прежние reports
и их границы не переписываются. Конструктор, owner, container insert, name getter,
UTF-8 conversion и внешние сервисы не исполняются этим пакетом. Name fixture
возвращает отдельный descriptor и сохраняет outparam; cleanup текущего указателя
не подтверждает реальное владение исходным packet. Native dispatch и
post-state / continuation подтверждены отдельными пакетами ниже; онлайн требует
собственного доказательства.
Указатель публикации — `generated-login-registration/index.json`; это не next-profile.
34 новых native сценария и 602 tooling теста прошли. Общий повтор 26 drivers
использовал 78 этапов и 26 публикаций из кэша без native / JVM / PE rebuild
(77.785473 с); reports и кэш-метрики сохранены в отчёте.
[Области и приёмка](evidence/updates/HEADLESS-AUTO-LOGIN-REGISTRATION-11322.md).

`container-v1` / `login-container` добавляет native insert, whole chained rehash,
name getter и signed-byte ANSI → UTF-16 constructor к готовому registration helper.
Пять roots проверяются целиком; ID 4 leaf исполняется, owner/window и dispatch —
нет. Новый native report обязателен даже при bootstrap на том же SHA.
После публикации proved роль заменяет reference seed; старый однофункциональный
report не расширяет свой scope. Указатель — `generated-login-container/index.json`.

Parent validation memo хранится только в текущем SourceStore: точные роли
context / report, source, tools и полная lineage участвуют в ключе. При обращении
снова сверяются SHA материалов; изменение или повреждение не даёт cache hit.
Isolated namespace не наследует направленный memo frozen input recipe.
Source barrier в конце прохода сохраняется; memo не переносится в другой проход.
120 native сценариев и 655 тестов прошли. Общий повтор 27 drivers использовал
81 этап и 27 публикаций из кэша без native / JVM / PE rebuild (93.517172 с).
[Области и приёмка](evidence/updates/HEADLESS-AUTO-LOGIN-CONTAINER-11322.md).

`dispatch-v1` / `login-dispatch` связывает опубликованные container и
reader / handler contexts с native lookup, dispatcher, wrapper, TLS setter / reset
и четырьмя cleanup leaves. Объединённый scope — 29 whole roots и 12 leaves;
указатель публикации — `generated-login-dispatch/index.json`, это не next-profile.
Дочерняя роль выбирается среди доказанных публикаций точного SHA; reference seed
не создаёт вторую кандидатуру и не заменяет native report.

107 сценариев включают доставку к native handler через vtable и два paired reuse
с теми же owner / packet. Python готовит предусловия и фиксирует наблюдения,
но не подменяет native reader → handler gating. Размер owner — 80 байт:
контейнер и active packet slot разделены. Frame size ≥ 5, initial active packet
и TLS равны нулю — явные предусловия, а не native проверка короткого header.
TLS provider / index 0 или 1 заданы fixtures; сам source-bound setter / reset
исполняется. Input UTF-8 — native, diagnostic UTF-8 — отдельный fixture.
Heap / storage, SDK / UI / clock services остаются fixtures. Transport framing /
integrity, SEH и целая онлайн-сессия этим scope не подтверждаются.
107 native сценариев и 701 тест прошли. Общий повтор 28 drivers использовал
84 этапа и 28 публикаций из кэша без native / JVM / PE rebuild
(81.942016 с). Итоговые reports и замеры сохранены
в [отчёте пакета](evidence/updates/HEADLESS-AUTO-LOGIN-DISPATCH-11322.md).

`state-flow-v1` / `login-state-flow` продолжает native dispatch / reader /
handler через post-state wrapper / getter / target и continuation getter /
source vtable `+0x28` / reset. Singleton публикует native constructor до доставки;
providers задают только ambient условия. Packet, decoded strings и registry
не reseed-ятся при входе в handler. Допуск — 33 whole roots / 14 leaves;
standalone lookup повторно не исполняется и отмечен `native_lookup_used=false`.
Пять zero-fill globals проверяются по PE virtual spans с отдельной шириной.

Три доказанные parent roles выбираются отдельно по точному SHA и semantic report.
Новый proof и native report обязательны; reference seed не выдаётся за результат.
Index — `generated-login-state-flow/index.json`, без назначения next-profile.
325 native сценариев и 773 теста прошли. Общий повтор 29 drivers использовал
87 этапов и 29 публикаций из кэша без native / JVM / PE rebuild
(150.653545 с). Пять готовых exports переиспользованы без JVM.
[Матрица, providers, доказательства и приёмка](evidence/updates/HEADLESS-AUTO-LOGIN-STATE-FLOW-11322.md).

`send-handoff-v1` / `login-send-handoff` связывает native Login prepare /
SDK / metadata с целым sender и source getter. 896 сценариев покрывают четыре
pending состояния над 224 различными подготовленными входами; прежняя фиктивная
ось `send_return=0/1` не повторяется. Source sender проверяет short ID, выбирает
timeout из session при пятом float32 аргументе 0 и передаёт тот же packet сервису
через virtual slot `+0x38`. При hit insert / delegate / getter / sink пропускаются.
Доказательство ограничено 12 whole roots / 7 leaves, packet 320 и session 160 байт.

Service vtable / sink синтетические, pending insert и delegate effects — fixtures.
Исходного перехода к writer внутри этого sender нет; schema wire role остаётся
отдельной доказанной зависимостью. Real service / queue ownership / serialization
требуют следующего пакета. Новая роль публикуется в
`generated-login-send-handoff/index.json`, без next-profile или допуска онлайн.
Проверки: 896 native случаев и 815 тестов. Общий повтор 30 drivers использовал
90 этапов и 30 публикаций из кэша без native / JVM / PE rebuild
(140.784932 с).
[Матрица, source boundaries и приёмка](evidence/updates/HEADLESS-AUTO-LOGIN-SEND-HANDOFF-11322.md).

`backend-wire-v1` / `login-backend-wire` добавляет целый source publisher,
service thunk / backend, Login writer / framing / archive cleanup к одному native
prepare delivery. 1807 сценариев используют независимые prepared inputs и byte
oracle; наблюдаются реальные native bytes до cleanup. Допуск — 29 whole roots,
13 returning leaves и 3 tails. Fixture checksum / identity transform / transport
capture не подтверждают настоящую сеть и online admission.

Новая роль публикуется в `generated-login-backend-wire/index.json`; текущая
игровая сессия и next-profile не меняются. Общий повтор 31 drivers использовал
93 stages / 31 publications без native / JVM / PE rebuild (302.339482 с).
[Матрица, memory ledger, source boundaries и замеры](evidence/updates/HEADLESS-AUTO-LOGIN-BACKEND-WIRE-11322.md).

`frame-integrity-v1` / `frame-integrity` исполняет настоящие CRC initializer /
update и XOR, отдельно и внутри direct backend → Login writer / archive / cleanup.
Матрица — 113 случаев: 103 primitive + 10 backend entries, 16 whole roots /
9 returning capsules / 2 tails. Packet fields берутся из immutable parent report;
в этой матрице preparation / SDK / sender / publisher и service assignment
не исполняются. Transport остаётся bounded capture фактических cipher bytes.

Роль публикуется в `generated-frame-integrity/index.json`; базой следующего
патча становится проверенный SHA22 context. Общий тёплый повтор 32 drivers
использовал 96 stages / 32 publications без native / JVM / PE rebuild
(236.979263 с). Текущая сессия и next-profile не меняются.
[Матрица, guards, source boundaries и замеры](evidence/updates/HEADLESS-AUTO-FRAME-INTEGRITY-11322.md).

`buffer-transport-v1` / `buffer-transport` подключает native resize / полный
chained growth и потребителей archive.raw / queue.append / ordinary transport.
Матрица — 65 сценариев / 95 шагов, 5 whole roots / 1 set-count leaf. Проверяются
aligned и small allocations, source bytes, sentinel, zero/copy/free order,
retained ownership, guards и Win64 ABI. Opaque allocator / CRT и synthetic wake
остаются providers; socket / drain / backend lifetime не подтверждаются.

Роль публикуется в `generated-buffer-transport/index.json`; базой следующего
патча служит проверенный SHA22 context. Тёплый общий повтор 33 drivers использовал
99 stages / 33 publications без native / JVM / PE rebuild (177.023237 с).
Новый driver использовал готовый source collect 17 функций; текущая сессия
и next-profile не менялись. [Доказательства и границы](evidence/updates/HEADLESS-AUTO-BUFFER-TRANSPORT-11322.md).

`service-lifecycle-v1` / `service-lifecycle` подключает native publisher /
assignment / constructors, control move-release / deleting и backend destructor /
reset / ring cleanup. Матрица — 42 сценария / 84 poison-раунда, 12 whole roots /
1 dispatch leaf; service / backend / control занимают 240 / 800 / 24 байта.
Source writes, allocator / stack unknown bits, ABI и конечные owners сверяются
независимым oracle. Service slots после destructor остаются dangling.

Heap / vector / engine / registration / callback effects — fixtures;
`cleanup_find=end` не подтверждает native unregistration. Роль публикуется в
`generated-service-lifecycle/index.json`, без next-profile или online admission.
Тёплый общий повтор 34 drivers использовал 102 stages / 34 publications без
native / JVM / PE rebuild (118.639629 с). Готовые parent native suites
и exports переиспользованы без повторного исполнения или JVM.
[Матрица, source границы и приёмка](evidence/updates/HEADLESS-AUTO-SERVICE-LIFECYCLE-11322.md).

## Выбранные материалы и публикации v2

Обычный `update --auto` и существующий watcher выбирают v2 через
`knowledge/update-engine.json`. Explicit baseline / resume сохраняются;
изменение definitions создаёт новый run с выборочным reuse. Каталог native
drivers находится в `knowledge/native-drivers-v2/*.json`: точные module SHA,
factory, family, index path и publication contract проверяются до исполнения.

Discovery search.sqlite3 служит только поиском кандидатов. Выбранные export rows
восстанавливаются из completion receipt / report / pseudocode и точного EXE,
затем попадают в отдельную SQLite для frozen adapters. Missing не доказывает
отсутствие функции. Изменённый / неоднозначный материал остаётся блокером.

Новая публикация получает свою v2 квитанцию через обычный frozen publish;
в последующих ключах участвуют выбранные descriptors / release rows / tools /
lineage, а mutable selectors проходят полный before/after barrier invocation.
Добавление несвязанного descriptor не сбрасывает старые квитанции. Legacy UTF-8
provenance обрабатывает отдельный typed bridge, не меняющий старый report.

Новые ручные исследования общих блокеров ведутся через
`research-scoped-v2.py prepare/collect/finish`; старые requests остаются в своём
workflow. Команда scoped check проверяет одну completion, полную историю —
прежний `knowledge-index.py check`. Квитанции явно содержат
`validation_scope=selected_materials_only`, `global_history_verified=false`.
Файлы, переданные через --context, остаются SHA-pinned inputs: их изменение,
включая собственную запись такого файла, требует нового request.

Первый слой и его границы сохранены в
[отчёте v2](evidence/updates/HEADLESS-UPDATE-INFRASTRUCTURE-V2-11322.md).
[Resource planning v2](evidence/updates/HEADLESS-RESOURCE-PLANNING-V2-11322.md)
завершил обычный plan-only и resume. Отрицательные cache hints оставляют архив
pending; положительные проходят прежний полный ключ / manifest / output SHA.
Промежуточные JSON, SHA и table projections используются повторно только внутри
Scope; перед сохранением плана и итоговой публикацией выполняется свежий полный
SHA / alias barrier. Изменившийся, в том числе своим адаптером, вход требует
нового прохода. Поиск hints ещё обходит всю stage history; разделение resource
keys остаётся открытым. Эта проверка плана не подтверждает целый игровой вход.
[Уточнение для Windows Path](evidence/updates/HEADLESS-RESOURCE-WINDOWS-PATHS-V2-11322.md)
сохраняет нечувствительное к регистру сопоставление отсутствующих архивов;
на других системах используются их штатные правила сравнения путей.

## Финальный барьер владельца

Обычный v2 update использует [owner scope v3](evidence/updates/HEADLESS-UPDATE-OWNER-SCOPE-V3-11322.md).
Batch declarations и строки его приватной SQLite остаются provisional.
Объединённые SHA и все sources проверяются владельцем после bundle preparation,
до назначения next-use pointers. Поздние sources учитываются; закрытый owner
повторно не используется. Отдельная команда research сохраняет прежний полный
барьер. Новых CLI-флагов для этого шага нет.

## Кэш публикаций v3

Машинный [publication recipe](native-publication-engine.json) выбирает v3,
сохраняя прежние native drivers / stages. [Проверенные области и замеры](evidence/updates/HEADLESS-NATIVE-PUBLICATION-V3-11322.md).
Memo rows / tools / SHA действует только внутри одного invocation и заканчивается
свежим полным барьером. Собственная запись index сбрасывает row memo.
Новое доказательство имеет собственный guard, receipt и namespace;
точный завершённый v2 proof переносится явным bridge, старые receipts сохраняются.
Не удалять старую квитанцию для обхода конкретного corruption-блокера.
При отсутствии publication selector прежний reviewed v2 путь остаётся доступен;
неизвестный selector отклоняется. Команды CLI не изменились.

## Окончательная проверка установки

Перед сохранением plan-only и перед публикацией next-use pointers контроллер
ещё раз проверяет полные SHA установленных EXE / архивов через исходный digest.
Size/mtime и исходный audit не заменяют эту проверку. При изменении файлов
нужен новый проход после завершения загрузки; старый пакет для иного SHA
не назначается. [Полный проход, тесты и границы составной проверки](evidence/updates/HEADLESS-FULL-UPDATE-INSTALLED-BARRIER-11322.md).
`needs_review` означает сохранённые блокеры, а не разрешение входа.

## Журналы и дальнейшая работа

В библиотеке ресурсов вне Git хранятся `knowledge/update-runs`, `update-stages`,
`update-contexts`, `check-results`, `prepared-profiles`, `prepared-bundles` и
`next-profiles`. Данные наблюдателя находятся в
`%LOCALAPPDATA%/PhoneExit/Vampir/update-watch/<установка>/`.
Базы generic семейств публикуются отдельно в `generated-native/index.json`
(UTF-8), `generated-string-writers/index.json` и `generated-archive-wire/index.json`,
а также `generated-version-results/index.json`, `generated-version-prepare/index.json`,
`generated-login-prepare/index.json` и `generated-login-sdk/index.json`;
семейства Version helpers — в `generated-version-helpers/<family>/index.json`;
Login metadata — в `generated-login-metadata/<family>/index.json`;
LoginResult — в `generated-login-input/<family>/index.json`;
они не являются next-profile. Указатели читаются соответствующими adapters отдельно
от исторических function catalog projections.

Сводка различает проверенные функции, semantic результаты, возможности,
корневые блокеры и зависимых потребителей. Число строк прежней queue не равно
числу независимых ручных задач. Метрики показывают исполнение, reuse, JVM,
длительности и стоимость проверки кэша; обещания времени будущего патча не делаются.

Новый общий блокер разбирать по [RESEARCH-WORKFLOW](RESEARCH-WORKFLOW.md).
После результата подключать правило к автомату и кэшу сразу. Автоматическое
применение готового правила сохраняет машинную квитанцию; повторный ручной
`prepare/collect/finish` для каждой неизменной функции не требуется.

Исторический замер прежнего контроллера:
[HEADLESS-RESUMABLE-UPDATE-11316](evidence/updates/HEADLESS-RESUMABLE-UPDATE-11316.md).
Прежняя инструкция, закреплённая историческим фактом, сохранена побайтно в
[RESUMABLE-UPDATE-11316](RESUMABLE-UPDATE-11316.md); её команды и запреты относятся к тому этапу.
Установленные инструменты и их ограничения: [ANALYSIS-TOOLS](../ANALYSIS-TOOLS.md).
Проверка текущей автоматизации, замеры и оставшиеся границы:
[HEADLESS-AUTOMATIC-UPDATE](evidence/updates/HEADLESS-AUTOMATIC-UPDATE.md).
Следующий подтверждённый пакет:
[автоматический string writer 20 → 22](evidence/updates/HEADLESS-AUTO-STRING-WRITER-11322.md).
Архивные методы и целые тела пакетов:
[автоматический archive-wire 20 → 22](evidence/updates/HEADLESS-AUTO-ARCHIVE-WIRE-11322.md).
Подготовка и чтение ответа:
[автоматический Version 20 → 22](evidence/updates/HEADLESS-AUTO-VERSION-11322.md).
