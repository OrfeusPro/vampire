# LoginResult: native post-state и continuation в общей доставке 1.13.22

Источник — `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Машинные указатели, точные наблюдения и SHA инструментов:
[AUTO-LOGIN-STATE-FLOW-11322.json](AUTO-LOGIN-STATE-FLOW-11322.json).
Новый `state-flow-v1` / `login-state-flow` подключён к штатному автоматическому
обновлению и publication cache. Поддержка целого игрового входа этим не выдаётся.

## Что проверено

Нативная цепочка registry → dispatch → reader → wrapper → handler / result gate
продолжена исходными post-state wrapper / target / getter и continuation getter →
vtable slot `+0x28` → reset. Continuation singleton публикует исходный constructor
до доставки; координатор не вызывает post-state или reset вместо handler.

Матрица содержит 325 сценариев: 40 wrapper-вариантов post-state × 8 настроек
continuation и 5 негативных путей. Отдельные direct-target случаи прежнего
post-state suite не выдаются за интеграцию. Проверяются peer early return,
отказ result gate, popup code 54, отдельный code 22 и пустое тело reader.
В отрицательных ветках post-state / reset остаются неисполненными.
Один положительный случай вызывает native rehash; отказ reader наблюдает
native name getter, diagnostic constructor и archive cleanup.

В новом допуске 33 целые функции и 14 leaves. Сам факт допуска не означает,
что каждый root прошёл исполнение. Standalone lookup уже доказан дочерним
dispatch-пакетом; в этих 325 delivery он не повторяется и `native_lookup_used`
равен `false`. Четыре добавленные целые функции занимают 488 инструкций /
2298 байт. Два добавленных getter-листа читают свои source-bound globals.

Наблюдения включают реальные входы / аргументы, post-state service `+0x250`,
actor / class exits, source vtable и последовательность constructor vptr,
поля reset, continuation `+0x308` и flag. Адреса стека и необязательный RAX
post-state не интерпретируются как признак успешности: handler игнорирует
этот return. Сохраняются проверки ABI, canaries, допустимых native stores,
неизменности packet / payload / registry / decoded strings и чужих полей.

Первый прогон был отклонён из-за единственного различия standalone-ожидания:
первый helper reset `+43` получил в RDX исходную continuation vtable, которую
handler загрузил перед virtual call. Ноль в прежнем standalone oracle не
описывал это integrated состояние. Новый provider проверяет полное равенство
RDX таблице и обозначает его как `source_vtable_low32`; регистр не меняется.
Остальные helper inputs, ABI и guards сохраняются. Исходный отказ и полный diff
сохранены указателем `expectation_correction`; допуск по нему не выдавался.
Теперь несовпадение итоговой строки сценария с oracle сохраняет actual / expected /
spec, proof, канонический SHA контекста, SHA инструментов и ограниченный список
конкретных полей автоматически. Ранние source / guard assertions сохраняют свой
точный отказ; полный row diff относится к завершённому наблюдению сценария.

## Границы providers

Пять ambient globals находятся в zero-initialized virtual tail `.data`.
Для каждого проверяются адрес, ширина 1 / 4 / 8 байт и PE section span;
не существующие в файле байты не объявляются file-backed доказательством.
Service, actor, class и continuation разнесены. Их предусловия готовятся
до delivery; вход в handler ничего в них не перезаписывает.

Class / lookup / actor virtual methods, backend services и continuation
init / clear / shrink / cleanup helpers остаются явными fixtures.
Nonempty destructor loops, OOM / SEH и произвольные malformed maps не покрыты.
OS TLS provider, heap / storage, настоящий SDK / UI / clock и diagnostic UTF-8
также сохраняют прежние границы. Input UTF-8, source TLS setter / reset
и archive cleanup исполняются нативно.

Frame размером не менее 5 байт и начальные active packet / TLS равные нулю —
предусловия вызывающего кода. Короткий header и восстановление произвольного
stale active этим не подтверждаются. Транспортное framing / integrity,
CharacterList send, весь вход и онлайн-сессия остаются отдельными контрактами.
Профиль, соединение и игровые команды не изменялись.

## Автоматическое применение и приёмка

Каждая из трёх parent roles выбирается по отдельной доказанной публикации
точного SHA с проверенным semantic report. Reference seed нужен только для
bootstrap; после публикации он не создаёт вторую кандидатуру baseline.
Новая квитанция связывает четыре whole-body signatures, инструкции / callees /
RIP edges, оба getter-листа, handler callsites, vtable и virtual providers.
Неоднозначность, изменённое тело или повреждённая lineage дают конкретный blocker.

Ключ parent validation включает упорядоченные роли, context / report pointers,
source, tools и полную lineage. Перед cache hit повторно проверяются SHA;
memo живёт только в одном замороженном SourceStore. Конечный source barrier
сохранён. Старые proof engines и исторические доказательства не менялись.
Обычное обновление выполняется через
[общую инструкцию](../../RESUMABLE-UPDATE.md); новый publication index —
`generated-login-state-flow/index.json`, это не назначение next-profile.

325 новых native сценариев и 773 тестов общего набора прошли.
Первый проход нового семейства: 2043.698008 с.
Два повтора не запускали native / JVM; последний использовал 3 этапа и одну publication receipt, 33.082686 с.
Первый общий проход 29 drivers: 1072.694702 с; тёплый: 150.653545 с.
Оба переиспользовали 87 semantic stages без native replay / JVM; тёплый взял 29 publications без полного publish / transfer и PE rebuild.
Prepare / collect переиспользовали все 5 готовых экспортов, missing = 0, новых JVM = 0.
Byte SHA 78 инструментов / contexts совпали с Git checkout.
Замеры drivers не включают prepare / collect и глобальную сверку исторического индекса.

Неизменные parent native suites не запускались снова. При новом SHA автомат
применяет готовое правило и запускает требуемый сценарий для нового источника;
source / dependency / tools изменения инвалидируют соответствующий кэш.

Отдельный статический аудит холодного пути обнаружил повторные validate /
transfer / export coverage, поиск dispatch owners по EXE и повторный rehash
lineage до parent memo hit. Записка с точными вызовами и безопасными ключами
сохранена указателем `infrastructure_review` в машинном отчёте. Это план нового
recipe с source / tools / role / lineage identity и обязательными barriers;
ускорение этих участков пока не измерено и не объявляется реализованным.
Черновик projection memo сохранён отдельно: 21 pure mutation test и drywalk
62 evidence files / 50 документов / 70 transitive tools прошли. Он не подключён
к действующему adapter и не заменяет его проверку; указатель — `static_memo_draft`.

## Дальше

Следующий общий пакет — Login prepare metadata → Login wire с проверкой
точных аргументов sender. Реальные send / transport effects, Version sender,
clock / heartbeat, world и current entry admission остаются открытыми.
План следующего пакета сохранён отдельно; это планирование, не semantic proof.
