# Login prepare: native sender и передача подготовленного пакета, 1.13.22

Источник — `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Машинные указатели и измерения:
[AUTO-LOGIN-SEND-HANDOFF-11322.json](AUTO-LOGIN-SEND-HANDOFF-11322.json).
Правило `send-handoff-v1` / `login-send-handoff` подключено к автоматическому
обновлению и кэшу. Этот пакет проверяет передачу сервису, без подтверждения wire
или онлайн-входа.

## Уточнение плана по исходному sender

Подготовленный ранее план предполагал связь prepare → wire. Новый whole export
sender содержит 64 инструкции / 250 байт. Его исходный путь иной: проверка pending
ID → при отсутствии insert boundary → delegate boundary → native service getter →
virtual service slot `+0x38`. При найденном ID sender возвращается раньше всех
этих вызовов. Внутри sender нет вызова packet writer через packet slot `+0x10`.

Поэтому scope закреплён как `bounded_native_login_send_handoff`. Нельзя подставить
writer в синтетический service slot и выдать это за исходную связь: у этих вызовов
разные receiver / аргументы. Доказанный wire context используется отдельно для
сверки схемы Login; его независимый native suite не запускается повторно.

## Проверяемая цепочка

Один верхний native вызов prepare исполняет исходные constructor, SDK-getters,
metadata pipeline и sender. Packet занимает 320 байт. Native sender получает
тот же указатель и исходные 15 UTF-16 строк / 10 scalar полей, подготовленные
этой цепочкой. Пакет и строки не перезаписываются между prepare, sender и sink.
В стенде допущены ровно 12 whole roots / 7 leaves; SDK и service getter leaves
проверяются по исходным байтам. Lookup pending ID и выбор timeout исполняются
нативно; insert / delegate effects и service sink остаются fixtures.

Вход sender проверяется как полная Win64 tuple: session, тот же packet, short ID 4,
значение исходного qword и пятый аргумент с float32 bits 0. При промахе native
sender выбирает timeout из `session+0x30`; fixture проверяет его raw bits,
указатели / stack aliases и capability в переданном record. Delegate получает
исходный callback token. Getter нативно читает свой singleton из zero-fill `.data`;
service object и его vtable `+0x38` заданы синтетически и не выдаются за исходный
класс. На virtual call проверяются receiver и тот же подготовленный packet.

Матрица — 896 сценариев: 14 preparation cases × empty / nonempty × 8 metadata
cases × 4 pending states. Прежний `send_return=0/1` был fixture outcome; исходный
prepare не использует это возвращаемое значение. Обе прежние строки дают один
и тот же подготовленный результат, поэтому 448 parent rows сведены к 224 точным
ожиданиям. RAX sender не трактуется как успех / отказ.

Pending states: `count==free`, пустой inline bucket, heap chain miss и heap chain hit.
Inline capacity 2 хранит key 5 в bucket 1, запрос key 4 попадает в пустой bucket 0.
Heap capacity 4 использует коллидирующий key 8, цепочки `[8]` / `[8,4]` согласованы
с исходным hash mask. Ожидаются 672 forwarding и 224 suppressed handoffs.
При hit insert / delegate / getter / sink не вызываются. Во всех случаях исходный
prepare продолжает post-notify / SDK event по условиям и destructor.

Проверки включают целые тела функций, source callsites, пятый stack argument,
исходный callback token, getter RIP-global, границы zero-fill span, реальные native
переходы, ABI, canaries, точные scalar bytes, владение и освобождение строк,
неизменность provider inputs. Перекрытие fixture со всеми допущенными native
инструкциями и листьями запрещено до установки hooks. Вложенный `h.call` запрещён.

## Автоматизация и приёмка

Выбор base и dependencies производится по отдельным proved publications точного
SHA и их semantic reports. Новый sender переносится по целому телу, callees,
ветвлениям и RIP edges; service getter, typed source inputs и parent roles входят
в квитанцию. Проверка только переноса не заменяет новый native report.

Parent validation memo живёт внутри одного SourceStore. Ключ содержит роли,
contexts / checks, source, tools и полную lineage; повреждённые материалы
проверяются до memo hit. Конечный source barrier сохранён. Старые инструменты
и исторические proofs не изменялись. Публикация идёт в
`generated-login-send-handoff/index.json`, без назначения next-profile.

До native прогона список tools дополнен хэшами используемых utility и admission
модулей. Прерванный pre-native journal сохранён как `tool_closure_correction`;
результатов native сценариев в нём нет. Финальный результат получен с новым freeze.

При несовпадении завершённой строки с oracle автомат сохраняет immutable
actual / expected / spec, canonical context digest, proof, tools и до 16 diff paths.
Early guard / source assertions сохраняют свой конкретный отказ; полный row diff
относится к завершённому наблюдению сценария.

896 native сценариев и 815 тестов общего набора прошли.
Первый проход нового семейства: 560.943324 с.
Повторы не запускали native / JVM; последний взял 3 этапа и одну publication receipt из кэша за 10.587279 с.
Первый общий проход 30 drivers: 940.165715 с; тёплый: 140.784932 с.
Оба использовали 90 готовых semantic stages; тёплый переиспользовал 30 publications без полного publish / transfer и PE rebuild.
Prepare / collect собрали один missing whole sender export одной JVM в готовом проекте; готовые parent exports переиспользованы.
Byte SHA 38 инструментов / contexts совпали с Git checkout.
Независимые parent native suites не запускались повторно; измерения drivers не включают prepare / collect и глобальную сверку индекса.

## Границы и следующий пакет

Pending insert, delegate/add, синтетический service sink, SDK / backend / map /
variant / string storage, allocator / destructor, notifications и import / security
effects сохраняют явные fixture-границы. Native pending mutation, произвольные
повреждённые таблицы / OOM / SEH, настоящий service class / queue ownership,
async lifetime и отправленные байты не доказаны. Синтетический sink читает packet
синхронно; хранение указателя на stack packet в реальной очереди этим не разрешено.

Далее нужно подтвердить публикацию настоящего service singleton и vtable `+0x38`,
затем путь к writer / transport и ownership до prepare destructor. Новые цели
и границы записаны в `next_package`; это планирование, не semantic proof.
Framing / integrity, Version sender, ответы, clock / heartbeat / world,
SDK backend и current online admission остаются открытыми.
Профиль, сеть, соединение и игровые команды этим пакетом не менялись.
