# LoginResult: native dispatch, TLS и archive cleanup

31 октября 2026. Источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинные доказательства, reports и замеры](AUTO-LOGIN-DISPATCH-11322.json).

## Цепочка доставки

`dispatch-v1` / `login-dispatch` связывает готовые container и reader / handler
с целыми текущими Dispatch `0x1467c8f00` (154 инструкции / 647 байт) и lookup
`0x1467c9240` (45 / 171). Union содержит 29 целых функций и 12 leaves.
Два missing exports собраны одной JVM; готовые child exports не повторялись.

Регистрация ID 4 и дополнительные collision / high-byte entries создаются native
register / insert, до передачи frame registry замораживается. Native dispatcher
читает LE16 ID с frame+3, выполняет FNV по обоим байтам и ищет запись в том же
контейнере. Packet / handler pointers наблюдаются после вставки; фактические
lookup returns и последующие вызовы сверяются с этими bindings.

Archive constructor получает frame+5, длину body, source flags 1 и fifth arg 0.
Native reader через packet slot+0x20 пишет тот же packet, затем успешная ветка
Dispatch вызывает handler slot+8, wrapper `0x14153bd00` и handler slot+0x10.
Handler и общий gate исполняются нативно. Python больше не решает, вызвать ли
handler после reader; он лишь наблюдает эту цепочку и проверяет результат.
Packet fields, strings, logical cursor и handler events читаются из памяти.

На входе handler проверяются owner+0x48=packet, TLS context=owner и исходная
тройка handler / context / packet. После handler return активная ссылка очищается.
Reader-owned packet / frame / heaps защищены от повторных записей, включая
запись тех же байтов. Archive защищён на время handler; затем снимается только
его точный диапазон для законного native cleanup. Registry остаётся read-only.

## TLS и cleanup

TLS setter `0x144aacc10` исполняется как 30-байтовый leaf. Он читает `_tls_index`
из zero-initialized virtual tail секции `.data`, затем GS:[0x58], provider vector
и block+0x100cc0. Это адрес без file backing: PE span проверяется отдельно,
скрыто читать raw bytes по нему нельзя. Provider и индексы 0 / 1 — явные fixtures.
В каждом сценарии оба slots сбрасываются; невыбранный slot равен null, оба
защищены от записи. Изменяется только эмулированный GS_BASE Unicorn, ОС не меняется.

После success и reader failure native setter сбрасывает TLS. Четыре cleanup leaves
`0x144aacc70 → 0x144aac2c0 → 0x144aacf30 → 0x144aacef0` исполняются целиком:
15 / 31 / 15 / 11 байт. Проверяются последовательность, тот же archive pointer,
vptr chain и нулевые buffer / length / cursor / swap после возврата.
Ненужные handler/service writes после leave() не попадают в handler observation.

## Предусловия и матрица

107 сценариев: 77 delivery vectors из child composition, 16 lookup, 8 unknown ID,
4 focused deliveries (collisions / high bytes / growth) и 2 paired reuse.
Каждый reuse передаёт success → empty-body failure → unknown ID на том же owner,
registry и packet, без повторной регистрации, конструктора или reseed.
Оба TLS provider indices покрыты; после успеха native-cleared состояние остаётся
нулевым на следующих failure / unknown ветках.

Frame size ≥ 5 — явное предусловие вызывающего кода. Native dispatch не проверяет
короткий header перед чтением ID; такая проверка не приписывается клиенту.
Initial active packet и TLS равны 0. Failure / unknown ветки не объявляются
восстановлением произвольно повреждённого prestate. Transport framing / integrity,
SEH / OOM и malformed maps требуют собственных контрактов.

Owner стенда занимает 80 байт, включая active pointer; packet allocation request
344 байта отделён от reference extent 352. Native packet constructor теперь
выполняет trailing string init через настоящий ANSI constructor с source NUL,
а не прежнюю empty fixture. Загрузка RDX за 26 байт до call проверена вместе
с отсутствием перезаписи аргумента между загрузкой и вызовом.

Native input UTF-8 conversion исполняется. Diagnostic UTF-8, allocators / free,
vector reset / reserve, SDK / UI / clock и прочие сервисы остаются fixtures.
OS TLS provider, native registration owner/window, post-state / continuation
integration, сеть и целая онлайн-сессия этим пакетом не подтверждаются.

## Перенос и кэш

Контексты и reports composition / container проверяются независимо по полному SHA.
Bootstrap seed не заменяет новое native доказательство; опубликованная роль
вытесняет reference при выборе будущей базы. Проверяются whole instructions,
virtual slots, typed RIP literals, PE virtual TLS span и точные листья.
Cleanup leaf может переместиться независимо от соседнего; нормализация выполняется
для каждого leaf, а tail допускается только в явно объявленную цепочку.

Parent memo ограничен одним SourceStore, полными ролями context / report, tools
и lineage. Данные сверяются до cache hit и конечным source barrier; namespaces
не наследуют неправильный directional memo frozen input recipe.

Первый запуск остановлен до native: generic child at() видел bootstrap и proved
composition с одинаковым SHA. Новый adapter выбирает ровно одну проверенную
публикацию и её exact report. Regression-тест покрывает неоднозначность и чужой SHA;
исходный журнал сохранён, новый tools SHA создал отдельный проход. Старый engine
не менялся. Tooling run с изменившимися входами отклонён и выполнен заново для
зафиксированных файлов. Эти результаты не выдаются за native-сбой.

Семейство подключено к [реестру drivers](../../native-check-adapters.json), обычному
`update --auto`, resumable journal и publication cache. Указатель результата —
`generated-login-dispatch/index.json`; он не назначает профиль текущей сессии.

Пройдено тестов общего набора: 701; 107 новых native случаев прошли.
Первый проход семейства с новым native доказательством: 622.469535 с.
Два повтора семейства не запускали native/JVM; последний использовал 3 этапа и одну publication receipt, 11.618185 с.
Первый общий проход 28 drivers: 426.338094 с; тёплый: 81.942016 с.
Оба использовали 84 готовых semantic stages без native replay и JVM.
Тёплый проход: publications reused 28, полных publish/transfer 0, PE rebuild 0.
Prepare/collect переиспользовали archive constructor и собрали два missing whole exports одной JVM; очередь пуста.
Byte SHA 61 инструментов / contexts совпали с Git checkout.
В первом полном проходе parent validation выполнена один раз и переиспользована 3 раза в том же SourceStore.
Замеры относятся к выбранным drivers; глобальная сверка исторического индекса учитывается отдельно.

## Остаток

Для следующего общего пакета post-state / continuation уже готовы четыре roots:
`0x1467589a0`, `0x144a2d9b0`, `0x1464a9800`, `0x1464afcc0`.
Новых exports / JVM не требуется. Новый явно проверяемый native union будет
33 whole roots / 14 leaves; request для дополнительных четырёх адресов остаётся
в пределах одного collector batch. Пять globals находятся в virtual tail `.data`:
нужны PE spans и providers, а не вымышленные file-byte hashes. Точные pointers
готовых contexts / reports, source bindings и оставшиеся границы сохранены
в planning-only next package; текущая приёмка их integration не подтверждает.

Нужны интеграции post-state / continuation, prepare → wire и оставшиеся текущие
SDK / clock / heartbeat / world contracts. Transport / receive framing и integrity,
настоящий SDK backend и целый онлайн-вход остаются отдельными проверками.
Профиль и игровая сессия не менялись. Неизменные готовые suites использовать
через proofs / reports / cache, не разбирать повторно вручную.
