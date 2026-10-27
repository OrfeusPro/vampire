# ID204 → окружение → readiness квеста в версии онлайн-сессии

EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это 1.13.16, на которой запущена сохраняемая сессия. Установленная 1.13.18
имеет другой SHA; этот результат на неё не переносится.
Продолжение [receiver/pending](HEADLESS-QUEST-ENVIRONMENT-PENDING-11316.md).

## Связь обработчика

Поиск E8 callers receiver145DAD170 не нашёл проверенных вызовов. Отдельный
поиск E9 дал tail1467CA82E в root1467CA790. Кандидат подтверждён полным экспортом,
source bytes и native execution, а не одним найденным совпадением.

Новый export run-dec73d0dbc90 SHA256
`06a3e94e91d161db3f5d631054d565f2d1f2074e3c3ccb60ef0b9024511910cf`.
Он содержит handler1467CA790 (43 инструкции) и rejection target146750120.
Оба tail targets были явно включены в request; существующий receiver экспорт
сохранён. Rejection target здесь заменяет fixture, его экспорт не означает исполнение.

На регистрации проверено exact source окно1467B5853..1467B588C:
handler table149DC56B8 → vptr store, packet allocation40 → constructor14584CA00,
R8 handler / RDX packet / RCX dispatcher → call1467CB6C0.
Окно декодируется полностью. Table slots:1414096C0/14153B9D0/1467CA790.
Root регистрации1467B4C60 содержит 19000 инструкций; целая регистрация не
экспортировалась и не исполнялась. Активный dispatcher этим не подтверждён.

Constructor14584CA00 не имеет unwind root: первый collector request отказал,
границы не расширялись. Его exact 28-byte leaf исполняется отдельно и пишет
packet vptr14996B7A8. Slot+28 этой таблицы указывает на leaf145757EC0,
который настоящими инструкциями возвращает ID204. Leaves и bytes закреплены
в новом контексте, а не подставлены по историческому адресу.

## Полнота общего фильтра

Gate1467CD7B0 взят из прежнего run-eff5f37ca91c, SHA256
`4e22414b4f8c1c431e4b3c417917f72aee1223df0049b08d50d121275619b43d`.
Legacy export содержит 250 инструкций, block_coverage_complete=true,
direct_flow metadata отсутствует. Сверка с EXE выявила пропущенную цель
прямого перехода1467CDAB2: bytes488B4D47, `MOV RCX,[RBP+47]`.
Она явно добавлена как pinned instruction leaf только новому контексту.

Executable prefix1467CD7B0..1467CDBC7 теперь совпадает с 251 source instruction,
последняя — RET1467CDBC6. Следующие inline tables не объявляются кодом.
Проверка сравнивает все инструкции этого prefix, включая дополнительный блок;
это не отключение проверки границ. Handler сравнивается по полным unwind ranges.
Все прочие прежние export/leaf/fixture ограничения сохранены.

## Совместное исполнение

Новый контекст использует существующий replay окружения и добавляет handler,
native common gate и packet ctor/ID leaves. Прежние 97 сценариев сохраняются.
48 сценариев receiver теперь начинаются с handler1467CA790, а не с прямого
вызова receiver. Пакет получает source vptr, result code0; setting mode обычный.

Handler логирует code packet+10 и world packet+14 через диагностические fixtures,
получает ID204 через настоящий virtual+28 и передаёт code/ID/пустой diagnostic/
flag0 в общий gate. При true exact getter14560ADC0 получает то же окружение,
а E9 передаёт исходный packet в actual receiver145DAD170.

Далее в том же эмуляторе исполняются receiver stores, writer14560F9E0,
phase handler145618B30, callback145606830 и equality predicate14568CAD0
с прежними явными внешними fixtures. Проверяются pending+44 на входе writer,
committed+40, прежний world+F4, vector+60, enum+59, callback и readiness.
Матрица old0/5 × world0/1/10012/FFFFFFFF × enum0/3 × guard missing/deny/allow.
Input packet остаётся неизменным после native обработчика.

Пять дополнительных отказов: code10/FFFFFFFF в обоих setting modes и
code1197 в special mode. Native gate ведёт в rejection tail fixture;
окружение0x200 остаётся побайтно неизменным. В обычном mode error presentation
предшествует rejection; в special mode её нет. Принятие1197 в обычном mode
этим новым сценарием не проверялось. Всего 150 случаев: прежние145 + пять отказов.

Tool `replay-quest-environment-update-11316.py` с явным контекстом
`quest-environment-world-handler-11316.json`, helper
`quest-world-handler-binding-11316.py`, тест `test_vampir_quest_world_handler_11316.py`,
check `native-quest-world-handler-11316`. Старый default context сохранён,
его отдельная регрессия прошла.
Артефакт: `code-clues/quest-environment-world-handler-11316/c0ad3db55f169c2828f5c0970a998e8bb2701a160b2b42d89be6f651028706ae/manifest.json`.

## Что остаётся до реального offer

Packet reader не включён в эту композицию: native input synthetic, wire204
проверен отдельно. Diagnostic formatting/notification, gate setting/error
presentation и rejection tail — fixtures. Регистрация — static window.
Receiver virtual+A8=true всё ещё явно подставлен; active derived vtable неизвестна.
Остальные guards/providers/scheduler/string fixtures перечислены в контексте.

После применения world equality может стать true, но phase остаётся3.
Отдельное условие Time lifecycle требует phase>5; этот проход его не закрывает.
Далее нужны actual derived vtable, путь завершения фазы и привязка активных
loaded task/data+14/actor position перед production offer.

`network_used=false`, `action_admitted=false`. Живая сессия и её owner не
перезапускались; ID1810, движение и прочие игровые команды не отправлялись.
Это закрывает source binding handler→receiver для данного SHA, а не готовность
всех квестов или совместимость 1.13.18.
