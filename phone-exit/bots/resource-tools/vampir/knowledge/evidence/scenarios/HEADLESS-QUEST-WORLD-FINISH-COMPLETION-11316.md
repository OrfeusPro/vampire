# Ответ ID206 и native завершение окружения

Источник: EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960` (1.13.16).
Продолжение [метода завершения](HEADLESS-QUEST-ENVIRONMENT-COMPLETION-11316.md).
Результат не допускает установленную 1.13.18 или живые команды автоматически.

## Привязка ID206: статическая часть

В EXE найдена literal `PktWorldMoveFinishResultHandler::OnHandler()` по
149DC5630; её decoded RIP reference 1467CA4ED находится в root1467CA450.
Whole handler и receiver145DACA00 получены collect в run-7650bee00bb6,
SHA256 details.json `9c583d5995e73bb8b2f8891c8c965781f1f5b44a68f445e8fe0dc73c615ddefe`.
Оба имеют полное block/direct-flow coverage; все инструкции сверены с EXE.

Registration window 1467B589E..1467B58D7 закреплено exact bytes в helper:
handler table149DC5610 имеет slots1414096C0/14153B9D0/1467CA450;
allocation0x120 → constructor14584C8B0 → register1467CB6C0 с packet в RDX,
handler в R8. Точная пара LEA/store14584C8BC..14584C8C6 устанавливает
packet table14996B5E0. Её slot+28 указывает на getter145757EA0,
bytes `b8ce000000c3`, то есть ID206.

В whole handler после общего gate1467CD7B0 принятая ветвь вызывает
receiver145DACA00: E8 по1467CA5D0, bytes `e82b245eff`. Перед gate обработчик
проверяет player+8, пишет диагностику и вызывает подготовку145D9C220.
После receiver есть дополнительные обновления и уведомления.
Registration, constructor prefix, getter и handler проверены статически;
handler/gate/reader не исполняются в новом составном сценарии.

## Native receiver → actual virtual +78 → phase6

Whole receiver145DACA00 включён в прежний harness вместе с whole derived
completion145DA88D0, base helper145612A90 и phase setter145618B30.
Таблица derived149A3DAC0 скопирована непосредственно из source page;
slot+78=145DA88D0 и slot+A0=145DA4D50 проверены. Только +A0 выполняется fixture
с результатом0; completion dispatch и запись фазы — настоящие инструкции.

Переносы receiver проверяются по окончании каждого вызова:

| Вход / правило | Окружение / персонаж |
| --- | --- |
| packet+18, qword | environment+38 |
| packet+20, u32 | environment+40 и player+1F8 |
| default zero source | environment+44 очищается |
| packet+24, u32 | environment+48 |
| packet+110, qword | environment+50 |
| packet+29, byte | environment+58; DL завершения |
| environment+5B | environment+5A |
| packet+118, byte | environment+F1 |
| прежний +50 и packet+110 оба0 | environment+79=true, иначе false |

Получатель вызывает virtual+78 с RCX=environment, DL=packet+29,
R8D=packet+20 и R9B=packet+119. Native derived/base completion записывает
phase6 перед уведомлением. Предыдущая +79 учитывается отдельно при обработке
actor; нулевое новое значение вычисляется по старому/new quest context.

Матрица24 случая: old quest0/110120 × new quest0/110120 × old flag+79false/true
× kind0/2/255. World задан10012, packet+119=1, +118=1; поля synthetic.
Вектор double3 (1.25,-2.5,3.75) проверяется на входе actor-create boundary.
Lookup actor и его создание возвращают0; запись environment всё равно доходит
до completion. Реальные инструкции refcount возвращают control+8 к исходным2.
Порядок: world notice → actor-create missing → phase formatting → phase notify
→ event clear → UI reset. Прежние28 completion cases также выполняются.

## Проверка и границы

Helper `quest-world-finish-binding-11316.py`, общий runner
`replay-quest-environment-completion-11316.py` с `with_world_finish=True`.
Тест `test_vampir_quest_world_finish_completion_11316.py`, check
`native-quest-world-finish-completion-11316`. Регрессия прежнего completion прошла.
Артефакт:
`code-clues/quest-world-finish-completion-11316/aa6337b06005cb72ede06f1e9cd5d77c2c6eb70330361bd4a243b62874e96e7a/manifest.json`.

World record lookup возвращает missing; providers, применение player arrays,
vector predicate, heading conversion, actor lookup/creation, +A0, другие services,
диагностика/UI — fixtures. TLS задан уже инициализированным. Actor не создан,
массива эффектов packet+E8 нет; actor-present и непустые массивы не исполнялись.
Нет engine/world/class объектов, listeners или saved delegate. Native+78 и phase
setter не подменены. Дополнительные производные ветви исключены как прежде.

`native_execution=true`, `network_used=false`, `action_admitted=false`.
Подтверждены receiver и completion в одной VM; связь с ID206 handler пока
статическая. Следом исполнить whole handler с gate/early-return/error paths,
затем связать real world record+0C/name, active task и полный Time lifecycle.
Фаза6 сама по себе не подтверждает существование actor или готовность квеста.
