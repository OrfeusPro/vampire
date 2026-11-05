# SDK и Launcher 18 → 22, статическая сверка входных функций

Полный target SHA
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Последняя проверенная база этих SDK / Launcher ролей — 1.13.18,
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Машинные указатели и границы — в [квитанции](AUTO-SDK-LAUNCHER-ENTRY-11322.json).

| Роль | База 18 | Target 22 | Инструкций |
| --- | --- | --- | --- |
| GMC constructor | 1444C4510 | 1444C4370 | 137 |
| NID context | 1450E3FB0 | 1450E3D30 | 972 |
| NID result | 1450F4170 | 1450F3EF0 | 1041 |
| Launcher token request | 1444EECD0 | 1444EEB30 | 652 |
| Launcher sign-in request | 144503E10 | 144503C70 | 679 |
| Launcher token response | 1444CC4B0 | 1444CC310 | 551 |
| Launcher sign-in response | 1444D3A30 | 1444D3890 | 762 |

Всего проверены 4794 инструкции. Поиск ограничен unwind roots в окне
±128 KiB. Он сравнивает целые формы инструкций и локальные ветвления.
Candidate discovery служит выбором адресов. Зарегистрированный check заново
сверяет полные exports с точными EXE и проверяет границы блоков.

Два request roots взяты из готового `run-e1e179d90d4c`.
Остальные пять получены одним Ghidra пакетом `run-ff9992487494`
с переиспользованием проекта. Повторный collect использовал готовые материалы
при `new_jvm=0`.

Для NID проверены непрерывный code prefix до RET, байт NOP 90,
точная граница шести RVA и все относительные цели таблицы.
Для Launcher проверены route literals, два E9 callback thunks к выбранным
response roots и CRT identity `api-ms-win-crt-convert-l1-1-0.dll!_wtoi`.
Пары внешних calls и RIP references каждого root сохранены в proof.

Пять проверок покрывают реальный статический пакет и отказы при пропущенном
маршруте, изменённом SHA, неверном callback, подменённом CRT или типе вызова.
BSS references учитываются при сравнении инструкций. Поиск literals читает
file-backed данные. Входные SHA повторно сверяются перед возвратом результата.

Check `sdk-launcher-entry-shapes` зарегистрирован в `research-checks.json`
с `on_update=true` и добавлен к обоим контрактам, `sdk-gmc2` и `launcher`.
Ключ кэша включает оба EXE, пять exports, контекст и используемые инструменты.
Контекст пары находится в `native-contexts/sdk-launcher-entry-11322.json`.
Новый SHA требует собственной пары и нового результата.

Область результата — `static_entries_only`. Внешние callees / данные остаются
открытыми зависимостями. Исполнение SDK/GMC2/NID, HTTP, текущие значения settings
и целый вход этим пакетом не проверялись. Binding допуска и prepared profile
не назначены. Семантические обязательства прежних контрактов сохранены.

## Следующий общий пакет

SDK/GMC2/NID использует финальную базу из
[итогового runtime отчёта 1.13.18](HEADLESS-LAUNCHER-RUNTIME-FINAL-11318.md).
Нужно перенести 34 roots и фиксированные leaves / switch tables, затем выполнить
3667 сценариев на target SHA и опубликовать девять component manifests
для существующего `update-profile.py`. Формы трёх SDK entry уже доступны.

Следом Launcher требует связать 14 roots текущего контракта с keys,
transport / getters / dispatch / identity и выполнить интеграционные сценарии.
Четыре request / response формы уже проверены этим пакетом.

Исторический SDK batch сохранён как база. Его present cache key изменился
из-за tooling inputs, поэтому весь исторический набор повторно не запускался.
Работа target SHA потребует собственных native доказательств.
