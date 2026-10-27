# SDK/GMC2/NID 1.13.18: итог общего автопрохода

[Состав, доказательства и ограничения](evidence/updates/HEADLESS-SDK-BATCH-11318.md).

Штатный `update --resume` подтвердил **81 → 75 строк**: закрыты три SDK/NID
bindings, переносы assembly/geo checks и зависимость launcher от SDK.
Новых причин нет. Всего закрыто 75 строк из исходных 150; это причины
блокировки, а не 75 независимых ручных экспериментов.

`sdk-gmc2` получил `passed` в границах source checks. У launcher остались
`release-launcher-contract: requires_port` и
`sdk-runtime-launcher-11316: requires_port`. Проверенный offline candidate
ещё не является рабочим launcher-профилем; loader не переключался.

Пакет содержит 34 source roots, 21 проверенную цель switch tables,
3667 native cases и 288 дополнительных helper cases. Четыре штатных checks
дали 30 passed tests: 13 client и 17 infrastructure. Дополнительные
15 collector и четыре tooling-scope tests прошли отдельно. Исторический
SDK assembly 1.13.16 failure не засчитан как passed и не скрыт.

Source-specific `source_variants` выбирают проверку по полному SHA;
тестам новой версии не требуется перестраивать старый SDK profile report.
Общий native report используется assembly, geo и batch check через hash cache.
Две группы addresses и оба `finish` использовали те же четыре check reports.
34 roots оформлены двумя requests только из-за лимита 32; один пакет и коммит.

Факты: `551bcd65c9e3f8d57673613e6818b74419e2a6d72858697570f2cd1c5cbd3bcf`
и `fd47df98d15eec7ec014ec58034d91d7e8489ef9ce1f1b9cdc98ca79906ee492`.

Завершающий прогон занял 995.811 секунды. Изменился общий runner, поэтому
старые stage receipts были пересчитаны и затронутые регрессии выполнены
автоматически. Переиспользовано stage receipts 0, новых Ghidra-запусков 0;
при этом собственные check/native caches использовались. Нулевой stage reuse
не означает повторный SDK native replay для каждого потребителя.

Журнал в библиотеке ресурсов:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
SHA256: `6aac061ca242f7ed74fc34f12a2768aac5c4b671c9ea95d53f864fee3069dd7d`.
Полный список: `knowledge/reports/update-manual-queue-11318-75.md`.

Состояние `needs_review`, profiles пуст, activation/baseline promotion false.
Следующий пакет — current launcher runtime/source guards и список персонажей;
далее оставшиеся clock/game profile prerequisites и отдельная живая проверка.
Квесты и постоянная сессия 1.13.18 этим результатом не объявлены готовыми.
