# QuestUpdate wire и статический перенос Tutorial dispatch

Штатный обновлятор подключает два новых recipe: статический перенос
QuestUpdate 1810 / Tutorial dispatch и ограниченные native-сценарии
QuestUpdate. Они имеют собственные selectors, cache inputs и конечные
барьеры перед публикацией. Источник — полный SHA 03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f; база —
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960.

## Статические связи

Проверены 19 whole roots: 14 функций QuestUpdate wire и пять Tutorial dispatch.
Восемь ролей связаны с готовыми INPUT / OUTPUT доказательствами, 11 новых
разбираются общим правилом. Отдельно сверены 11 leaves, десять таблиц,
13 entry boundaries и memcpy. OUTPUT-роли базы 1.13.16 сопоставляются
с текущими целыми функциями; mapping из базы 1.13.20 не подставляется.
Ветвления, callees, RIP-данные, alias-разделение таблиц и выбранные slots
проверяются вместе. Только явно зарегистрированные Tutorial JMP tails
разрешены за границы whole roots.

Регистрация Tutorial ограничена выбранным окном 57 байт с ctor / handler
table anchors. Проверено восемь байт mutable global storage, значение и
provider не подтверждены. Девять fixture entries имеют unwind-границы,
четыре — точные ограниченные leaf / tail-thunk формы; их тела не исполняются.
Ни окно, ни статический перенос не доказывают исполнение owner / handler.

## Native wire

Матрица содержит 117 сценариев: 81 запись → обратное чтение, все 29
обрезанных префиксов, один двухбайтовый хвост и шесть отказов raw writer.
Тело пакета — 29 байт, native поля — 41 байт; float32 wire преобразуется
в double-поля. Сверяются все байты тела / полей, cursor, counters, vptr / ID,
память исходного packet и guards объектов / буферов. Конструктор выбирается
по RIP-ссылке на packet table, без эвристики длины.

Отдельный новый harness сохраняет готовый INPUT engine. Whole IO исполняет
14 native roots; raw-failure scope исполняет 13 и явно заменяет только raw
writer. Это 768 + 24 проверенных Win64 вызова. Проверяются nonvolatile GPR /
XMM, стек, MXCSR control bits, разрешения чтения / записи и fixture return
PC. Memcpy ограничен восемью байтами и объявленным вводом / выходом, включая
скаляр на стеке. OUTPUT заранее выделен на 128 байт; growth — trap.
Endian helpers, настоящий allocator, handler application, server effects
и разрешение игровых действий остаются отдельными границами.

## Обычный путь и кэш

[Статический selector](../../quest-action-transfer.json) использует точные
INPUT seed / readers и текущий OUTPUT context / check. [Native selector](../../quest-wire-native.json)
передаёт 14 адресов штатному collector; экспортируются только недостающие.
Stage inputs включают оба SHA, lineage, код, правила, exports и runtime.
Повреждение отчёта, неоднозначность, изменение layout или source оставляют
конкретный blocker. Same-invocation SourceStore / Owner и свежие SHA
проверяются до публикации.

Первый статический перенос занял 22.0876 с, missing-only экспорт —
21.69424 с. После исправления стенда готовые этапы использованы
повторно; компонентный прогон с новым native stage занял 34.207674 с.
Отдельно сохранены исходные preparation stages. Два повтора —
4.542636 и 4.461966 с: четыре готовых stages,
ноль новых JVM, PE builds, static transfer и native replay. Готовые
QuestSync / Tutorial INPUT suites не исполнялись повторно. 1935 tests
прошли с тремя прежними пропусками; шесть дополнительных checks прошли.
Tooling результаты отделены от source-bound native отчёта клиента.

## Что остаётся

Native Tutorial handler / defer / apply / queue, QuestSync handler,
реальное владение storage и runtime quest-контракт остаются открытыми.
Команды на сервер и вход в игру не выполнялись. Допуск онлайн и следующий
runtime-профиль не назначались; наблюдатель выключен. Сохранены 52 прежних
fact текущего SHA, 219 baseline facts, исторические разделы и 59 frozen inputs.

- [Машинная приёмка](AUTO-QUEST-ACTION-WIRE-V1-11322.json).
- [Готовые INPUT-сценарии](HEADLESS-QUEST-PACKET-NATIVE-V1-11322.md).
- [Запуск и диагностика](../../RESUMABLE-UPDATE.md).
