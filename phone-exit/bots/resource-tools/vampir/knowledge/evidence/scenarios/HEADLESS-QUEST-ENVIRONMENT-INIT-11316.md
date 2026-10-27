# Начальная запись поля окружения для quest readiness

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `21986c0f3835f5cd569f32c622859a1686be976665c6d775fe148e22f261d776`.
Продолжение [связки окружения](HEADLESS-QUEST-ENVIRONMENT-BINDING-11316.md).

## Метод из таблицы объекта

Constructor 1456001D0 устанавливает vtable 149909370. Slot+10 этой таблицы
содержит адрес 14560E670. У адреса нет unwind range; вместо запроса Ghidra с
выдуманной границей закреплены все 71 исходный байт до RET в
`knowledge/native-contexts/quest-time-gates-11316.json`. Внутри нет вызовов
и переходов; декодирование покрывает каждый байт. Harness сверяет их с EXE.
Это явный метод таблицы, а не подтверждённый этап живого игрового цикла.

Метод выполняет следующие записи (hex offsets от environment this):

| Поле | Источник / значение |
| --- | --- |
| +38, qword | qword по 1496706D8 |
| +40, +44, +48, dword | dword по 1496706E0 = 0 |
| +C8, +D0, qword | 0 |
| +30, byte | 7 |
| +5A, word | 0101 |
| +78, word | 0100 |

Инструкция 14560E67B читает dword по 1496706E0, а 14560E681 пишет его в
this+40. Это та же исходная нулевая константа, которую
[конструктор QuestTask](HEADLESS-QUEST-TASK-BASE-DEFAULT-11316.md) переносит в
base+14. Числовое совпадение не устанавливает названия enum или смысл фазы 7.

## Native проверка

В общую Time цепочку после constructor добавлен вызов source slot+10.
Проверяются actual env+40=0, byte+30=7 и word+5A=0101. Начальная память перед
constructor по-прежнему A5; без данного метода +40 оставался A5A5A5A5 при
registration fixture. После метода getter 1418AF880 читает уже записанный 0.

Fixture task data+14 теперь берёт исходный dword 1496706E0. Это перенос
проверенного начального значения, а не исполнение task loader в общей памяти
Time replay. Отдельный loader check подтверждает 0 на шести настоящих CSV rows.
Прежние synthetic data14=3 и environment kind=3/4 больше не используются.
Mismatch case явно меняет environment+40 на 1, сохраняя data+14=0.
Phase case явно меняет byte+30 на 5, остальные сохраняют native 7.
Selected quest/режим и RunInInstance/byte+5A задаются для прежних ветвей явно.

34 сценария прошли с прежними результатами timer/completion и блокировок;
каждая case дополнительно фиксирует data14, environment40 и environment30.
Артефакт: `code-clues/quest-time-gates-11316/8b5468019ffcb2db05758c8b47b2a9804923a186e692430d34b88a8971a00f2f/manifest.json`.
Check: `native-quest-time-gates-11316`; тест `test_vampir_quest_time_gates_11316.py`.

## Границы и дальнейшая работа

Base registration helper, model lookup, прочие timers, JSON/string/property bag,
completion sink и fallback model virtual+30 остаются fixtures. Вызов метода
слота+10 в настоящем lifecycle, callbacks и поздние записи полей ещё неизвестны.
Начальное равенство 0==0 не означает готовность шага на живом персонаже.
Для допуска offer нужны активные значения, selected task и actor position.
`network_used=false`, `action_admitted=false`. Онлайн-сессия не изменялась.
