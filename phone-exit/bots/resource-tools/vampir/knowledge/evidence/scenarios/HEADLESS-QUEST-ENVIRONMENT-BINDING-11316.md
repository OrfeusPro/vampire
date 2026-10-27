# Объект окружения в условии выполнения квеста

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `714825407af883dfa8d1a506b40472431cc52d2fc15bcfceac52cce7173aa705`.
Новые экспорты: constructor run-430fed1bb906 (SHA закреплён в
`knowledge/native-contexts/quest-time-gates-11316.json`), base helper
run-484b66614e30 SHA256 `3fcf1c70b84c49edcc16a5e162680b7f844b13973f7e8aed0973b3e35a360c60`.

## Источник объекта и сравниваемое поле

Exact leaf 14560ADC0, bytes `488b05e1b0fd05c3`, читает pointer по 14B5E5EA8.
Важен точный адрес: это 14B5E5EA8, а не предполагаемый по имени менеджер.
Поиск RIP-relative MOV/LEA дал кандидат store 1456001EE; его принадлежность
и инструкции подтверждены целым экспортом constructor 1456001D0.
Поиск использовался для навигации, а не для доказательства отсутствия других
косвенных записей.

Конструктор сохраняет this в global 14B5E5EA8 и устанавливает окончательную
primary vtable 149909370. Её slot+B8 содержит 1418AF880, exact leaf
`8b4140c3`: читает int32 this+40. Следовательно, predicate 14568CAD0
сравнивает QuestTask data+14 с int environment+40 через этот virtual getter.
Ни поле +40, ни числовые значения пока не названы region/world/instance enum.
Соседние environment+30/+50/+58/+5A не смешиваются с ним.

## Что делает конструктор и что остаётся неизвестным

Constructor вызывает 144286F50 с this+28. По статическому целому экспорту
helper устанавливает vptr 149493728, получает registry через 14429E590,
входит в critical section и вызывает 144283510, передавая this и byte 3.
Значение 3 — аргумент регистрации; оно не является доказанным environment+40.
Registry и возможные последующие callbacks ещё не исполнены и не разобраны.

В native Time replay исполняется целый constructor, exact global getter и
оригинальный virtual getter. Вызов base registration helper остаётся явной
fixture: проверяет receiver this+28 и возвращает его, без callback обработки.
Перед constructor память заполнена A5. После него поле +40 сохраняет A5A5A5A5.
Это проверка footprint только при указанной fixture, а не утверждение о
неинициализированной памяти настоящего клиента. Реальный registry callback
может менять состояние; фактическое значение нужно проследить дальше.

## 34 совместных сценария

Сохраняются [task/data и RunInInstance](HEADLESS-QUEST-TIME-TASK-BINDING-11316.md)
и вся Time callback/start/tick/timer/completion цепочка. Вместо environment
provider и virtual kind callbacks теперь используются native constructor,
global load и оригинальная vtable с exact getter. В каждой case проверены
return this, global binding, primary vtable и один вызов registration fixture.

Для проверки ветвей environment+40 затем задаётся явно: 3 либо 4 для mismatch,
как и прежний synthetic data+14=3. Это значения теста, не живые показания;
[загруженный QuestTask](HEADLESS-QUEST-TASK-BASE-DEFAULT-11316.md) имеет начальный 0.
Открытые/закрытые условия, null record/data, смена record state и fallback
model virtual+30 сохраняют ожидаемые результаты. 34 сценария прошли.

Артефакт: `code-clues/quest-time-gates-11316/aa5828ca42049944eecc25ef3c930055815f5ed87fc72b3190abcb9685e369ce/manifest.json`.
Check: `native-quest-time-gates-11316`, тест `test_vampir_quest_time_gates_11316.py`.
Model lookup, registration helper, окружение, JSON/string, прочие timers,
property bag, completion sink и fallback model virtual+30 остаются fixtures.
`network_used=false`, `action_admitted=false`.

Следом — source registry callback / запись environment+40 и поздние записи
QuestTask data+14. Адаптер реального шага не должен копировать synthetic 3/4.
Онлайн-сессия не перезапускалась и игровых команд не получала.
