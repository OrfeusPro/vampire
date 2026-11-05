# Композиция VersionResult текущего клиента

Target EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Последняя проверенная база handler — 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
[Машинная квитанция](AUTO-VERSION-RESULT-FLOW-CURRENT.json) закрепляет контекст,
native результат, source check и неизменный повтор.

## Выполнение

Обработчик `0x1467a0610` перенесён в `0x1467a0660`. Сверены все 42 инструкции
с обоими EXE, direct call roles, ID 2, packet constructor и handler table.
Окно регистрации содержит 75 байт; его инструкции и связи проверяются статически.
Для обработчика получен один новый Ghidra export. Готовые input / result gate /
Login exports переиспользованы. Финальный scoped collect использовал три готовых
материала, новых JVM — ноль.

Общий context-driven verifier исполняет native reader → handler → result gate.
Проверены восемь кодов ответа при двух значениях state flag: 16 сценариев.
Проверки контролируют потребление 17 байт input, неизменность packet / canaries,
аргументы и порядок событий, Win64 nonvolatile GPR и XMM6–XMM15, стек и Login handoff.
Для `0x1197` при flag 0 сохраняется фактический переход gate; это результат
native fixture, серверный смысл кода и runtime error policy этим не меняются.

Текущие standalone input / gate отчёты использованы после проверки точных SHA,
полноты матриц, runtime и transfer proofs. Их отдельные native матрицы не повторялись.
Shared input constructor fixtures исполняются внутри новой композиции.

## Обновление и повтор

В `game-version` зарегистрирована привязка `result-handler` текущего SHA.
Source variant `native-version-result-handler-context` использует
`test_vampir_version_result_flow.py`, 64 зависимости и восемь исходных artifacts.
Обычный dispatcher `on_update` направляет его через `version-result-flow-guard.py`:
guard проверяет context и выбранные dependency / transfer proofs до и после
проверки, включая попадание в кэш. Повреждение proof останавливает повтор.

Четыре source-bound теста и две новые проверки guard в tooling прошли.
Общий tooling: 27 групп, 2056 обнаруженных случаев, четыре skips.
Неизменный вызов штатного dispatcher завершился за 0,542 с. Запуск дочерних
процессов был запрещён assertion-проверкой; новых native исполнений / JVM — ноль.

Контекст текущего SHA и проверка подключены к обновлению и кэшу. Генерация этого
composition context для следующего неизвестного SHA остаётся открытой:
новые source pointers требуют проверенного переноса и собственного результата.
Одно наличие текущей привязки не добавляет поддержку будущего EXE.

## Границы и продолжение

Dispatcher delivery не исполняется. State / string / logging / error services
и peer имеют явные fixtures. Login preparation перехватывается на входе;
его выполнение и отправка Login в этой композиции не проверяются.
Сетевые запросы не выполнялись, профиль не активирован, вход онлайн не подтверждён.

Из трёх пакетов пробелов прежнего ограниченного candidate этот пакет закрывает
VersionResult handler / gate. Остались CharacterList / выбор и clock / Ping /
ограниченный вход в мир; затем связывание готовых proofs с candidate и runtime
composition. Создание Carnage и HP / MP сохраняют собственные source guards.
Полная очередь world-session не становится обязательной для прежнего bounded candidate.
