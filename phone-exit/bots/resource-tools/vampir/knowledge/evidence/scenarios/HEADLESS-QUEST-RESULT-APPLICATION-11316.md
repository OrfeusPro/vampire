# Registered 1811: результат → ключ/state/progress → модель

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Final request: `0499c736b95096495ed2e36a08c901fc227f2d183e1cf98791c3b3bcc523d4b7`.
Связано с [wire 1811](HEADLESS-QUEST-UPDATE-RESULT-11316.md).
Полные SHA exports — в `knowledge/native-contexts/quest-result-application-11316.json`.

## Registration и границы выгрузки

Точный ctor E8 call 1467BA0D1 →145828B50 находится в root 1467B4C60.
Его whole export отклонён до Ghidra по существующему unwind range budget;
лимит не расширялся и та же попытка не повторялась. Вместо этого проверяется
явное source окно 1467BA0B0..1467BA0E9: LEA handler table149DC9078, vptr store,
packet allocation48, ctor, R8 handler/RDX packet/RCX dispatcher и registration
call1467CB6C0. Все ключевые bytes фиксированы; окно полностью декодируется,
но не объявляется целой функцией или выполненным dispatcher setup.
Handler table slots: 1414096C0 /14153B9D0 /1467B27A0.
Это static binding установленного клиента, не доказательство live registration.

Первый handler export был отклонён Ghidra: tail E9 в1467B27E9 выходит из
unwind range к145D81C10. Новый request явно включил эту цель; collector сохранил
проверенную CALL_RETURN metadata. EXE и unwind не менялись. Успешный export
run-a2c85605edb8 содержит handler/wrapper, run-73ea3887aad5 — application145D92510;
общий gate1467CD7B0 уже был в run-eff5f37ca91c.

## Что выполняется

Целые handler1467B27A0, gate1467CD7B0, wrapper145D81C10 и dispatch145D92510.
Exact model getter1455BE4B0 и packet ID getter1458344B0 исполняются как leaves.
Handler получает ID через packet virtual+28, передаёт code packet+10 и ID1811
в gate с пустым diagnostic value и flag0. При true получает current model и
вызывает wrapper; при false application вообще не вызывается.

Wrapper передаёт key=packet+18, state byte=packet+20, nested pointer=packet+28
и flag1 в145D92510. Эта функция вызывает прежнюю progress projection145DE4610,
ищет model record по тому же key и выбирает model virtual+48 при missing record
или +50 при existing. Передаются тот же state, projected progress и flag1.
Тем самым raw qword+18 связан с quest key, а byte+20 с state применения.
Это не полный39-byte QuestRecord; дополнительные поля исходного списка из
ответа1811 не выдумываются.

## 192 сценария

Result0/10/FFFFFFFF/1197 × два explicit setting modes × existing/missing ×
keys110120/UINT64_MAX × state0/2/6 × progress index0/5. Projection fixture
проверяет exact key/nested pointer и возвращает bounded projected progress;
virtual callbacks проверяют точные fields/receiver/flag и порядок.
Input packet/model/record/settings неизменны, guards сохранены.

Результат0 допускается в обоих режимах. Code10 и FFFFFFFF не допускаются.
Code1197 допускается при setting+8 !=1, после error presentation; при setting+8=1
допускается только0. Смысл самого setting и code1197 не установлен; runtime
confirmation не должна считать каждый true gate синонимом успешного действия.
Счётчики, type/index внутри nested progress читаются ранее проверенным wire,
здесь projection заменена явной fixture; её whole lookup/loader доказательства
не выдаются за выполненные вместе с этим handler.

## Fixtures и следующий шаг

Gate setting getter145594DB0, error presentation145FD3EE0, projection145DE4610,
model lookup1455BBCB0, new-record wrapper145DE3790 и virtual application callbacks
остаются fixtures. Native selected-task replacement/lifecycle не исполняются;
model callback не меняет реальный task state. Все неизвестные gate ветви не
покрыты этими четырьмя codes. No network/process commands, live session preserved,
`action_confirmation_admitted=false`.

Для применения live decoder теперь есть source-bound key/state/progress layout,
но ещё нужны явный runtime receipt и корреляция с отправленным quest/index,
условия selected-state/actor position и владельческий pump. Сначала подключить
наблюдение1811 и проверять прогресс/ошибку отдельно от sent; затем один
ограниченный live action без автоматического повтора. Реальные многосессионные
аккаунты, движение/диалоги/обучение общей цели этим результатом не закрыты.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_result_application_11316.py
```

Tool `replay-quest-result-application-11316.py`, check
`native-quest-result-application-11316`.
Артефакт: `code-clues/quest-result-application-11316/9517f187c527b58dc6b298f01bc00d8bee6806f4de8c4b79307ed9ffd5baacb0/manifest.json`.
