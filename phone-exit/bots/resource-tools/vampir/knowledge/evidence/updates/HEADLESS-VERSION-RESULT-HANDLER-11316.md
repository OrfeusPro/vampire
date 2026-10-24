# VersionResult 1.13.16: регистрация, handler и переход

24 октября 2026. SHA256 Windows-клиента:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [текущего reader](HEADLESS-VERSION-RESULT-11316.md).

## Проверенная цепочка

Окно `1467b4c8b..1467b4cd4` внутри owner `1467b4c60` создаёт handler с table
`149dc6690`, packet размером `28` через constructor `1456d7c90`, затем передаёт
packet/handler в register `1467cb6c0`. Table packet `149926d68` содержит actual
ID getter `14148a940` → 2. Handler slot `+10` указывает на `14679d1b0`.
Окно проверяется по source bytes, SHA и инструкциям; весь oversized owner
повторно не экспортируется и не исполняется.

Handler получает ID виртуальным вызовом, передаёт result из packet `+10`, ID 2,
нулевой временный struct и `R9D = 0` в actual gate `1467cd7b0`.
При принятии вызывает peer getter `144ab0c40`, восстанавливает stack/RBX и
tail-переходит на current Login prepare `1467ce030` с peer в RCX.
Это та же привязка prepare, которая исследована в
[whole Login](HEADLESS-LOGIN-PREPARE-11316.md).

14 native сценариев: codes 0/1/42/58/708/1304/ffffffff × state flag 0/1.
Только code 0 достигает Login prepare; остальные завершают handler.
При flag 0 ошибки, кроме 42, вызывают capture error service с исходным code
и policy 0; при flag 1 error service не вызывается. Проверены gate arguments,
нулевой temporary, порядок событий, неизменность packet, guards и ABI.

## Воспроизведение

[Context](../../native-contexts/version-result-handler-11316.json),
[verifier](../../../verify-version-result-handler-context.py),
[три теста](../../../../../test_vampir_version_result_handler_context.py).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_result_handler_context.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-result-handler-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-result-handler-11316.json
```

Новый export handler — `run-74fac8b21253`; gate из `run-eff5f37ca91c`
использован повторно. E9 → prepare объявлен collector как tail call на явно
заданный root. Исходные инструкции и unwind bounds не менялись.
Report: `F:/PhoneExit Resources/Vampir/knowledge/native-version-result-handler-checks/b76cdc39c1f96f8e2579620a72fa3cf417379e00f739687c3367de38ee841723/manifest.json`.
SHA source, exports, tool и context сохранены в машинных результатах.

## Границы и обновление

Packet synthetic; state getter, peer getter, строки, log/error services — fixtures.
Login prepare захвачен на входе, его тело в этом replay не исполняется.
Reader и handler здесь ещё не объединены одним packet/dispatch replay.
Другие коды gate, UI эффекты ошибок, настоящая регистрация и состояние peer
не подтверждены. Живой Game Login и создание персонажа не выполнялись.

Check `native-version-result-handler-context` связан с `game-version`.
Для следующей сборки нужны новые подтверждённые constructor/table/registration,
handler/gate/callee и tail target; одного совпадения тела недостаточно.
Профиль и baseline автоматически не активируются. Далее — объединённый путь
reader/handler и оставшиеся зависимости игрового профиля для живой проверки.
