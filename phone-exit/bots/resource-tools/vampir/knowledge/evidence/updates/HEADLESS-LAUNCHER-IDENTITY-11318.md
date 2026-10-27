# Launcher 1.13.18: поля игрока и SDK context

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [response callbacks](HEADLESS-LAUNCHER-RESPONSE-CALLBACKS-11318.md).
Авторизация, новый runtime profile и игровые действия не запускались.

## Проверенный путь

В одной VM исполняются целый sign-in callback `1444D3A30`, SDK context getter
`1444C2010` и country setter `144552560`. Полнота трёх unwind roots проверяется
по исходным инструкциям, blocks, direct flow и conditional fallthroughs.
Диагностика выключена. Getter получает manager от fixture singleton; при пустом
manager+110 вызывает fixture initializer, после чего возвращает manager+110.

Дополнительно исполнен constructor leaf `1444C2F20..1444C30B2`: 403 байта
закреплены буквально и сверяются с полным SHA EXE. Это линейный участок без
CALL/JMP/условных переходов, заканчивающийся RET. Полный native constructor
записывает ключи playerInfo/player/playerId/playerStatus/gameRegion/idpInfo/
joinedCountryCode в owner+20/28/30/38/40/48/50. Экспорта Ghidra этого leaf нет;
его проверка отдельная, а не объявление его unwind root.

Новый явный экспорт `run-7ecda68a9805/details.json`, SHA256
`2b6c4eb8f049945e94e9ba4987f3bd4b0c45313c277db66113c59b375928f6c8`,
также сохраняет player setter, Save и Load для следующего шага. Их тела в
этом replay не исполняются. Callback взят из прежнего `run-e3abc26162e7` с
SHA256 `0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42`.

## Сорок сценариев

20 вариантов повторены для готового и лениво инициализируемого context:
нет resultData; только accessToken; нет player; 16 комбинаций наличия
accessToken/country/region/playerStatus при наличии playerId; пустые поля.
HTTP 200, валидный JSON и отсутствие errorCode заданы fixtures. Ошибочные
статусы и SDK errors остаются в предыдущей проверке 74 сценариев.

| Поле | Native назначение |
| --- | --- |
| resultData.accessToken | FString assignment на SDK+78 |
| player.playerId | player setter с flag=0, затем Save(settings), Load(SDK) |
| player.joinedCountryCode | native country setter с flag=0, storage helper на SDK+210 |
| player.gameRegion | FString assignment на SDK+68 |
| player.playerStatus | отдельный object consumer, затем follow-up consumer |

При отсутствующем поле старое значение сохраняется; явная пустая строка
передаётся дальше. Нет player — нет player setter / Save / Load. Эти три
операции сохраняют порядок. Для каждого варианта callback один раз передаёт
исходную response pair dispatcher capture; weak strong count возвращается к 2.
Наличие resultData без player не является доказательством успешного входа.

## Границы и автоматизация

HTTP, JSON parse/presence/getters, глобальные ключи resultData/accessToken,
FString операции и запись country member — fixtures. Member keys берутся из
настоящего constructor. Отдельная привязка global accessToken initializer ещё
нужна: известный кандидат `1411AF990` пишет другой global `14B5641D0`, поэтому
он не принят как доказательство ключа `14B563C60` в callback.

Player setter, Save, Load, singleton, initializer, post-sign-in events и
dispatcher — captures. Replay не доказывает запись на диск, свежесть SDK,
JSON type policy, непустой токен, доставку callback движком или live auth.
idpInfo отсутствует во всех fixtures и остаётся неизвестным. Проверка
настоящего dispatcher/cleanup сохранена отдельно; здесь она не повторяется.

Runner `replay-launcher-identity-11318.py`; unittest
`test_vampir_launcher_identity_11318.py`: два теста прошли, 40 native сценариев.
Артефакт в библиотеке ресурсов:
`code-clues/launcher-identity-11318/153954c34c847b45f11305766562d9b5b06da1ad39326da78e03e37928f31ab0/manifest.json`.
Check `launcher-identity-11318` сразу включён в `on_update`; полные зависимости
и оба Ghidra artifacts входят в cache key. Reviewed functions добавлены в
`launcher-fields-callbacks` с ограничениями. Поддержка нового SHA или runtime
activation из этого не следует.

Далее проверить global key initializer, реальные JSON getters и SDK settings /
GMC2/NID нового SHA, затем собрать профиль. Не повторять эти 40 сценариев
вручную при неизменных входах: штатный workflow использует hash cache.
