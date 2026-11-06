# Viper factory и отдельный допуск создания

Источник EXE SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Пакет `viper-creation-current-v1` связывает шесть source-bound proofs,
[producer / JSON](HEADLESS-CREATE-PRODUCER-CURRENT.md), writer / result / handler,
явный appearance candidate и ClassInfo. Текущая Class CSV взята из готового
resource baseline нового pakchunk1 с полной проверкой SHA архива и CSV blob.

Выбрана строка DarkMage `Id=1`, `Type=1`, `DefaultGender=1`, preset 1.
Явный F-кандидат даёт десять байтов `[1,1,0,1,2,1,1,0,0,1]`, JSON keys
`1..7` со значением 0.5 и `VoiceType=1`, пустые items и flags 0/0.
Имя передаётся при запуске. Serialized и model значения, исходные unknown,
название `Cheat` и числовая группа `Chest` сохраняются раздельно.
`model_only=true`, `verified_loaded_asset=false`, `runtime_admitted=false`.
Фактическая внешность загруженного экрана этим не подтверждается.

## Командный запуск

Отдельный `bounded-create:<SHA>` закрепляет immutable entry profile,
factory, установленный EXE, patch manifest и все runtime consumers.
Стандартная библиотека проверяет SHA до активации. Capability допускает
только текущий `character-create-current-v1`, вложенный родитель разрешает
SDK / лобби / список. Мир, квесты и stats этим не включаются.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-bounded-creation-current.py
python -X utf8 phone-exit/bots/vampir-headless/run-bounded-create.py --account $accountId --profile $createSelector --output $privateReport
```

Команда использует credentials и назначенный сервер существующей панели.
Устройство и почтовые формы обрабатываются родительским входом в том же
SDK контексте. Factory вызывается только после успешных Login и свежего
пустого CharacterList того же соединения. Непустой список Create не запускает.

До постановки Create сохраняются принятый пустой список, предложенное имя
и постоянная попытка. Полное тело валидируется до журнала. После неизвестного
исхода слепой повтор запрещён. В успешном ответе используются возвращённые
имя и ключ, даже если серверное имя отличается от предложенного.
Отдельное чтение списка после попытки сверяет ключ и назначает свежий слот.
Старый список, полученный до Create, не сохраняется с новой датой результата.
Вход в мир требует следующего отдельного допуска.

Проверены четыре теста factory, четыре теста допуска / codec / журнала
и три теста настоящего профиля с локальными runner fixtures. Сеть в этих
проверках не используется. Один Create, свежая identity, потеря соединения,
сохранение unknown после открытия БД заново и запрет повторной отправки
покрыты отдельно. Прежние flow и journal cases сохранены.

`viper-creation-current` и `bounded-creation-current` включены в `on_update`,
частичный `character-create`, общий tooling и проверку кэша.
Успешный онлайн Create и постоянная игровая сессия пока не подтверждены.
