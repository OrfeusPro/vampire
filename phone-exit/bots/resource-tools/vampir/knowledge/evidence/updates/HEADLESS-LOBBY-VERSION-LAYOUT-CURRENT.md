# Текущий lobby VersionResult: восемь операций чтения

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Использованы готовые экспорты из [пакета clock / lobby](HEADLESS-ENTRY-COLLECT-CURRENT.md),
без новой JVM. Новый вопрос / check `lobby-version-layout-current` выделен
из большого незавершённого world-пакета.

Три целых native функции: constructor `0x145749a50`, reader `0x14574f5d0`
(60 инструкций) и handler `0x1467aeb30` (47 инструкций). Дополнительно исполняется
ранее найденный 111-байтовый setter clock. Reader делает восемь последовательных
операций: u32, bool, два TimeBase, u16, FString, u32, u32. Проверяется результат
каждого чтения. Поля назначения — `+10/+14/+18/+28/+38/+40/+50/+54`.

Три полных payload, 114 коротких префиксов, 24 явных отказа операции и шесть
ветвей metadata validate true / false подтвердили порядок и остановку reader,
передачу новых полей, пустую строку при false и clock setter. Archive scalar /
TimeBase / FString и новые metadata validate / apply, managers, peer continuation
остаются явными fixtures. Это не полное исполнение wire-примитивов или metadata
consumer; состояние UI manager в стенде равно 2.

`decode_current_lobby_version_result` требует точный SHA и возвращает отдельный
`CurrentLobbyVersionResultBody`: прежний 23-байтовый префикс, строка с u16 длиной
в UTF-8 байтах и два u32. Точная длина и строгий Unicode — локальная политика.
Новые поля остаются `raw_40/raw_50/raw_54`, их смысл не придуман. Старый decoder
и старый binder сохранены; binder отклоняет новый тип, чтобы не отбросить поля.

Проверка зарегистрирована в `MODULES`, отдельной tooling-группе и контракте
`game-login` с `on_update`. Cache key учитывает context, source-checked export,
helpers и версии Capstone / Unicorn. Полный текущий game-login / clock / world
candidate и metadata consumers остаются открыты. Нового runtime допуска нет.
