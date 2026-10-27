# Launcher runtime 1.13.18: профиль и ограничения

Источник EXE: `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Проверка offline, авторизация и игровые команды не выполнялись.

`audit-launcher-contract-11318.py` проверяет полный SHA, четыре сохранённых
Ghidra exports и 14 целых roots: десять инициализаторов ключей, два запроса
и два обработчика ответа. Сверены фактические инструкции / границы, аргументы
конструкторов строк, ключи / endpoint / callback / transport и result dispatch.
Отдельные штатные native checks исполнения JSON/HTTP/callback сохранены.

`build-sdk-runtime-profile-11318.py` использует общий кэш SDK: 3667 cases
и 288 helper cases из предыдущего пакета, без повторного native replay.
Девять компонентных reports публикуются для существующего сборщика профиля.
Проверяются установленный EXE до / после, SHA reports и CRT / locale.
Повреждённые материалы не принимаются как актуальные.

SDK loader закреплён на manifest
`f2c572a0999b330a6de86e31fe7cf4eab71cbcc888f0875897a9198d8ba4f7c5`
в `F:/PhoneExit Resources/Vampir/sdk-source-profiles/`.
Область — только `sdk-launcher-auth`, supported flows — только `launcher`.
`network_ready`, `game_protocol_verified`, `direct_sdk_operations_verified`
и `active_runtime_settings_verified` равны false. Игровой профиль и baseline
не переключены. Старый manifest сохранён, fallback на него отсутствует.

Семь интеграционных тестов используют реальные декодеры GMC2/XOR и построение
обоих launcher plans, подставные HTTP/browser executors и отдельные device keys.
Проверены разделение credential / launcherToken, один SOCKS route, истечение
контекста до второго POST, отказы при изменении EXE / component / manifest.
Прямые SDK-операции для нового SHA теперь отклоняются до browser capture;
при первом прогоне обнаружено и исправлено отсутствие этого ограничения.
Четыре статических теста проверяют контракт и отказы при повреждении источника,
экспорта или неполном составе roots. Все 11 тестов прошли.

Оба checks включены в `on_update`; `source_variants` выбирают новый тест по
полному SHA, исторические тесты и audits не переименованы в доказательства
новой версии. Штатные результаты в библиотеке:

- `knowledge/check-results/ce58e137fa38cddaa2d0202d47a792f88332fdc43d7cd1f8fe15b6c07c8bfd58/manifest.json` — source contract.
- `knowledge/check-results/ffdc017b4aa1196ad6aa2f82f3235aee786df3ec8be4f26ab7ef192ff365bc14/manifest.json` — runtime path.

Это доказательство ограниченного локального пути, не серверного входа.
CharacterList, clock / prepare-to-wire, игровой профиль, настоящий браузер /
SDK backend и устойчивая онлайн-сессия остаются отдельными проверками.
