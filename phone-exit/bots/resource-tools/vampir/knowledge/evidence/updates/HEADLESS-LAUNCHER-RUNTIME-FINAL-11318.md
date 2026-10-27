# Launcher runtime: финальный кэш пакета CharacterList 1.13.18

[Первичная проверка launcher](HEADLESS-LAUNCHER-RUNTIME-11318.md) сохранена
как отдельный результат. После переноса общих CharacterList harness scopes
SDK-пакет пересчитан один раз на новых зависимостях; смысл scope не расширялся.

Источник EXE:
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Текущий SDK runtime manifest в библиотеке ресурсов:
`sdk-source-profiles/4c8057b367524bc26e226088f5f5ef790309f82b8c81af90ffd7e829acdcd4d2/manifest.json`.
Общий SDK report:
`knowledge/sdk-batch-verified-11318/084b88caf38b6a291b73216b441c6b3b177348222b3584f6824bc16adb349d9e/manifest.json`.
Корень библиотеки — `F:/PhoneExit Resources/Vampir/`.

Оба digest совпадают с именами content-addressed каталогов. Builder повторно
воспроизводит manifest, loader закреплён на этот полный SHA и current source.
Исторические manifests не удалены; автоматического fallback нет.

В runtime check добавлены зависимости `audit-client-release.py` и
`bot_device_settings.py`: изменение canonical / snapshot logic или применения
настроек устройства теперь инвалидирует результат. Независимый review сверил
guards, source scope и CRT / locale; прямые SDK-операции current SHA
отклоняются до browser capture. Семь integration tests прошли повторно.

Область профиля — только `sdk-launcher-auth`, flow только `launcher`.
`network_ready`, `game_protocol_verified`, `direct_sdk_operations_verified`
и `active_runtime_settings_verified` остаются false. HTTP / browser executors
подставлены; настоящий backend, авторизация и серверная сессия не проверены.
Подключение SDK manifest отдельно от активации игрового профиля и baseline.
