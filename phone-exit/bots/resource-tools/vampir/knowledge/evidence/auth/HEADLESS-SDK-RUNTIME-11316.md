# SDK runtime profile для launcher 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [GMC2 geo](HEADLESS-GMC2-GEO-11316.md) и
[сборки кандидата](HEADLESS-SDK-PROFILE-11316.md).

## Что подключено

`build-sdk-runtime-profile-11316.py` собирает отдельный профиль для явного
launcher flow. Прежний кандидат и его доказательства сохранены. Сборщик проверяет
установленный EXE, шесть SDK reports (739 случаев), NID base (32), NID actual
helpers (1124), geo (672), полные SHA их зависимостей и Ghidra evidence.
Дополнительно выполняется [launcher source audit](HEADLESS-LAUNCHER-CONTRACT-11316.md).
CRT DLL и locale должны совпасть с NID helper report; locale не изменяется.

Профиль находится вне Git:
`F:/PhoneExit Resources/Vampir/sdk-source-profiles/d4b562f9f774833843ddf08f7b867c0ae732dff6fb46ee29b4ba2ad9fcb027be/manifest.json`.
SHA файла равен имени каталога; размер 623788 байт. `sdk-source-profile.py`
закрепляет полный SHA manifest и EXE, проверяет фактически установленный файл.
Старый профиль не используется как fallback.

Область профиля — `sdk-launcher-auth`, supported auth flows — только `launcher`.
`network_ready`, `active_runtime_settings_verified`, `game_protocol_verified` и
`direct_sdk_operations_verified` остаются false. Настройки начального real
окружения, отсутствующего NMENV, PC / webview type 0 и английского языка заданы
явно. Активное состояние запущенного клиента этим не определяется.

## Проверка цепочки без сети

`test_vampir_sdk_runtime_11316.py`: шесть тестов. Использованы настоящий pinned
loader, проверка установленного EXE, XOR / JSON GMC2 decoder, NID context / URL и
оба launcher request planners. Входные registry / device observation, HTTP,
browser callback и ответы SDK — синтетические fixtures. Ни auth endpoint,
ни игровой сервер не посещаются; реальные учётные данные не читаются.

Один свежий GMC2 body даёт constants и geo; route остаётся одним для обоих
SDK запросов. `launcher/token` получает provider credential, следующий
`launcher/sign-in` — отдельный launcherToken header. SDK DeviceKey отличается
от NID DeviceKey в URL браузера. Проверены reproducible manifest, повреждённый
report, изменённая dependency и запрет direct SDK операций до browser.

Сохраняются account / profile / route / source / age guards. После получения
launcher token добавлена повторная проверка контекста: превышение локальных
300 секунд останавливает второй POST. Это локальная политика, не SDK timeout.
Ранее существующие проверки также прошли: GMC2 runtime 5, release profile 5,
NID SDK runner 9, GMC2 context 6.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-sdk-runtime-profile-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_runtime_11316.py
```

Check `sdk-runtime-launcher-11316` связан с вопросом `sdk-profile-assembly`,
полным SHA, кодом runtime / сборщика, exports и CRT DLL / locale. Ориентиры
следующего обновления сохранены в `release-update-targets.json`: использовать
известные SDK / NID / geo / launcher targets, перепроверять изменённые источники,
не продвигать runtime автоматически по совпадению адреса или строки.

## Что ещё нужно

Direct SDK sign-in / fetch / sign-up / terms на текущий SHA ещё не перенесены;
runner отклоняет эти операции до открытия browser. Они не заменяются launcher
flow автоматически. Требуются отдельные source checks, включая ответы и условия.

Игровой source profile пока относится к прежним сборкам: список / выбор
персонажа, подключение к миру и позиции новой версии требуют отдельной сверки.
Живой launcher вход и принятые сервером значения не подтверждены. Пользователь
сообщил о недоступности серверов; повторные входы в этой проверке не выполнялись.
