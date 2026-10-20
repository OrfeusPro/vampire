# LobbyLogin: preparation до отправителя и последний байт 7

20 октября 2026. Продолжение [writer и источников SDK / NID](HEADLESS-LOBBY-LOGIN-WRITER.md).
Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

Использован текущий Ghidra export из `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`,
331 функция / 151 предупреждение. Нового экспорта не потребовалось.
Восстановленный псевдокод preparation 0x1467a9360 сверён с исполнением;
constructor leaf 0x145744fa0 взят из подтверждённого direct call и проверен
декодированием до RET без переходов / calls. Его bytes / file offset / SHA
сохранены вместе с selected-server getter leaf 0x144aaaa10.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-login-preparation.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_preparation.py -v
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/lobby-login-preparation-replay.json`.
SHA256: `e962f61e34d7c700d02936cac07be101fdda3b4640977484f8b64fccfe0e5808`.
Содержит source / tool / inherited tool SHA, fragments и leaves, 16 fixtures
и snapshots packet на входе в sender. Capstone 5.0.6 / Unicorn 2.1.4 вне runtime.

## Исполненная область и результат

Настоящая функция 0x1467a9360 выполняется с начала до входа в sender
0x144aa89b0. Реально исполняются constructor, присвоения полей, SDK / NID
guards, selector expression и selected-server getter. Остановка на sender:
сам sender, destructor и сеть не исполняются.

Version global flag 0x14b520cc9 задан false, как в ранее полученном настоящем
LobbyVersionResult. Дополнительная ветвь разбора numeric text при true
в этот replay не входит. SDK / NID getters, platform selector, collector,
FString helpers / allocation / diagnostics — явные ограниченные fixtures.
Реальные аккаунты / tokens / профиль игры не использованы.

| Packet field | Проверенный результат |
| --- | --- |
| uint32 +0x10 | 2 при selector 3; 1 при проверенных остальных selectors |
| uint32 +0x14 | 2 при wrapper kind 2; 0 при проверенных других kind |
| uint32 +0x68 | точный dword game peer+0x270 через настоящий getter |
| uint32 +0x6c | 0 из constructor при выключенном Version flag |
| raw byte +0x80 | **7** из constructor, сохраняется до отправителя |

Constructor содержит `mov byte ptr [rcx + 0x80], 7` на 0x145744fa7.
Это raw byte, его смысл пока не именуется bool или enum. Предыдущий encoder
уже сохранял произвольный byte; теперь установлено значение этой preparation
ветви. Числа kind и server ID в harness — fixtures, не доказанные начальные
значения живого клиента. Автоматический выбор 0 из этого replay не следует.

Сценарии: selector 0 / 1 / 2 / 3 / 4 / 255; kind 0 / 1 / 2 / 3 / uint32 max;
server ID 0 / 42 / uint32 max; отдельное отключение SDK, manager, auth и NID info.
Это 16 комбинаций, не декартово покрытие всех возможных состояний.

В SDK / NID fixtures нормальный packet получает пять уже связанных строк
и явную collector string. При отсутствии NID info пусты country и metadata,
а отдельный NID из SDK auth остаётся. При отсутствии SDK auth сохраняются
global player text / прежний wrapper token; NID info имеет отдельную ветвь.
Такие fixture snapshots не заявляются пригодными для настоящей авторизации.

## Runtime

`make_windows_lobby_login(version_result=..., kind=..., selected_server_id=..., metadata=...)`
проверяет отдельный успешный LobbyVersionResult и flag +0x14 == false.
Возвращает явный LobbyLoginPayload с integers `(2, mapped_kind, server_id, 0)`
и raw byte 7; metadata сохраняется, первые пять строк оставляются SDK binder.

Kind, server ID и metadata обязательны в вызове. Builder не наблюдает их
и не задаёт defaults. При включённом флаге требуется отдельная обработка
numeric context; эта ветвь явно не поддерживается. Ненулевой version result
отклоняется как локальная политика владельца. IO и отправки внутри builder нет.

Четыре новых теста воспроизводят 16 native scenarios, проверяют numeric fields,
raw byte, SDK / NID guards и builder. Также прошли четыре writer / binding,
четыре lobby codecs и шесть Login context tests — всего 18 проверок.

Далее — наблюдение kind / выбранного сервера в lifecycle собственного клиента
и полная сборка metadata по NID UserInfo, затем связанный LobbyLogin / ответ.
Настоящий вход в лобби, список серверов ID 104, игровой Login, персонажи и
позиция остаются следующими этапами. Новых сетевых попыток здесь не было.
