# ChannelManager silent: переход к Auth и обязательный player ID

19 октября 2026. Продолжение [игрового AutoSignIn](HEADLESS-GAME-AUTO-SIGN-IN.md).
Источник — код собранного Windows клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источник и воспроизведение

[replay-channel-silent-handoff.py](replay-channel-silent-handoff.py) создаёт
`F:/PhoneExit Resources/Vampir/code-clues/channel-silent-handoff-replay.json`.
SHA256: `3615dc6f1bbf800d512f0b69a9cad790e6438d1db15dfce156ad08e7e8ae8ea0`.
Report сохраняет tool/source/upstream SHA, instruction bytes/file offsets,
полные unwind fragments, bounded support leaf и literal provenance.
Команда из корня: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-channel-silent-handoff.py`.
Capstone 5.0.6/Unicorn 2.1.4; budget 4096 instructions на сценарий.

## Подтверждённая цепочка

| Этап | Native source | Результат |
| --- | --- | --- |
| Сохранение callback | 0x1444feb4d → binder 0x1444ba4f0 | ChannelManager impl+0xd0 |
| Support gate | leaf 0x144517ef0 | Читает byte global 0x14b4f13f8 |
| Context gate | calls 0x144523ff0 / 0x144525630 | Null service shared pointer уводит в error branch |
| Сохранённый player | 0x1444fedf8 → 0x144524d80 | FString из settings CDO, fixture getter |
| GetAuth | 0x1444fee02 → 0x1445209e0 | Реальный getter возвращает service impl+0x150 |
| Передача callback | 0x1444fee32 и 0x1444fee5e | Две копии function storage; clone targets — fixtures |
| Передача в Auth | call 0x1444fee6b → 0x1444fdd00 | Auth impl, сохранённый player ID, callback descriptor |
| Auth callback binding | 0x1444fdda9 → binder | Auth impl+0xa8, отдельно от обычного SignIn impl+0x98 |
| Auth player gate | 0x1444fdf01 | FString count > 1 нужен для продолжения |

Точный diagnostic связывает target 0x1444fdd00 с FAuthImpl::SignInSilently.
Обычный FAuthImpl::SignIn 0x1444fb800 остаётся другим entry point.
Таким образом, различие service+0x170 (ChannelManager) и +0x150 (Auth)
сохраняется, но **переход из первого во второй теперь подтверждён**.

Поддержка задаётся явным fixture byte. Его реальная инициализация и выбор
конкретного провайдера ещё не восстановлены. Нельзя называть gate проверкой
готовности текущего реального аккаунта.

## Двенадцать native сценариев

Восемь channel scenarios: unsupported, uninitialized и шесть передач
callback absent/inline/heap × player empty/nonempty. В неподдерживаемом случае
stop 0x1444feb71, при null context stop 0x1444fec88 — до allocation error object.
Это исследовательские границы; полный error callback не исполнен.

При forwarding native ChannelManager возвращает AL=1 и передаёт player ID
без изменений, в том числе пустую строку. Marker callback в fixture сохраняется;
реального игрового function target этим не доказано. Bound callback проходит
две clone и две release операции, сами storage primitives заменены fixtures.

Четыре отдельных Auth gate scenarios исполняют entry 0x1444fdd00:

- Null context → stop 0x1444fdde4 перед error object, diagnostic Auth not initialized.
- Пустой player ID → stop 0x1444fdf0d перед error object, diagnostic No PlayerID.
- Один символ и обычный fixture ID → stop 0x1444fdfea перед request preparation.

Следовательно, возврат ChannelManager AL=1 — только факт передачи дальше,
а не успешная сессия. Для нового профиля без player ID silent-ветка не заменяет
первый вход с credential. Это ещё одна проверенная причина не использовать
внутренние bool-флаги как доказательство авторизации.

## Статическая часть и ограничения

В полном Auth fragment сохранены authUrl и v1/sign-in literals, request
preparation и HTTP call site. Эти части **не исполнялись** текущим replay.
Не утверждается, что silent и обычный sign-in имеют одинаковый полный body,
validation, callback или серверный контракт.

Реально исполняются ChannelManager function, support-byte/GetAuth getters
и отдельные Auth entry/context/player gates. Service context, settings CDO,
player getter, channel/auth binding и TFunction primitives — fixtures/captures.
Logging отключён fixture. Нет проверки provider selection, первого входа,
expiry/refresh, game Login, гонок или реального service lifecycle.
Игра, память процесса, профиль, реальные credentials и HTTP не использованы.

[Три regression tests](../../test_vampir_headless_channel_silent_handoff.py)
проверяют воспроизводимость, адреса перехода, callback/player forwarding,
ветви context/support и пустой player ID. Ещё шесть game callback/dispatch
тестов прошли. Runtime не менялся; последний полный suite — 316 тестов из
предыдущего runtime milestone, повторно не запускался.

Следующий шаг — связать успешный Auth silent response с callback impl+0xa8,
ChannelManager/game continuation и обычным credential-first входом.
