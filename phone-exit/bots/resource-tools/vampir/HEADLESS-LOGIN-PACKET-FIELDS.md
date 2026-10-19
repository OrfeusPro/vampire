# PktLogin: constructor, SDK getters и заполнение полей

19 октября 2026. Продолжение [VersionResult → Login](HEADLESS-VERSION-RESULT-HANDLER.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-login-packet-fields.py](replay-login-packet-fields.py) →
`F:/PhoneExit Resources/Vampir/code-clues/login-packet-fields-replay.json`.
SHA256: `2aa8eb8d34d07abcc3baa37a1a2c9d33b8a9b93fdd693a98fcab54f764836497`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-packet-fields.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report содержит source/tool/upstream SHA,
fragments/bytes/file offsets, два getter leaves, globals из decoded RIP refs,
diagnostic/platform literals и snapshots 16 scenarios.

## Исполненный участок

Native **0x1467a9700 → 0x1467a9b0b**, с остановкой до UI/post-send/cleanup.
Реально вызывается constructor **0x1456d4c80**, ставящий vtable **0x1498d6058**
PktLogin из [packet bindings](HEADLESS-PACKET-BINDINGS.md). Затем actual код
заполняет поля и доходит до **0x144aa8020** на **0x1467a9b06**.

На handoff проверены request-manager pointer, packet vptr, R8D4 и stack float0.
Getter request manager **0x144aa7c40** и сам handoff — captures. Это ещё
не доказательство transport send: writer/frame/queue/socket здесь не исполнялись.
Полный VersionResult replay не объединён с этим отдельным native Login run.

## Netmarble ID и SDK access token — разные поля

При включённом global SDK flag, ненулевом manager и manager+0x38:

- **0x145604b90** → cached getter **0x1444aacb0** → object+0x110 →
  **0x144524940**. Diagnostic буквально называет последний
  **UNMServiceSettings::GetNetmarbleId**. Он берёт FString из settings+0x4a8,
  native caller копирует result в **PktLogin+0x30**.
- **0x1456039c0** → cached getter **0x1444aab90** → object+0x110 →
  FString+0x78, через copy helper обновляет caller-context+0x58 и возвращает
  этот descriptor. Native Login копирует его в **PktLogin+0xa0**.

Второй путь связан с ранее найденным SDK token: response getter **0x1444bb470**
тоже вызывает **0x1444aab90** и возвращает object+0x110; response сохранял
`resultData.accessToken` в его+0x78. См.
[SDK response fields](HEADLESS-SDK-SIGN-IN-RESPONSE.md). Этот getter fragment
включён в новый report для проверки связи; сам response callback здесь не исполнялся.

Два cached getter globals **разные**, поэтому SDK module+0x78 нельзя подменять
settings+0x4a8 или player ID. Service/module/settings objects, cache globals,
SDK strings и initialized cached branches в replay заданы fixtures.
Ни реальные identifiers, ни token не читались.

Actual cached SDK getters и GetNetmarbleId исполняются. Low-level FString
copy/assign/constructor/resize остаются fixtures. Null object init helper
**0x1416aaaf0** capture не создаёт отсутствующий объект.

При отсутствии module getter0x1456039c0 может вернуть прежний context+0x58.
Два fixtures различаются только начальным кешем: empty → empty token field,
old-cache-fixture → тот же old value в Login. Это не свежая авторизация;
не считать наличие непустой строки подтверждением response/expiry/session.
Поведение copy helper при замене непустого кеша непустым token не проверено.

## Остальные подтверждённые переносы

| Packet field | Источник/поведение |
| --- | --- |
| +0x10 / +0x20 | wrapper+0xf0 / wrapper+0xe0, FString copies |
| +0x30 | GetNetmarbleId result, при SDK gates |
| +0x40 | FString global0x14b520d10 |
| +0x50 | DWORD global0x14b520cb8 |
| +0x78 | getter0x1445c63a0 fixture output |
| +0x88 | wrapper+0x100 FString |
| +0x98 | selector0/1/2/3/4 → byte0/1/2/3/5; 5/255 →0 |
| +0x99 | Android literal match →0, IOS →1, Windows fixture →3 |
| +0xa0 | SDK token accessor result, при SDK gates |
| +0xb0 | actual getter0x144aaaa10: peer=[wrapper+0x10], DWORD peer+0x270 |
| +0xd8 | collector0x145604bf0 fixture output, при manager+0x48 gate |
| +0xf8 | raw DWORD207 (0xcf) |
| +0x110 | char pointer global0x14b14ae28 → FString fixture |
| +0x120 | raw DWORD global0x14b125530 |
| +0x124 | byte policy getter result+0x18, fixture7 |
| +0x130 / +0x131 | separate policy-helper bool fixtures, SDK-dependent gates |

Peer+0x270 ранее связан с выбранным server ID через
[BeginGame setters](HEADLESS-BEGIN-GAME-SERVER-TARGET.md). В новом replay
actual getter читает fixture42; поле+0xb0 не угадывается по числу.
Остальные strings/flags не названы deviceID/playerID/country без getter evidence.
В частности selector mapping ещё не имеет доказанного enum name.

Platform getter, UTF-16 comparison и string primitives — fixtures. Source
литералы Android/IOS сохранены с offsets. Проверены ровно эти сравнения;
case folding/политика общего OS getter и Android execution не заявлены.

## Проверки и ограничения

16 native scenarios: Windows/Android/IOS fixture, selectors1/2/3/4/5/255,
SDK-disabled, manager-absent, auth-absent, module-absent, settings-absent,
empty SDK fields и module-absent с прежним token cache.
[Три regression tests](../../test_vampir_headless_login_packet_fields.py)
перестраивают report, проверяют ctor/getter/diagnostic source links, отдельные
NetmarbleId/token fields, platform/selector bytes, server/raw values,
request kind/timeout, SDK gates и старый кеш.
Три новых и шесть смежных tests VersionResult/SDK completion прошли.

Тестовые SDK values не являются настоящими credentials. Runtime не менялся;
полный suite379 не повторялся. Игра/profile/process memory/network не использованы.
Не исполнены init fallback, string internals, collector/policy backends,
request handoff/transport, Login writer, post-send UI/cleanup и server LoginResult.

Далее Login writer/encoding и handoff0x144aa8020 → transport send. Отдельно
остаются реальные device/profile inputs и полный SDK response→Login dataflow.
