# LobbyLogin: полный writer и источники SDK / NID

20 октября 2026. Продолжение [настоящего LobbyVersionResult](../../../../../vampir-headless/LIVE-LOBBY-VERSION.md).
Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Ghidra 12.1.4: 331 функция, 151 сохранённое предупреждение.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-3584658f8dad`.
Manifest SHA256: `635912b93700eac9691841486c58ee1ac4bac1e00c0de234da9811a2cb46b6f8`.
functions.json SHA256: `c3b206efff28c03acb373378e2efa53fa639070d11738e8b048638481d5521de`.
Использованы прежние preparation / writer, затем экспортированы семь функций
SDK player accessor / settings и NID UserInfo / collector / field selection.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-login-writer.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-lobby-nid-input-index.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_writer.py -v
```

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

| Имя | SHA256 |
| --- | --- |
| lobby-login-writer-replay.json | f04ee1fd9d23228131417d25bdffd3402e5d6d7eaa5891ba68348f317560408b |
| lobby-nid-input-index.json | 789259cd399f7c4f7efe9c0854559f5d33aa4db275824957a0ff9a3e43ea1b32 |

## Полная схема body ID 3

PktLobbyLogin: constructor 0x145744fa0, writer 0x145756e80, vtable
0x1498f0258. [Packet binding](HEADLESS-PACKET-BINDINGS.md) подтверждает ID 3.
Это отдельный пакет от игрового Login с тем же ID.

| Object fields | Wire |
| --- | --- |
| +0x10, +0x14 | два LE32 |
| +0x18, +0x28, +0x38, +0x48, +0x58 | пять FString |
| +0x68, +0x6c | два LE32 |
| +0x70 | FString |
| +0x80 | raw byte |

FString: LE16 длина UTF-8 в байтах, затем bytes. Минимальное тело — 29 байт.
Native writer исполнен целиком на 24 fixtures: шесть вариантов строк,
включая Unicode / emoji / длинные строки, и bytes 0 / 1 / 2 / 255.
Числовые значения различимы, включая крайние uint32 bits. Все bytes body
совпали с независимой сборкой ожидаемого формата. Writer сохраняет +0x80
без нормализации; это не доказательство допустимости любого значения сервером.

Исполняются настоящие archive primitives / UTF-8 routines. Packet fields
и заранее выделенные archive buffers — явные fixtures. Allocation / string /
CRT helpers унаследованы из прежнего harness. Constructor, preparation,
frame / socket и серверный ответ в новый native replay не входят.

## Подтверждённые источники пяти строк

Preparation `0x1467a9360` в SDK-ветви использует:

| LobbyLogin field | Источник |
| --- | --- |
| +0x18 | SDK player accessor 0x145606660 → settings GetPlayerId 0x144524d80 |
| +0x28 | SDK access token через 0x1456039c0 |
| +0x38 | NMDeviceKey через 0x1445c63a0 |
| +0x48 | NID UserInfo +0x170 через accessor 0x145604960 |
| +0x58 | отдельный Netmarble ID через 0x145604b90 |

Назначение settings getter подтверждено compiled diagnostic
`UNMServiceSettings::GetPlayerId` и цепочкой вызовов. Player ID и SDK token
не заменяют друг друга и не заменяют отдельный NID.

Поле UserInfo +0x170 связано с ключом **I_JoinedCountryCode** в serializer
0x144551060: исходный LEA поля, ссылка на key literal и fragments сохранены
в новом индексе. Accessor 0x145604960 создаёт UserInfo, вызывает loader
0x145604090 и копирует FString по этому offset. Эти связи проверены
статически; полный accessor / loader / serializer не исполнялся в новом replay.

## Составная строка +0x70 и числовой контекст

Collector 0x145604bf0 получает UserInfo, сериализует его в map и вызывает
selector 0x1455fb550 для заданных ключей. Индекс сохраняет каждую compiled
строку, её bytes / SHA / file offset и проверенные constructor / selector calls.
Найдены 27 обращений к 26 разным ключам; I_World встречается дважды:

I_GameCode, I_GameVersion, I_TID, I_CountryCD, I_PID, I_ChannelType,
I_SDKVersion, I_World, I_PlatformADID, I_ConnectIP, I_UDID,
I_JoinedCountryCode, I_DeviceOSVersion, I_DeviceModel, I_OS, I_Region,
I_TimeZone, I_LanguageCD, I_NMDeviceKey, I_NMIDFV, I_NMMarket, I_NMNID,
I_PCSeq, I_NMCPU, I_NMRAM, I_NMVGA.

Это структура параметров SDK / игры / устройства. Наличие ключа само по себе
не доказывает источник его значения, обязательность, escaping или полноту
выходной строки. После selectors есть дополнительные условные append paths.
Runtime пока не собирает эту строку и не придумывает аппаратные параметры.

Числа в preparation также остаются явными: platform expression для Windows
даёт 2; другой field зависит от wrapper+0x64. Поле +0x68 получает выбранный
game server ID через getter 0x144aaaa10: wrapper+0x10 → peer+0x270.
Поле +0x6c имеет отдельную условную ветвь numeric text; она зависит от флага
ответа Version. Значения полного live-контекста и source ветви для +0x80
не подменены defaults. Это ещё одна граница перед настоящим LobbyLogin.

## Runtime и проверки

`LobbyLoginPayload` — отдельный immutable тип с шестью строками, четырьмя
uint32 и raw byte; `encode` требует явный byte budget. Данные скрыты из repr.
`login_context.bind_lobby_sdk_fields` заполняет только пять доказанных строк
из явных SDK / NMDeviceKey / NID / joinedCountryCode inputs, отклоняя пустые
значения и конфликт. Составная строка, числа и raw byte сохраняются.
Происхождение / свежесть / аккаунт inputs остаются обязанностью владельца
соединения; parser SDK response сам по себе этого не доказывает.

Четыре новых теста воспроизводят оба отчёта, сравнивают все native bodies,
проверяют budgets / redaction / bind / конфликт и compiled country / key
bindings. Также прошли четыре lobby codecs, четыре LobbyLoginResult и шесть
Login context tests. Три проверки экспорта Ghidra прошли: всего 21 проверка.

На этом этапе новых сетевых попыток и Login с реальными токенами не было.
Далее — оставшийся numeric / metadata context, связанная отправка LobbyLogin,
его реальный ответ и decoder ID 104 перед игровым endpoint / персонажами.
