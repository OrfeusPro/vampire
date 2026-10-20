# Launcher-вход: отдельный credential и два HTTP-вызова

20 октября 2026. Продолжение [первичного индекса авторизации](HEADLESS-AUTH.md).
Установлено конкретное различие между NID-входом бота и launcher-ветвью кода.
Оно пока не доказывает причину игрового `LoginResult = 16` и не разрешает
заменить credential бота изменением одного номера канала.

## Источники

Собранный Windows EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Перед разбором все четыре адреса проверены через реестр: существовали только
ссылки на diagnostic literals, подробного Ghidra-разбора не было.

Ghidra: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-2af5fa68a59a`.
412 функций, 189 предупреждений. Manifest SHA256
`a1c660b393381408966f624aff2d5e4fc990321132ff455bc2845b94c03cf2e9`,
functions.json SHA256
`166852ae1fccd641afb7e756fc01ed29ba2bf25773295f461a0141d588d1a3da`.
Псевдокод сверялся с декодированными инструкциями прежнего source-bound индекса.

Отчёт [replay-launcher-auth-gate.py](../../../replay-launcher-auth-gate.py):
`F:/PhoneExit Resources/Vampir/code-clues/launcher-auth-gate-replay.json`, SHA256
`4426c48d5bf536237969d34b9e6fbefea9fbae6b9c0a9fc6dd030f6a102f181b`.
Сохраняет исходные инструкции, строки, vtable, SHA зависимостей и псевдокода.
Каждый исходный фрагмент сверяется с EXE до исполнения.

## Выбор launcher-контекста

`FChannelManagerImpl::IsRunningOnLauncher`, `0x1444eb1c0`, вызывает уже известный
auth-context helper `0x144520a60`, затем сравнивает тип с FString global
`0x14b4f1020`. Diagnostic прямо сообщает `AuthType is not nmlauncher.`.
При совпадении устанавливается общий flag `0x14b4f13fd = 1`.
При отсутствии контекста или несовпадении возвращается false; прежний flag
при этом не очищается. Его полный lifecycle этим не установлен.

Десять native-сценариев исполнили gate и настоящий ASCII comparison:
`nmlauncher`, `NMLAUNCHER`, `netmarble`, другой тип и отсутствующий контекст,
каждый при прежнем flag 0 / 1. Первые два приняты, остальные отклонены.
Auth-context helper, освобождение строк и значение comparison global — явные
fixtures; initializer global и настоящий command-line parser здесь не исполнялись.
Диагностика отключена. Источники `NMAUTH_TYPE` / `NMAUTH_TOKEN` и fallback
`AUTH_TYPE` / `AUTH_TOKEN` уже описаны в [auth path](HEADLESS-SDK-AUTH-PATH.md).

## Credential отличается от NID credential

`FChannelManagerImpl::CreateLauncherCredential`, `0x1444dd8a0`:

| Участок | Установленное действие |
| --- | --- |
| `0x1444dd91a` | Вызов launcher gate `0x1444eb1c0` |
| `0x1444dd950` | Повторное получение auth context через `0x144520a60` |
| `0x1444dd9f9` | Запись byte credential+0x50 = 200 |
| `0x1444dd9fd` | Перенос строки токена в credential+0x58 через FString helper |
| `0x1444dda25` | Разбор token container через ранее исследованный `0x144537b20` |
| `0x1444dda3e` | Ключ `chc`; при допустимом числовом поле заполняется отдельный byte +0x68 |
| `0x1444ddb1b` | Передача credential в уже известный `SetCredential`, `0x1444f9050` |

Vtable `0x1494d61d8`, slot +8 → `0x1444e6570`: это тот же base GetObject,
который ранее исполнялся в [NID credential](HEADLESS-NID-CREDENTIAL.md).
Он сериализует `channelCode` из byte +0x50. У launcher credential этот slot
не указывает на NID override `0x1450e50d0`, добавляющий `channelAccessToken`.
Поэтому launcher credential нельзя описывать как NID payload с заменой 33 на 200.
Полное создание launcher credential в этом новом replay не исполнялось;
перечисленные инструкции и vtable являются статическими доказательствами.

## Два отдельных запроса

| Функция | Подтверждённая сборка запроса | Не закрыто |
| --- | --- | --- |
| `FAuthImpl::GetTokenByLauncher`, `0x1444e8130` | `authUrl` + `launcher/token`; четыре общих поля nmDeviceKey / deviceKey / countryCode / os; при credential его GetObject дополняется gameCode / buildCode; вызов `0x14451c3f0`, callback `0x1444d8510` | Полный ответ, его принятие и следующий переход |
| `FAuthImpl::SignInByLauncher`, `0x1444fd270` | `authUrl` + `launcher/sign-in`; те же четыре поля устройства; отдельная map со значением из credential+0x58; вызов `0x14451c570`, callback `0x1444d8600` | Точный ключ map из global `0x14b4f0a70`, ответ и связь результата с игровым Login |

Перенос credential+0x58 в отдельную map виден по
`0x1444fd4c0..0x1444fd4f2`: адрес ключа, адрес строки, затем создание map.
Имя этого ключа не угадано по соседним accessToken / authToken.
Общие ключи устройства уже связаны с initializer и native fixtures в
[обычном SDK sign-in](HEADLESS-SDK-SIGN-IN.md).
Наличие двух методов не доказывает, что они всегда вызываются последовательно:
маршрутизация и callbacks требуют отдельной проверки.

## Проверки и следующий шаг

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-launcher-auth-gate.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_launcher_auth_gate.py
```

Новый replay покрывает только gate. Не читались реальные launch arguments,
токены, аккаунты и память игры; HTTP не отправлялся, runtime не менялся.
Следующий участок — initializer ключа `0x14b4f0a70`, callbacks
`0x1444d8510` / `0x1444d8600` и выбор между launcher / обычным SDK sign-in.
Новый игровой вход имеет смысл после доказанной и реализованной цепочки,
а не после подстановки канала или повторения прежнего запроса.
