# После OnResult: Save, channel manager и credential SDK

19 октября 2026. Продолжение [callback boundary](HEADLESS-SDK-PERCENT.md).
Четыре native прогона связали принятый email result с объектом credential:
provider channel **20**, SDK credential channelCode **33**. Его GetObject
добавляет channelAccessToken и channelCode. Это входные данные SDK sign-in,
не ответ авторизации SDK и не готовая игровая сессия.

## Источник и воспроизведение

[replay-nid-credential-adoption.py](replay-nid-credential-adoption.py) проверяет EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это compiled Windows client, не настоящий исходный C++ проект.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/nid-credential-adoption-replay.json`, SHA256
`ac3de39b5fcbb313615d5427b4d5ff0f33d13c0594116aeb81b5468e61863be1`.
Сохранены source/helper/static fragments, vtable bytes/file offset/SHA,
ASCII key literals, upstream primitive report SHA и synthetic events/payloads.

Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-credential-adoption.py`.
Переиспользованы [actual integer/channel helpers](HEADLESS-NID-PRIMITIVES.md)
с той же проверенной локальной ucrtbase. Native OnResult продолжен после
0x1450ef437 до stop 0x1450ef51f. Дополнительно исполнены base credential ctor,
GetChannelManager, SetCredential wrapper/impl и GetObject/base GetObject.
Диагностика отключена явным fixture log level=0.

Storage Save result и RemoveAllCredentials — captures. Settings setters, JSON
initializer/field writes, финальная map insertion и retain count — shims/captures.
Allocation/copy/free/atexit ограничены прежними fixtures. Живые настройки игры,
Saved, browser profiles и память процессов не читались; запись на диск не выполнялась.
FString key ctor 0x141420f70 принимает узкую ASCII строку; отдельный shim не
подменяет её wide-конструктором 0x141421150.

## Подтверждённая цепочка

| Call site / target | Наблюдаемое действие |
|---|---|
| 0x1450ef437 → 0x14453cdf0 | точный diagnostic UNMServiceSettings::Save |
| 0x1450ef440 → 0x144521550 | FServiceImpl::GetChannelManager, возвращает wrapper по owner+0x170 |
| 0x1450ef448 → 0x1444f5190 | diagnostic RemoveAllCredentials; здесь capture |
| 0x1450ef451 → 0x144521550 | повторное получение manager |
| 0x1450ef45e → allocator | allocation 0x68 bytes |
| 0x1450ef470 → 0x1444bd500 | base ctor с DL=0x21; запись byte credential+0x50=33 |
| 0x1450ef480 | derived vtable 0x1496e16f0 |
| 0x1450ef498..0x1450ef4c5 | копия accessToken в credential+0x58 |
| 0x1450ef51a → 0x1444f8fd0 | SetCredential wrapper → impl 0x1444f9050 |
| 0x1444f9149 | impl читает byte credential+0x50 для map key |
| 0x1444f91c7 → 0x1444bb100 | map insertion capture: key=33, тот же access token |

Save имеет bool return, но caller не проверяет RAX после вызова. False/true ×
два synthetic access tokens дали одинаковую последовательность clear→insert33.
Это доказывает caller behavior, не успешность/безопасность настоящего Save.
Сама Save содержит SaveGameToMemory/SaveArrayToFile и retry diagnostics;
её полный persistence format/защита не исполнены и не считаются подходящим
хранилищем для нашего бота без отдельного проектирования.

## Два поля GetObject

Вторая запись vtable 0x1496e16f0+8 указывает на 0x1450e50d0.
Этот метод:

1. Берёт **ASCII** literal channelAccessToken на 0x1450e50e0.
2. Передаёт descriptor credential+0x58 в JSON string setter 0x1444822f0
   на call site 0x1450e50fe.
3. Вызывает base GetObject 0x1444e6570, который читает credential+0x50 и
   добавляет numeric channelCode через 0x144482210 на 0x1444e65a6.

Наблюдаемый объект: `{ "channelAccessToken": "<provider access token>", "channelCode": 33 }`.
JSON field writes захвачены; исходная JSON initializer/сериализация HTTP body
не исполнялись. Не заявляется побайтовый формат всего SDK request.
RefreshToken, netmarbleId и country остаются отдельными settings inputs;
provider channel20 не подставляется в поле channelCode этого credential.

## Общий модуль и следующий шаг

`vampir_core.nid_sdk_credential.build_nid_sdk_credential` принимает email
NidEmailCredential, повторно проверяет его через существующий fields validator
и возвращает frozen NidSdkCredential. channel_code=33 не задаётся пользователем,
access token скрыт в repr. as_object возвращает новый dict из двух наблюдаемых
полей. Нет HTTP, password/refresh storage, SDK mutation или статуса login success.

Четыре теста проверяют воспроизведение/vtable/ASCII literals, save return/порядок,
common payload против native captures, callback→credential33, redaction и invalid
вручную созданные inputs. Далее FAuthImpl::SignIn 0x1444fb800: полный request
authUrl/v1/sign-in, headers/device/client context, response/SDK token, затем
связь с game Login. Путь, автоматически вызывающий SignIn после этого result,
и привязка к активной попытке входа пока не доказаны. Реальных аккаунтов/запросов нет.
