# Вызовы после SignIn ведут к FPlatformLogImpl::SendSignIn

20 октября 2026. Продолжение [создания common data](HEADLESS-NID-OWNER-FACTORY.md).
Источник — собранный Windows-клиент; это не исходный C++ проект.

## Что установлено

SDK_SignInResponse после успешной обработки ответа вызывает:

`0x144524800 → 0x144524d70 → 0x144548ca0 → 0x144548cb0`.

Первый getter возвращает wrapper SDK-сервис+0x310, содержащий owner.
Второй — восьмибайтовый leaf: `mov rax, [rcx]; add rax, 0x78; ret`.
Он возвращает соседний компонент owner+0x78, а не common data inner+0x28.
Wrapper 0x144548ca0 исполняет `mov rcx, [rcx+0x10]` и прямой JMP на
0x144548cb0. Следовательно implementation берётся из owner+0x88.

Implementation связан точным diagnostic literal по 0x1494ebba0:
`Netmarble::Service::FPlatformLogImpl::SendSignIn(void)`.
SHA256 literal с завершающим NUL:
`50beeacdbb11f9d4755c4175a0850f5db76f4ac4096fcf99eb7d0c659d8783fa`.
RIP reference находится внутри implementation. Это уточняет аналитические
имена SDK_PostSignInOwnerGet / SDK_PostSignInOwnerActionImpl в Ghidra.

Псевдокод с доступным SDK-сервисом собирает данные с ключами GameCode и
ChannelCode и вызывает 0x144546880 с raw аргументами 1 и 2. Дополнительная
ветвь проверяет NMSDK.PlatformType и вызывает 0x144547040 с числами 1 и 400.
Эти числа не объявляются ID игровых пакетов, статусами персонажа или кодами
ошибки. Вложенная отправка и реальные значения события не исполнялись.

## Native-проверка

[replay-sdk-sign-in-log.py](../../../replay-sdk-sign-in-log.py) исполняет настоящий
getter, forwarding thunk и implementation от входа до возврата в ветви
недоступного SDK-сервиса. Три fixtures отличаются заполнением owner:
0 / 0x55 / 0xff. Проверены адрес owner+0x78, implementation из +0x88,
факт входа в implementation и отсутствие изменений 0xf0 байт owner.

Объекты owner / platform log заданы fixtures. Получение weak service через
0x144523ff0 и lock через 0x14451fd40 имитируют отсутствие сервиса; diagnostic
logging выключен. Это покрывает ранний выход, а не рабочий сценарий SignIn
с доступным сервисом. Нельзя делать вывод, что SendSignIn и все вложенные
методы никогда не обновляют common data. Причина Login 16 не установлена.

## Происхождение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт: `export-c7552efd2125/run-ea54dcc17371`, 406 функций,
184 предупреждения. Manifest SHA256:
`0057e13d29892e68a8d6105b010c1348cc32455d5205019ff9500094d854cb07`.

Getter не имеет unwind entry. Его reviewed leaf длиной 8 байт добавлен
в manifest с проверкой конечного RET. Forwarding thunk длиной 9 байт не
выдаётся за unwind root; его точные bytes и SHA сохранены в replay report.
Граница implementation взята из PE unwind. Псевдокод прочитан до replay.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-log-replay.json`,
SHA256 `d4d99fbadfb1722ea4de8fe3e7ce6c8e43ef8c03e7b23ef44218e98ed42943b4`.
В отчёте сохранены source / tool / dependency SHA, диапазоны инструкций,
leaf / thunk evidence, diagnostic / key literals с references и три сценария.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-sign-in-log.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_sign_in_log.py -v
```

Прошли 7 проверок: две SignIn log, две factory и три Ghidra export.
Отчёты воспроизведены, SHA и связь экспорта с manifest проверены.

Далее — ветвь с доступным SDK-сервисом, вложенная отправка и источники common
data; параллельно остаётся различие SDK-only и launcher authorization.
Runtime, поля аккаунта и сеть не менялись. Игра не запускалась, DLL не загружалась.
