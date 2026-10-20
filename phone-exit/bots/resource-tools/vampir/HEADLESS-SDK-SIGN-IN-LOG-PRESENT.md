# SendSignIn с доступным SDK-сервисом

20 октября 2026. Продолжение [ветви без сервиса](HEADLESS-SDK-SIGN-IN-LOG.md).
Четыре native-сценария исполнили полный SendSignIn с доступным сервисом и
отсутствующим optional NMSDK.PlatformType. Сетевых запросов не было.

Настоящие инструкции читают GameCode из settings data+0x38 и ChannelCode
из byte data+0x88. Captured event содержит две пары GameCode / ChannelCode;
первый аргумент отправителя равен owner из SDK service+0x310, следующие —
1 и 2. Channel fixtures 0 / 20 / 33 / 255 проходят без изменения.
Тип variant-конструктора для ChannelCode не установлен: сохранён raw аргумент.
Begin/end span двух пар и ключи проверены до передачи в sink.

Weak references, singleton/settings getters, string/variant/map backends и
sink 0x144546880 — fixtures. Дополнительное событие при доступном PlatformType
не исполнялось. Реальные значения аккаунта и типы сериализованных чисел
по этим fixtures не выводятся.

Sink разобран в Ghidra. Точный diagnostic определяет 0x144546880 как
FLogImpl::SendPlatformLog. Среди проверенных literals — I_LogId,
I_LogDetailId, I_PCSeq, I_LogDes. В обоих sink 0x144546880 / 0x144547040
найдены calls copy 0x14450e580 и writer 0x144551060. Псевдокод передаёт
writer локальную копию common data и mode 1. Полное native-исполнение sink,
copy и фактическая отправка здесь не проверены. Это потребление common data,
а не доказанный источник их первоначального заполнения.

EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-39c86d5d40cc`: 408 функций / 186 предупреждений.
Manifest SHA256: `b51e4dc2ae9fe8ac4659ea7305c1dbc877c822c34bee30b29b524069d57e81be`.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-log-present-replay.json`,
SHA256 `2d84fbb830dab974a48168e4c2838d99e3465660eccf3ebff2d344eeeaf41613`.
Он содержит source/tool/dependency hashes, native ranges, sink literals / calls
и результаты четырёх сценариев; native и static evidence разделены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-sign-in-log-present.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_sign_in_log_present.py -v
```

Прошли 6 проверок: present-service, две absent-service / diagnostic и три
Ghidra export. Runtime не менялся. Причина InvalidState не установлена.
