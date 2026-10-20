# Основная строка NID metadata для Login

20 октября 2026. Продолжение
[compiled ключей metadata](../network/HEADLESS-LOBBY-LOGIN-WRITER.md).
Исполнены целиком collector `0x145604bf0` и selector `0x1455fb550` с явными
fixtures доступности UserInfo, map и строковых primitives. Это проверка формата
и порядка, а не заполнения реального SDK UserInfo.

## Подтверждённое поведение основной ветви

Collector конструирует локальный UserInfo, вызывает загрузчик `0x145604090`
и при успехе передаёт его writer `0x144551060` в режиме 1. Затем открывает
объект символом `{`, вызывает selector для compiled списка ключей и закрывает `}`.
Если UserInfo недоступен, основная строка не добавляется.

Selector получает ключ из map через hash / lookup. При отсутствии ключа
ничего не добавляет. При наличии вызывает преобразователь значения
`0x144476940`, затем formatter с literal `"%s":"%s"`, `0x1498b8958`.
Перед следующей парой добавляет запятую, если после `{` уже есть содержимое.
Строковое преобразование значения остаётся fixture, поэтому escaping внутри
самого преобразователя пока не доказан.

Порядок 27 обращений / 26 разных ключей:

```text
I_GameCode, I_GameVersion, I_TID, I_CountryCD, I_PID, I_ChannelType,
I_SDKVersion, I_World, I_PlatformADID, I_ConnectIP, I_UDID,
I_JoinedCountryCode, I_DeviceOSVersion, I_DeviceModel, I_OS, I_Region,
I_TimeZone, I_LanguageCD, I_NMDeviceKey, I_NMIDFV, I_World,
I_NMMarket, I_NMNID, I_PCSeq, I_NMCPU, I_NMRAM, I_NMVGA
```

Повторный `I_World` сохранён. Если map содержит только `I_World = 251`,
выход — `{"I_World":"251","I_World":"251"}`. Обычный dict / json.dumps
не воспроизведёт повторную пару. Пустой доступный UserInfo даёт `{}`;
недоступный UserInfo при пустом исходном output даёт пустую строку.

Шесть native-сценариев: все ключи, пустая map, только World, Unicode и
невыбранный ключ, строка с кавычкой / обратной косой чертой, недоступный UserInfo.
В строковом scenario подстановка formatter fixture намеренно буквальная;
это не доказательство допустимости такого значения реальным сервером.

В replay отключены две дополнительные ветви:

- SDK backend DeviceKey: formatter `,"I_DeviceKey":"%s"`;
- marketing attribution: вложенный `I_LogDes` с `MktClickId` / `MktChannel`.

Их наличие видно в коде collector; источники значений и исполнение этих ветвей
ещё не проверены. Включать их в runtime по выдуманным значениям нельзя.

Уточнение 21 октября: [официальная запись Login](../network/HEADLESS-LIVE-TCP-CAPTURE.md)
подтвердила I_DeviceKey в реальной metadata из 791 байта; I_LogDes отсутствует.
Значения и источник актуального DeviceKey ещё не подключены к сборщику runtime.

## Источник UserInfo: новые экспорты

Загрузчик при наличии SDK object получает данные через два коротких метода:

- `0x144524800`: возвращает `*input + 0x310`;
- `0x144521e80`: возвращает `*(*input + 0x28) + 0x28`.

Затем `0x1455fb2a0` копирует 37 FString descriptors по offsets
`0x00..0x240` с шагом `0x10`. В fallback path `0x1455faa10` переносит
descriptors из локального объекта. Это отдельные операции copy / move,
не сбор фактических аппаратных параметров и не чтение callback авторизации.
Копирование и источники 37 полей пока рассмотрены статически; в новом replay
загрузчик UserInfo заменён явным fixture.

Следующий необходимый участок — сопоставить поля этой структуры с ключами
writer и восстановить их setters / initialization в SDK. Наличие данных
в callback NID или SDK SignIn не доказывает заполнение всего UserInfo.
Параметр lobby kind также остаётся открытым.

## Runtime и проверки

`vampir_core.nid_metadata.encode_base_nid_metadata` принимает явную map строк
и три обязательных состояния ветвей. Значения должны представлять уже
установленные текстовые поля, а не угадываться по ключам. Основной порядок
и повторный World совпадают с native cases.

Локальная политика: bounded UTF-8 строки без кавычек, обратной косой черты
и control characters; неизвестные ключи игнорируются. Это ограничение входов,
а не восстановленная реализация native value conversion. Размер map до 64,
значения до 4096 символов, выход до 65 535 UTF-8 байт. Неподдержанные optional
ветви отклоняются. Значения при недоступном UserInfo тоже отклоняются.

Кодировщик не подключён к реальным lobby / game Login. Текущий runner всё ещё
явно использует SDK-auth-present / NID-UserInfo-absent branch. Новых сетевых
попыток, записи device keys, запуска игры или создания аккаунтов не было.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-metadata.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_metadata.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_lobby_login_writer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

## Происхождение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-adc44aa77ce6`: 394 функции / 181 предупреждение.
Manifest SHA256: `888cde6e724976455ca80347634f05f78952bf68c5add300c096ab5ee476bdd0`.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/nid-metadata-replay.json`.
SHA256: `7e150ff232f9a7b3939dca55e23149d0c46c1eb0c520e700fffeef6dc266cdff`.
Содержит source/tool/dependency/key-index SHA, инструкции, fixtures и результаты.
Исходный compiled список — `code-clues/lobby-nid-input-index.json`.
В runtime нет Capstone / Unicorn / Ghidra; исследования остаются отдельно.
