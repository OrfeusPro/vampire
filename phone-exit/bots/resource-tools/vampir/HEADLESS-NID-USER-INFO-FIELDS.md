# Поля UserInfo и запись NID map

20 октября 2026. Продолжение [формата metadata](HEADLESS-NID-METADATA.md).
Двенадцать сценариев исполнили полный `LobbyNID_UserInfoWrite`, `0x144551060`,
с размеченными 37 FString descriptors. Подтверждены указатели исходных полей,
условия пропуска и отдельные обращения к getters. Реальные значения SDK
в этом исследовании не читались.

## Поля, связанные с ключами

Смещения относятся к UserInfo, а не к SDK manager или сетевому пакету.
В сценарии с непустыми полями получены 33 прямые связи:

| UserInfo offset | Ключ map |
| --- | --- |
| +0x00 | I_OS |
| +0x10 | I_DeviceOSVersion |
| +0x20 | I_DeviceModel |
| +0x30 | I_NMManufacturer |
| +0x40 | I_NMModel |
| +0x60 | I_UDID |
| +0x80 | I_GameVersion |
| +0x90 | I_SDKVersion |
| +0xa0 | I_GameCode |
| +0xb0 | I_NMBuildCode |
| +0xc0 | I_NMMarket |
| +0xd0 | I_TID |
| +0xe0 | I_ConnectIP |
| +0xf0 | I_NMMobileIP |
| +0x100 | I_CountryCD |
| +0x110 | I_City |
| +0x120 | I_ChannelType |
| +0x130 | I_NMChannelCode |
| +0x140 | I_NMChannelUserID |
| +0x150 | I_PID |
| +0x160 | I_Region |
| +0x170 | I_JoinedCountryCode |
| +0x180 | I_LanguageCD |
| +0x190 | I_World |
| +0x1a0 | I_NMCharacterID |
| +0x1b0 | I_NMSessionID |
| +0x1c0 | I_TimeZone |
| +0x1f0 | I_NMCPU |
| +0x200 | I_NMRAM |
| +0x210 | I_NMVGA |
| +0x220 | I_NMResolution |
| +0x230 | I_NMNID |
| +0x240 | I_NMNIDChannelType |

Полная map и выбранная collector строка различаются: writer добавляет больше
ключей, чем collector запрашивает. Writer не повторяет I_World; повтор появляется
в selector sequence collector. Offsets +0x1d0 / +0x1e0 не получили прямой связи
в этих сценариях; нельзя назначать им имена по оставшимся позициям.

## Условия и обновления внутри writer

- I_GameCode и I_NMBuildCode добавляются только при непустых соответствующих
  строках (native count > 1). Пустые значения других полей не обязательно
  означают отсутствие ключа.
- I_NMNID и I_NMNIDChannelType добавляются вместе по непустому UserInfo+0x230.
  Отдельно проверено: пустой +0x230 подавляет обе пары, даже если +0x240 непуст;
  непустой +0x230 разрешает пустое значение второй пары.
- Writer заменяет UserInfo+0x50 результатом `Version_Input48Source`,
  `0x1444e5ff0`, и использует его для I_NMDeviceKey. Источник NMDeviceKey
  ранее исследован в [жизненном цикле ключа](HEADLESS-VERSION-DEVICE-INPUT.md).
  В этом replay getter — capture с отдельной строкой.
- UserInfo+0x70 заменяется результатом `0x1444e3ac0` при ненулевом mode;
  при mode = 0 записывается пустая строка. Это значение идёт в I_PlatformADID.
  Источник getter пока не установлен.
- I_NMIDFV получает отдельный результат `0x1444e5350`. Его backend — fixture.
- I_NMAppSetID и I_NMInstallPackageName получили пустые строки в этих сценариях.
  Для I_NMAppSetIDScope перехвачен вызов constructor `0x14446eff0` с RDX = 0;
  тип и преобразование этого variant не объявлены восстановленными.

С непустыми строками writer добавляет 39 разных ключей, с пустыми — 34.
Это наблюдение выбранных fixtures и выключенной diagnostic ветви, не гарантия
полноты metadata настоящего аккаунта. Строковые / variant / map primitives,
SDK getters и ownership cleanup заменены ограниченными hooks. Сам writer
исполняется от входа до возврата в обоих режимах.

## Поиск источников заполнения

`build-nid-user-info-callers.py` нашёл 56 подтверждённых прямых E8 вызовов
двух getters. Для `0x144521e80`, возвращающего сам UserInfo, всего три roots:

- `0x1444c1ad0`;
- `0x144588bb0`;
- `0x145604090` — уже известный загрузчик metadata.

Первые два проверены в Ghidra. `0x1444c1ad0` получает UserInfo и передаёт его
в `0x144550e40`, затем переносит полученный объект в свой context+0x48:
это consumer, а не доказанный initializer, несмотря на предварительное имя
экспорта NID_UserInfoInitCandidate. `0x144588bb0` передаёт найденный UserInfo
в `0x1445ab9f0` с объектом из своего +0x20, затем читает I_LanguageCD (+0x180).
Следующие конкретные участки — `0x1445ab9f0` и `0x144550e40`.
Другие
найденные callers обращаются к wrapper настроек `0x144524800`; сам факт вызова
не доказывает запись UserInfo. Root `0x14458f270` не прошёл linear decode
и сохранён как явный пробел; indirect и tail calls этим поиском не покрыты.

## Воспроизведение и отчёты

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-user-info-write.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-nid-user-info-callers.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_user_info_write.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_metadata.py
```

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Writer прочитан в существующем экспорте `run-adc44aa77ce6` до native исполнения.
Новый экспорт: `export-c7552efd2125/run-bf447b531cdf`, 396 функций.
Manifest SHA256: `47d3292822990f70c33cd4c755810e7238cd5e170c58f86317ef5261245cd0db`.

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

- `nid-user-info-write-replay.json`, SHA256
  `e5bd0766b12375f11f9e30d87044c8f85d6c603c22b245967dce224a52cdb9dd`;
- `nid-user-info-callers.json`, SHA256
  `7c0f54e444ece299f09bdb422205ad2a436884e0179cd51dea314d1c7b0ee93f`.

Сохранены source/tool/dependency hashes, исходные диапазоны инструкций,
fixtures, пары map, перезаписанные поля, verified calls и gaps.
Тесты воспроизводят оба отчёта и проверяют конкретные ключи / offsets,
режим getter, сохранение отдельных PID / NID / device key и optional gates.

Runtime и реальные поля аккаунта не менялись; сетевых попыток не было.
Далее — источники заполнения полей, затем подключение подтверждённых metadata
к lobby / game Login. Причина InvalidState пока не установлена.
