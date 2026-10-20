# UserInfo оказался FCommonLogData: создание и потребители

20 октября 2026. Уточнение к [полям UserInfo](HEADLESS-NID-USER-INFO-FIELDS.md).
Название UserInfo в предыдущих аналитических именах сохранено для совместимости
с отчётами. Диагностические строки самого клиента уточнили исходные имена:

| Исследованный участок | Literal / ссылка | Имя из клиента |
| --- | --- | --- |
| writer 0x144551060 | 0x1494e6f10 | Netmarble::Service::FCommonLogData::ToMap(..., bool) |
| export 0x144550e40 | 0x1494e7330 | Netmarble::Service::FCommonLogData::ToJsonObject() |
| caller 0x144588bb0 | 0x1494ee190 | Netmarble::Service::FPushImpl::OnChangedUserData() |

Это точные compiled строки с проверенными RIP references, не восстановленные
исходники C++. Они показывают роль структуры в общих данных SDK и push-контексте.
Игра также включает выбранные данные этой структуры в Login metadata через
ранее проверенный collector. Обязательность metadata на сервере и её связь
с InvalidState не доказаны; по этому открытию нельзя объявить её ненужной.

## Что делают проверенные потребители

`0x144550e40` вызывает настоящий writer с mode = 1 и переводит map в JSON object.
`0x1445ab9f0` получает этот object и переводит его в строку для push context;
также обращается к настройкам DeviceKey / SDK. Это не источник заполнения
остальных полей FCommonLogData. Вложенный writer может обновить NMDeviceKey /
PlatformADID, как показано ранее; весь путь нельзя называть чистым чтением.

`0x1444c1ad0`, ранее названный NID_UserInfoInitCandidate, тоже экспортирует
готовую структуру в другой context. Предварительное имя не доказывает initialization.

## Создание и getter chain

Конструктор `0x14450e830` — leaf длиной 475 байт без unwind entry.
Он обнуляет 74 QWORD, то есть 37 FString descriptors / 0x250 байт,
и возвращает this. Размер и границы сохранены как reviewed leaf в manifest.

Owner constructor `0x14450f5d0` выделяет 0x278 байт, обнуляет их, ставит
таблицу `0x1494e6ec0` и вызывает конструктор полей на inner+0x28.
Указатель inner сохраняется в owner+0x28. Два готовых getters проходят так:

`SDK bridge → wrapper (+0x310) → owner → inner → 37 descriptors (inner+0x28)`.

Точнее: `0x144524800` возвращает `*input+0x310`; затем `0x144521e80`
возвращает `*(*input+0x28)+0x28`. В сценарии явно выделенный SDK bridge
связывается с созданным owner. Сам настоящий SDK host / class lifecycle
этим fixture не создаётся.

Три native-сценария с исходным заполнением 0 / 0x55 / 0xff исполнили:

1. Полный owner constructor от входа до возврата.
2. Вложенный настоящий 475-byte конструктор структуры.
3. Оба настоящих getter от входа до возврата.
4. Проверку, что getter вернул именно область созданных 37 пустых descriptors.

Allocation / memset, shared-pointer transfer, два дополнительных контейнера
owner и InitializeSRWLock — bounded fixtures. Проверено обычное успешное
выделение памяти; allocator failures и реальное обслуживание SDK не исполнялись.
Этот результат доказывает начальное пустое состояние, а не заполненность
структуры в настоящем Login после SDK SignIn.

## Поиск создания

`build-nid-user-info-construct-callers.py` повторно использует готовый E8 indexer.
Найдены 10 проверенных calls конструктора структуры / copy / owner constructor,
без ошибок linear decode. У owner constructor найден один direct caller:
`0x14450f420`. Indirect / tail calls не покрыты. Следующий путь поиска —
подключение owner к SDK host и обновление его common data из настроек / player.

Уточнение: `0x14453cdf0` после setter player ID уже связан с
UNMServiceSettings::Save; считать его источником common data по этому вызову
нельзя. Factory и подключение к SDK-сервису теперь проверены отдельно.
Следующий участок — `0x144524d70 → 0x144548ca0` после getter в SignInResponse.
[Новая проверка, источники и границы](HEADLESS-NID-OWNER-FACTORY.md).

## Происхождение и команды

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-8f720c6dedc9`: 401 функция, 182 предупреждения.
Manifest SHA256: `6a44797a6406bb82fcfdfed9f5c9993037aecacaa48562042598035445798b71`.

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

- `nid-user-info-owner-replay.json`, SHA256
  `0a082644f0a63c2441609ea310225d9866a667a3c1527c80f64176c455d488dd`;
- `nid-user-info-construct-callers.json`, SHA256
  `3230a491074f7c15b19271aec652425b215f8b954c93c418eb45937040f0df6e`.

Отчёты сохраняют hashes инструментов / источника, инструкции, leaf ranges,
diagnostic literal bytes / SHA / source references и результаты fixtures.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-nid-user-info-construct-callers.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-user-info-owner.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_user_info_owner.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_user_info_write.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Runtime и значения аккаунта не менялись, новых подключений не было.
Игровой Login по-прежнему требует устранить InvalidState до списка и создания
первого персонажа. Общие log fields не выдаются за подтверждённую причину отказа.
