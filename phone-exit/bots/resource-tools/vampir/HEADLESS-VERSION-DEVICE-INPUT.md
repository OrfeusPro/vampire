# Version и Login: общий NMDeviceKey и контекст SDK

20 октября 2026. Установлена связь ранее неизвестного getter
`0x1445c63a0` с уже исследованным `FDeviceInfo::GetNMDeviceKey`
`0x1444e5ff0`. Это закрывает источник одной строки в каждом запросе:
`Version+0x48` и `Login+0x78` содержат NMDeviceKey. Он отличается от
SDK deviceKey, NID device key, Netmarble ID и SDK access token.

## Источники и воспроизведение

Код клиента:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный EXE, не исходный C++ проект.

Ghidra 12.1.4: 269 функций, 108 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-7f884baf60f0`.
SHA256 манифеста:
`7287127a2bd438051ea7a7a4e47594bb6cef186b893959f5054c45e808faf0f7`.
SHA256 `functions.json`:
`0dfc49b0fa64d1d2bd728ea39d0ee4194ba34c9ac826d18c228888c865de4ac8`.

Переиспользованы [NM getter / storage / cache](HEADLESS-DEVICE-LIFECYCLE.md),
[исходные поля Login](HEADLESS-LOGIN-PACKET-FIELDS.md) и
[подготовка Version](HEADLESS-CONNECTED-VERSION-PACKET.md).
`Version_InputGetter48` в Ghidra вызывает NM getter и возвращает выходной
descriptor. Его вызовы в подготовке пакетов:

| Пакет | Вызов getter | Копирование результата | Поле из прежнего replay |
| --- | --- | --- | --- |
| Version | `0x1467a9e6a` | `0x1467a9e76` → `0x14143c260` | `+0x48` |
| Login | `0x1467a9807` | `0x1467a9813` → `0x14143c260` | `+0x78` |

Новый `replay-version-device-input.py` исполняет настоящие wrapper и
NM getter вместе на четырёх профилях: cache, stored value, генерация при
невалидном stored value и отказ записи. Каждый getter вызывается повторно;
второй вызов использует cache без новых storage / parser / generator событий.
Унаследованные storage / parser / источник GUID остаются fixtures. Полная
подготовка обоих пакетов этим replay не повторяется, её callsites статические.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/version-device-input-replay.json`.
SHA256: `bc564da67a1ec966bb8f26ff2ce7400362fb725db13566d2196706a58ce0252f`.
Сохранены native instructions / SHA wrapper, обе точки вызова, профили и события.

## Привязка в общем runtime

`vampir_core.login_context.bind_nm_device_key(version, login, nm_device_key=...)`
создаёт новые immutable payload, заполняя только две доказанные строки.
Входное значение сохраняется без нормализации. Пустое / некорректное значение
или отличающееся уже заполненное поле шаблона отклоняются, чтобы не смешать
контексты разных устройств. Остальные поля остаются явно заданными.

`bind_sdk_login_fields(login, sdk_data=..., netmarble_id=...)` переносит
SDK response accessToken в `Login+0xa0`, отдельный Netmarble ID — в `+0x30`.
Player ID из SDK не подставляется вместо Netmarble ID. Эти источники установлены
прежним исследованием Login; новый код связывает их с переносимым payload.
Парсер SDK сам не доказывает происхождение HTTP-ответа, свежесть токена,
аккаунт или срок действия. Эти проверки остаются ответственностью runner.

## Проверка текущего устройства и оставшиеся поля

Выполнено только чтение точной записи HKCU
`Software\Netmarble\NetmarbleSDK`, value `NMDeviceKey`: запись существует,
тип REG_SZ, 32 символа. Значение не выводилось, не коммитилось и не записывалось
в реестр аккаунтов бота. Наличие этой записи не доказывает её привязку к
тестовой почте или актуальному SDK-контексту. Ничего не генерировалось и
в реестре Windows не менялось.

Основная запись аккаунта бота по-прежнему имеет `confirmation = unknown`;
SDK-пара и NID identity не заполнены. Реальный вход не выполнялся.

Другие новые Ghidra-функции уточняют границы Version:

- `0x1414476a0` форматирует две / три строки как `%s|%s` / `%s|%s|%s`,
  с проверкой `Unknown` и обработкой разделителя `|`. Первые два getter
  копируют char-буферы `0x14b058cb2` / `0x14b058cbf`; в файле EXE они пусты.
  Их runtime-инициализация и смысл ещё не установлены.
- `0x1415c3960` обращается к GetNativeSystemInfo / GetVersionExW и строке
  `%d.%d.%d.%d.%d.%s` с `64bit`. Это статическая связь с данными Windows,
  не выполнение OS helper и не установленные значения для данного ПК.
- `0x1416d7af0` ищет context key в массиве, затем вызывает `0x1416d7a10`.
  При отсутствии / недопустимом индексе getter возвращает пустой descriptor.
  Содержание и активный выбор context store пока неизвестны.

Не назначать этим строкам имена ID пользователя / устройства по сходству.
Следующий шаг — получить согласованный SDK / NID device context, установить
инициализацию оставшихся полей, затем реальная авторизация и подтверждение.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-version-device-input.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_flow.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_device_lifecycle.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Все 17 выбранных тестов прошли: четыре context / wrapper, семь LoginFlow,
три lifecycle устройства и три provenance Ghidra. Реальный SDK sign-in,
вход в игру и привязка основной почты этими проверками не выполняются.
