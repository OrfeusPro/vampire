# Наблюдённые ключи текущего Windows-устройства

20 октября 2026. Три существующие записи SDK прочитаны из HKCU без запуска
игры, создания GUID, изменения реестра Windows или сетевой авторизации.
Они сохранены в игнорируемой `.local/accounts.sqlite3` для основного тестового
профиля. Confirmation остаётся `unknown`, серверная привязка не проверена.
Это выбор наблюдённого устройства для будущего входа, а не восстановленная
сессия аккаунта или доказательство активного SDK cache.

## Источники

Перед чтением проверен SHA256 установленного EXE:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Пути установлены по коду клиента:

- [DeviceKey / NMDeviceKey](../resource-tools/vampir/HEADLESS-DEVICE-IDENTITY.md).
- [Отдельный NID key](../resource-tools/vampir/HEADLESS-NID-DEVICE-CONTEXT.md).
- [Связь NMDeviceKey с Version / Login](../resource-tools/vampir/HEADLESS-VERSION-DEVICE-INPUT.md).
- [GameCode и SDKZone](../resource-tools/vampir/HEADLESS-SDK-SETTINGS.md).

| HKCU path | Value | Результат наблюдения |
| --- | --- | --- |
| `Software\Netmarble\thered` | `DeviceKey` | REG_SZ, 32 символа |
| `Software\Netmarble\thered` | `DeviceKeyForNetmarbleId` | REG_SZ, 32 символа |
| `Software\Netmarble\NetmarbleSDK` | `NMDeviceKey` | REG_SZ, 32 символа |

Все три значения различаются. Сами значения в вывод, документацию и Git
не помещались. Происхождение в SQLite содержит пути, дату, SHA клиента
и явную границу: stored identity, active cache / server binding unverified.
SDK-пара и отдельная NID identity записаны через существующие методы
DeviceRegistry; замена уже сохранённой identity запрещена этими методами.

Найденный store относится к явно выбранному контексту Netmarble / thered.
Наличие сохранённых строк не доказывает текущий platform / zone работающего
SDK, отсутствие SaveGame override или связь с определённой почтой на сервере.
Ни состояние `confirmed`, ни evidence подтверждения автоматически не выставлены.

## Чтение в runtime

`vampir_core.windows_device_identity.observe_windows_device_identity()`
требует явных `store_name` и `game_code`. Читает только три указанных value
с KEY_READ, проверяет REG_SZ / непустой ограниченный текст и повторяет чтение.
Изменение между двумя проходами отклоняется. Это обнаружение простой гонки,
а не атомарный снимок реестра и не вызов native GUID parser.

Не найденная / пустая / неподдержанная запись вызывает ошибку; fallback,
генерация нового устройства, поиск других stores и запись не выполняются.
Исходный текст сохраняется без нормализации к Python UUID. winreg импортируется
только при вызове Windows-функции; portable modules остаются импортируемыми
на Android. Для Android нужен свой источник, не копирование Windows fallback.

```python
from vampir_core.windows_device_identity import observe_windows_device_identity

# Только явное наблюдение. Не выводить identity или её поля в журнал.
identity = observe_windows_device_identity(store_name='Netmarble', game_code='thered')
```

## Подготовка зарегистрированного входа

`login_context.prepare_registered_login(version, login, binding=...,
sdk_data=..., netmarble_id=...)` требует реальный профиль с заполненной
SDK-парой и NID identity. `required` вызывает PermissionError до подготовки
пакетов; `unknown` допускает первую попытку, которая может запросить штатное
подтверждение. `confirmed` не заменяет проверку ошибок следующего входа.

Helper переносит NMDeviceKey в обе доказанные строки и SDK token / отдельный
Netmarble ID в Login, не меняя остальные явно переданные поля. Он не выполняет
HTTP и не доказывает принадлежность SDK-ответа аккаунту. Низкоуровневый
`start_login()` остаётся API явных payload; будущий runner должен применять
профиль и gate перед попыткой, а серверный challenge записывать через
`require_confirmation()`. Распознавание challenge ещё не реализовано.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_windows_device_identity.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_device_registry.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_flow.py
```

Все 20 тестов прошли. Кроме fixtures выполнено двойное чтение трёх реальных
значений через новый reader; длины и различие подтверждены без вывода ключей.
Следующий шаг — официальный NID sign-in / SDK credential с этим device
context, свежий SDK response и оставшиеся поля Version / Login.
Пароль, токены и коды подтверждения в SQLite не сохранять.
