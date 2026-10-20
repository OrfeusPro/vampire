# Dumper-7: первая разрешённая проверка работающего клиента

20 октября 2026. Пользователь явно разрешил загрузку Dumper-7 в открытый
Vampir после объяснения назначения DLL. Доступ к созданию персонажа ранее
подтверждён в [официальном клиенте через JP](HEADLESS-OFFICIAL-CLIENT-JP.md).

## Источники и способ

- EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
  SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
- Dumper-7: commit `90d1f390d26e31a1f71d29af56c6bd2f240b7493`.
  DLL: `F:/PhoneExit Resources/Vampir/tools/dumper7/Dumper-7-90d1f390d26e31a1f71d29af56c6bd2f240b7493/Dumper/x64/Release/Dumper-7.dll`.
  Повторно проверенный SHA256:
  `7f88848e0ce6db4a922f670494c6ff94e2c113e5218aa61362cbd0056965a99e`.
- Прочитаны локальные README, `Dumper/main.cpp`, `Settings.cpp`, `Settings.h`
  закреплённой версии. Upstream workflow требует загрузки DLL в процесс;
  сама DLL затем ищет структуры и генерирует SDK и mappings.
- Helper: [probe-dumper7-live.py](probe-dumper7-live.py). Только закреплённые
  EXE и DLL, явные PID и `--execute`. До записи пути DLL проверяются SHA,
  путь процесса и загруженные системные модули. Обычный Windows loader;
  драйверы и изменение привилегий SeDebugPrivilege не используются.
  Планируемый временный INI отключает SDK compilation test и включает
  автоматическую выгрузку после генерации. Существующий INI не заменяется.

Windows API: [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess),
[CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).
Повышение прав выполнено через обычный `Start-Process -Verb RunAs`.
Запросы Windows автоматически не подтверждались.

## Фактический результат

В обеих проверках выбран PID 45964; PID относится только к этому запуску.

| Проверка | Результат |
| --- | --- |
| Без повышения, `--execute` отсутствует | `OpenProcess load rights`: отказ 5, `admin=false` |
| Через стандартный запрос администратора, с `--execute` | Права открытия получены; `EnumProcessModules`: отказ 5, `admin=true` |

Отказ перечисления модулей произошёл **до** создания INI, выделения памяти,
записи пути DLL и создания loader thread. Загрузка DLL не началась.
SDK и mappings не получены. Процесс игры после проверки продолжал отвечать.
Причина отказа не установлена: это не доказательство конкретного механизма
защиты и не проверка совместимости Dumper-7 с объектами Vampir.
Обход отказа и повторная загрузка не выполнялись.

## Найденный защитный компонент

После закрытия игры проверены файлы и метаданные, без чтения содержимого журнала.
В `ProjectRED/Binaries/Win64/NMSSW/xcorona_x64.xem` указаны ProductName
`XIGNCODE3 SYSTEM`, CompanyName `Wellbia.com Co., Ltd.`, версия `2024.6.18.236`.
Проверка Authenticode вернула Valid, подписант Wellbia.com Co., Ltd.
SHA256: `bafd34bd40b38b215c3b0728d7c578cf9fb3c4629077c578bb17828c2ad0e534`.
Рядом есть `xigncode.log`. Драйверы xhunter1 и xhunter2 при проверке имели
состояние Stopped; игровой процесс уже отсутствовал, лаунчер оставался открыт.
Наличие XIGNCODE3 подтверждено файлами, но его причинная связь с отказом
EnumProcessModules и тем более с сетевым InvalidState не установлена.
Защита и её настройки не менялись.

Отчёты вне Git:

- `F:/PhoneExit Resources/Vampir/dumper7-live/20261020-access-check/report.json`,
  SHA256 `484abc10b99905939c8abcaecd923856a59c2806635a18277f7a6816b219485c`.
- `F:/PhoneExit Resources/Vampir/dumper7-live/20261020-first-load/report.json`,
  SHA256 `96db2ec19b45d4f060646693fcf9e7e2b6ed7d5dbe2b22d6d1a16ff00f3bf362`.

После попытки helper дополнен явными флагами состояния, повторной проверкой
пути после открытия процесса и SHA самого helper в новых отчётах. Эти поля
отсутствуют в двух первоначальных отчётах; попытка загрузки не повторялась.

## Проверки helper и дальнейшая работа

`python -m py_compile` прошёл. Проверены два защитных условия: имя запуска
`../invalid` отклонено parser; `--execute` с PID управляющего Python отклонён
по несовпадению EXE до получения прав загрузки и создания loader thread.
Отчёт второй проверки: `dumper7-live/20261020-identity-guard-check/report.json`
в библиотеке ресурсов. Исполнение пути после перечисления модулей не проверено.

Пример предварительной проверки из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/probe-dumper7-live.py --pid <текущий-PID> --run-name <новое-имя>
```

`--execute` разрешён только для явно согласованного live-эксперимента.
Имя запуска должно быть новым; отчёты прежних запусков не перезаписываются.
Если loader thread зависнет, helper не освобождает используемый им буфер пути;
повтор автоматически не выполняется. Таймаут генерации не означает выгрузку
DLL: авторазгрузка upstream срабатывает только после завершения генерации.
Если worker ещё мог не прочитать настройки, временный INI сохраняется с явной
отметкой в отчёте: удаление до чтения вернуло бы нежелательные defaults.
В фактической попытке до создания INI дело не дошло.

Для текущей сессии продолжить создание персонажа в официальном клиенте.
Сопоставление Franz 2 с числовым server ID и анализ headless InvalidState
могут продолжаться по имеющимся данным независимо от Dumper-7. В runtime бота
helper и DLL не включаются. Память с credentials и сетевой трафик не собирались.
