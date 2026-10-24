# SDK getters внутри Login 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Целый Login prepare теперь исполняется с тремя SDK-функциями и шестью короткими
getters. Проверены 2 016 сценариев: прежняя матрица из 672 случаев × три состояния
SDK-кэшей — заполнены, восстановлены через resolver fixture, остались пустыми.
Авторизация, сеть и активация игрового профиля не выполнялись.

## Источники и сбор материалов

- Caller / constructor: готовый `run-7c5a462e9d0c`.
- Mode getter: готовый `run-9dc981740f54`.
- Main/value getters и metadata collector: новый `run-2c9766b1ab08`.
  Выгружены только три отсутствующих unwind roots в существующем проекте,
  с отключённым общим анализом. Дерево вызовов не расширялось.
- Шесть leaf getters без unwind записей проверены по явным байтам EXE,
  с границами инструкций и завершающим ret. Их bytes/SHA закреплены в контексте.

Первый смешанный collect был отклонён до запуска Ghidra: среди адресов оказались
leaf getters, а collector принимает только unwind roots. Попытка сохранена как
failed, не перезапускалась. После проверки адресов подготовлен отдельный запрос
на три roots. Остальные материалы повторно не выгружались.

Точные SHA экспортов, bytes листовых функций и прямые calls:
[контекст](../../native-contexts/login-prepare-sdk-11316.json).
[Квитанция результата](LOGIN-SDK-11316.json).

## Что теперь исполняется

| Адрес | Проверенное действие |
| --- | --- |
| `14560ad80` | Читает manager pointer из `14b5e5ec0` |
| `14556ae90` | Читает language-object pointer из `14b5e4788`; caller читает byte `+18` |
| `145cc6a80` | Читает flags-object pointer из `14b5f13d8` |
| `145ccd310` | Возвращает AL = 1 при byte `object+8 == 3`, иначе 0 |
| `144ffe460` | Читает raw byte `handle+39` |
| `144ab0c80` | Читает u32 `*(owner+10)+270` |
| `14560aed0` | Сравнивает строку с `nmp`, `epicgames`, `gpgpc`, возвращает 0/1/2; неизвестное → 0 |
| `14560b070` | Читает singleton/cache `+110`, при необходимости вызывает resolver; при наличии cache получает строку, иначе возвращает пустую |
| `145609e50` | Через отдельный singleton/cache читает FString `cache+78`, передаёт count−1 (при count 0 — 0) в присваивание `handle+58`; возвращает адрес этого поля |

Если cache последнего getter отсутствует, поле `handle+58` сохраняется.
В сценарии используется отличающийся исходный текст, чтобы проверить эту ветку.
Присвоенный строковый буфер принадлежит SDK member, переживает очистку temporary
Login packet и не считается утечкой. Проверены его значение, отсутствие free,
ограничение изменения объекта только этим FString и неизменность остальных inputs.

Windows Login `+99 == 6` получается при mode `epicgames` и доступном основном
handle включённого SDK, а не при любом SDK.
Обычный `nmp` возвращает mode 0. Это уточняет прежний caller fixture «mode 1»;
старое доказательство не переписывается. Getter mode не использует входной handle
как источник строки: внутренний text provider остаётся fixture.

Реальный flags getter ограничивает `Login+130` значениями 0/1. Прежний caller
fixture с raw 80 проверял копирование byte, а не возможные результаты getter.
`Login+131` остаётся raw byte из другого handle. Эти поля не объединяются.

Сохраняются guards целого caller: 15 строковых полей, числовые поля, SDK gates,
аргументы и порядок send / post-notify / SDK event / destructor, ABI и ownership.
Вошедшие native getters считаются по фактическим entry addresses.

## Метаданные устройства и сети

Collector `14560b0d0` проверен **статически**, без его исполнения. В source-bound
инструкциях найдено 27 последовательностей `literal → wide constructor → consumer
145601840`: 26 разных ключей, `I_World` встречается дважды. Порядок, адреса literals
и call sites сохранены в контексте и проверяются автоматически:

```text
I_GameCode, I_GameVersion, I_TID, I_CountryCD, I_PID, I_ChannelType,
I_SDKVersion, I_World, I_PlatformADID, I_ConnectIP, I_UDID,
I_JoinedCountryCode, I_DeviceOSVersion, I_DeviceModel, I_OS, I_Region,
I_TimeZone, I_LanguageCD, I_NMDeviceKey, I_NMIDFV, I_World, I_NMMarket,
I_NMNID, I_PCSeq, I_NMCPU, I_NMRAM, I_NMVGA
```

В дополнительных ветках есть форматы `I_DeviceKey` и `I_LogDes` с `MktClickId` /
`MktChannel`. Их значения, JSON escaping, условие успешного получения SDK data
и функции `14560a680` / `145601840` ещё не проверены исполнением.
Наличие имени не означает, что поле заполнено или принято сервером.

Это источник для [единого пресета](../../../../../vampir-headless/CONNECTION-PRESETS.md),
но не разрешение подставлять auth/session/geo поля. Реальный выходной IP определяется
соединением; `I_JoinedCountryCode` принадлежит аккаунту. Существующий default preset,
наблюдённые ключи и пользовательские настройки не изменялись.

## Проверки и следующий патч

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_sdk_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_prepare_context.py
```

Три SDK-теста прошли за 20,054 секунды, включая 2 016 replay и отказы при
подмене leaf bytes, callee, export, native binding и metadata consumer. Прежние
три caller-теста также проходят. Эти замеры не являются временем полного обновления.

`native-login-sdk-context` включён в game-login/update; coverage остаётся partial.
Кэш зависит от полного SHA, трёх exports, context/verifier/SDK fixture module,
harness, pinned runtime и тестов. При следующей версии нужны отдельная сверка
leaf bytes/RIP globals, direct callees, mode literals, cache layout, member ownership
и metadata key/consumer links. Отсутствующий unwind у leaf не разрешает расширять
Ghidra export на соседнюю функцию. Новый SHA автоматически не поддерживается.

Внутренние SDK singleton / resolver / text provider / string methods, platform
и selector, aux metadata, allocator/destructor/send/post-event остаются fixtures.
Состояние synthetic; реальное SDK storage, токены, metadata values и конкурентные
изменения не доказаны. Далее — metadata collector/consumer и оставшиеся SDK
зависимости, интеграция writer/archive и текущий result reader. Source guard сохранён.
