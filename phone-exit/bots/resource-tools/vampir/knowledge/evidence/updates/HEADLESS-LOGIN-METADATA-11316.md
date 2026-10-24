# Цепочка metadata Login 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
На общей памяти целиком исполнены шесть явных roots:

| Функция | Адрес |
| --- | --- |
| Collector | `14560b0d0` |
| Selector | `145601840` |
| SDK UserInfo loader | `14560a680` |
| UserInfo writer | `144557a00` |
| UserInfo copy | `145601590` |
| UserInfo move | `145600d00` |

Collector использует готовый `run-2c9766b1ab08`. Два новых адресных batch exports
сохранены в `run-8ce3965fd27d` (selector/loader) и `run-44e5a260bb97`
(writer/copy/move). Существующий проект использован без общего анализа EXE.
Полные SHA exports и все call sites закреплены в
[контексте](../../native-contexts/login-metadata-11316.json).
[Квитанция прогона](LOGIN-METADATA-11316.json).

## Проверенный путь значений

Loader получает backend через `145490870`, затем shared object через явные
fixtures. При доступности объекта вызывает `14452b0a0` → `144528720`, получает
UserInfo и копирует 37 FString descriptors от `+0` до `+240`. Затем writer
строит map, selector делает 27 выборок и collector собирает итоговую строку.
При отсутствии backend / shared object loader переносит пустой UserInfo,
возвращает 0, collector оставляет результат пустым.

Следующие 33 соответствия проверены по переданным адресам полей и размеченным
значениям; смещения шестнадцатеричные, относятся к UserInfo:

| Смещение | Ключ | Смещение | Ключ |
| --- | --- | --- | --- |
| `00` | I_OS | `10` | I_DeviceOSVersion |
| `20` | I_DeviceModel | `30` | I_NMManufacturer |
| `40` | I_NMModel | `60` | I_UDID |
| `80` | I_GameVersion | `90` | I_SDKVersion |
| `a0` | I_GameCode | `b0` | I_NMBuildCode |
| `c0` | I_NMMarket | `d0` | I_TID |
| `e0` | I_ConnectIP | `f0` | I_NMMobileIP |
| `100` | I_CountryCD | `110` | I_City |
| `120` | I_ChannelType | `130` | I_NMChannelCode |
| `140` | I_NMChannelUserID | `150` | I_PID |
| `160` | I_Region | `170` | I_JoinedCountryCode |
| `180` | I_LanguageCD | `190` | I_World |
| `1a0` | I_NMCharacterID | `1b0` | I_NMSessionID |
| `1c0` | I_TimeZone | `1f0` | I_NMCPU |
| `200` | I_NMRAM | `210` | I_NMVGA |
| `220` | I_NMResolution | `230` | I_NMNID |
| `240` | I_NMNIDChannelType | | |

Writer заменяет `+50` результатом NM getter и использует для I_NMDeviceKey;
`+70` получает ADID getter в режиме 1 и используется для I_PlatformADID.
I_NMIDFV идёт из отдельного getter. Эти getters здесь fixtures.
I_NMAppSetID / I_NMInstallPackageName пусты; I_NMAppSetIDScope — непрозрачный
variant constructor с аргументом 0, его преобразование не объявляется доказанным.
`+1d0` / `+1e0` не получили имён: копирование не доказывает назначение поля.

I_GameCode, I_NMBuildCode и I_NMCharacterID отсутствуют при пустых исходных
строках. Непустой `+230` разрешает сразу I_NMNID и I_NMNIDChannelType, даже
если второе значение пусто. Writer создаёт 39 ключей при заполненных полях и
34 при всех пустых. Collector выбирает только объявленные 27 ключей, с повтором
I_World; остальные map entries в основную строку не попадают.

При доступном дополнительном backend добавляется I_DeviceKey. При marketing
fixture добавляется I_LogDes с MktClickId и MktChannel. Ветви проверены независимо,
включая оба выключенных / оба включённых. Недоступность основного UserInfo
подавляет обе ветви. Реальные DeviceKey/marketing источники пока не доказаны.

## Матрица и владение памятью

288 случаев: 6 backend/control состояний × 6 наборов UserInfo × DeviceKey
вкл/выкл × marketing вкл/выкл × 2 poison pattern.

Backend состояния: отсутствует; shared object отсутствует; готов с последней
strong/weak ссылкой; две strong ссылки; последняя strong при двух weak;
готов без control block. Проверены реальные декременты refcounts, условные
virtual destructor вызовы и ABI их fixtures. Сами destructor bodies не исполнены.

UserInfo: заполнен, пуст, пустые gate fields, отдельно пустой NID, отдельно
пустой channel type, Unicode / кавычка / обратный слеш. Проверены точные исходные
адреса, копирование всех 37 полей, selector order/stride 40/value offset 16,
итоговый текст, source/canaries, отсутствие temporary leaks / repeated free,
освобождение map buffer и сохранение восьми nonvolatile регистров / RSP.

## Границы и следующие обновления

SDK factory/settings/UserInfo backend, map/hash/lookup/variant primitives,
строковые constructor/copy/append/format и cleanup остаются fixtures.
Строковый format выполняет ограниченную буквальную подстановку. Кавычки и слеш
не доказывают JSON escaping реального CRT, проверенный текст может быть невалидным
JSON. Diagnostic branch выключена; неизвестное исполнение harness отклоняет.
Реальное заполнение SDK UserInfo, значения устройств / сети, токены и concurrency
не проверены. Цепочка ещё не включена в whole Login replay; сеть не запускалась,
source guard, baseline, default preset и рабочие аккаунты не изменялись.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_metadata_context.py
```

Три теста прошли за 16,224 секунды: общий pipeline и отказы на изменённых SHA,
export, callee и selector order. Это время этого набора, не всего обновления.
`native-login-metadata-context` подключён к game-login/update. Кэш зависит от
контекста, verifier/harness/runtime/тестов и трёх exports. Новый SHA требует
отдельной сверки calls, offsets, gates, refcount lifecycle, строковых literals
и обязательного прогона; автоматического продвижения runtime нет.

Далее: реальные источники UserInfo и строковые / map / variant primitives,
интеграция metadata в whole Login, соединение writer/archive и result reader.
Готовые шесть roots повторно не выгружать.
