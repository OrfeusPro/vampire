# GMC2 geo-контекст и проверка версии 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [NID helpers](HEADLESS-NID-PRIMITIVES-11316.md).
Сохранённый EXE / synthetic memory; реальные аккаунты, сеть и игра не используются.

## Текущая цепочка источников

Готовый RefreshSDKConstants передаёт callback `0x1444dee00`; его явный export
подтвердил CALL `0x1444cf500`. Следующий export handler подтвердил CALL
geo consumer `0x1444f8b10`. Это текущие ссылки, а не перенос старого адреса
по общему смещению. Отдельный точный diagnostic поиск нашёл SetCountryCode
`0x1445515c0` по ASCII `0x14953aa50`.

Выполнены настоящий GMC2 constructor `0x1444c4210` и resultData initializer
`0x1411b05c0`. Подтверждены descriptors:

| Descriptor | Точный ключ |
| --- | --- |
| Global 0x14b561df0 | resultData |
| Manager +0xc0 | geoIp |
| Manager +0xd0 | clientIp |
| Manager +0xe0 | geoLocation |
| Manager +0xf0 | isoCountry |

Geo slice `0x1444f8b3c..0x1444f8c03` вызывает nested wrappers для resultData,
затем geoIp; string wrapper получает clientIp и geoLocation. Настоящие move
stores переносят FString clientIp в settings +0x38. GeoLocation передаётся
SetCountryCode с notification flag 0. Callback / response-handler links проверены
статически, полная обработка HTTP / JSON / constants не исполнена.

## Реальный SetCountryCode

Исполнен весь метод `0x1445515c0` с logging / notification disabled и настоящий
case-insensitive compare leaf `0x14145f1e0`, включая таблицу из EXE.
Sentinel UTF-16 `A1` находится по `0x148a1542c`.

Если incoming равен A1 **или a1** и прежний country FString непустой, прежнее
значение сохраняется. Во всех других проверенных случаях выполняется assignment
в settings +0x3f0. Case-insensitive поведение выявлено actual compare, а не
fixture результата. Предыдущая portable policy проверяла только A1 и расходилась
с текущим клиентом для a1; новая source-specific policy исправляет этот случай.

672 native cases: четыре poison fills × четыре прежних country values
(zero-count / allocated empty / JP / HK) × семь incoming values
(zero-count / allocated empty / A1 / a1 / JP / HK / A1x) × три synthetic IP values
(zero-count / allocated empty / 1.1.1.1) × initialized / lazy settings CDO.
Проверены путь ключей, receivers / destinations, native IP move, country result,
assignment gate и canaries вокруг country descriptor.

Fixtures: JSON nested/string wrappers, FString storage / assignment / free,
exit registration и settings CDO acquisition. Это bindings извлечения,
не полная реализация JSON lookup / conversion. Native допускает пустые values,
но строгая локальная политика runtime продолжает их отклонять.
Не исполнены остальной geo-map / constants update, notification, persistence,
browser callbacks или авторизация. Реальные IP / route не наблюдались.

## Изменение runtime policy

`gmc2_context.py` принимает только два явных проверенных SHA: прежний 98802d…
и текущий d00a19…. Geo object сохраняет SHA своего decoder input; SdkInputs
требует точного совпадения SHA bundle / geo. Неизвестная версия и смешивание
старого geo с новой сессией отклоняются. Account / route / selected profile /
age guards сохраняются. Для текущего SHA sentinel включает a1; прежняя
историческая policy не переносится автоматически.

Это перенос только GMC2 context policy. `sdk-source-profile.py` ещё указывает
на старую сборку; его установленный EXE guard не отключён. Следующим этапом
нужно собрать / подключить текущий SDK profile и проверить весь offline путь.
Поддержка полной игровой сессии новой сборки этим не объявляется.

## Browser boundary и проверки

Отдельно выполнена команда `python -X utf8 phone-exit/bots/vampir-headless/nid-browser.py --smoke`:
synthetic_only / callback_captured / response_code_checked true, blocked_external 2,
blocked_popups 1, game_started false. WebView использует synthetic response filter,
auth endpoint не посещается. Девять browser unit tests прошли; это локальная
boundary проверка, не авторизация Netmarble или доверие к настоящему токену.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-gmc2-geo-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gmc2_geo_11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gmc2_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_sdk_runner.py
```

Четыре новых geo-теста (672 cases / policy parity / version isolation / invalid
values / corrupted export), шесть прежних context tests и девять SDK runner tests
прошли. Дополнительный `test_vampir_gmc2_runtime.py`: четыре проходят, один
останавливается на установленном EXE guard старого SDK profile. Это оставшийся
этап переноса профиля; guard не был обойдён ради прохождения теста.

Check `gmc2-geo-native-11316` связан с source / six exports / tools / runtime policy.
В release-update-targets.json записаны addresses, scopes и required_checks.
При следующем обновлении нужно сверить callback links, constructor key offsets,
geo slice / wrappers / setter / compare и повторить source-specific policy tests.
Автоматическое разрешение новой runtime версии не выдаётся.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Callback `run-e780fb3fe6db/details.json`, SHA `0967705efbbe8b625a2176a36ee903b39020d9c6e6b714e4d5ab903ef4b1b2f4`.
- Handler / setter `run-22a80de53437/details.json`, SHA `67dabcb549a4b24d5d89df01904966cda40ac129a0536804c2718c2c070afcdf`.
- Geo / wrappers `run-c7fac48d96a1/details.json`, SHA `4a966a1a0f30e281fe55f90fb72b38362a5ec9d07232b5cc0e908856e470881a`.
- Все exports находятся в `ghidra/request-exports/<SHA>/`; остальные три exports
  перечислены в tool / report и ранее проверенных SDK / launcher evidence.
- Native report: `code-clues/gmc2-geo-11316/990e41054b9d890ca9611a358645da4a3d28ccca06958f5dd397ada8e9ae1a72/manifest.json`.

Далее подключить текущий SDK profile, сохраняя installed SHA / account / route /
freshness guards; перед живой сессией повторить весь offline auth input flow.
