# SDK profile-кандидат 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки платформы](HEADLESS-SDK-PLATFORM-11316.md).
Это offline-сборка профиля, без авторизации, процесса игры и HTTP-запросов.

## Связь constructor и Start

Новый `replay-gmc2-base-11316.py` исполняет настоящий GMC2 constructor
`0x1444c4210`, затем Start `0x144508210` для всех 256 zone bytes × flag 0 / 1.
Для каждого из 512 случаев проверены destination +0x1e8, source offset,
строка URL из сконструированного source FString и передача flag в global.
Canaries manager сохранены.

| Zone | Source offset | Base |
| --- | --- | --- |
| 0 | +0x150 | https://alpha-apis.netmarble.com/gc2 |
| 2 | +0x170 | https://apis.netmarble.com/gc2 |
| 3 | +0x180 | https://dr-apis.netmarble.com/gc2 |
| Остальные | +0x160 | https://dev-apis.netmarble.com/gc2 |

FString storage, class/CDO getter, logging и capture последнего copy — fixtures.
Выполнение останавливается на copy boundary: запись строки в destination не
исполняется и не заявляется. Это дополняет прежнюю проверку выбора offset,
не заменяя границу fixture настоящим копированием.

## Сборка из шести reports

`build-sdk-profile-11316.py` использует шесть явно закреплённых immutable
native reports. Каждый проверяется по полному SHA, источнику, числу случаев,
хешам инструментов / dependencies, Ghidra evidence и portable helper.
Изменение зависимости требует нового replay. Старые source guard не менялись.

| Report | Случаев |
| --- | --- |
| Начальные settings / GMC constructor / SDK version | 9 |
| Game override / market selector | 106 |
| PC initializer / getter | 12 |
| Constructor + Start до copy boundary | 512 |
| URL builder | 27 |
| Headers capture | 73 |
| Всего | 739 |

Сборщик требует единственный production case real / NMENV отсутствует,
полный набор zone / flag, согласованность bases constructor со Start,
четыре PC случая и единственные canonical URL / public HTTP capture.
Отсутствующий native результат не заменяется значением portable helper:
helper используется только для дополнительного сравнения.

| Поле кандидата | Значение |
| --- | --- |
| Production zone / base | 2 / https://apis.netmarble.com/gc2 |
| Group / service | netmarbles-v5 / netmarbles |
| SDK version / BuildCode | 5.2.11 / 0 (строка A) |
| Market / GameCode | nmp / thered |
| Client ID | 18e6xn1vuR1lGrvR |
| OS label | PC, явный platform byte 3 |

NID raw webview type 0, английский язык, пустая страна и OS version остаются
явными локальными выборами. Фактические NID caller inputs новой сборки ещё
нужно сверить. Public GMC2 capture имеет пустой device key, шесть headers,
без account credentials. Реальная device identity здесь не читается.

Кандидат называется recovered-11316-candidate и сохраняется отдельно от runtime.
`runtime_enabled`, `network_ready`, `active_runtime_settings_verified` — false.
Он не подключён к панели или live runner и не заменяет recovered-release.
Файл не утверждает, что все native auth parsers новой сборки уже перенесены.

## Проверки и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-gmc2-base-11316.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-sdk-profile-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_profile_11316.py
```

Пять тестов проверяют повторяемость сборки, её public outputs / disabled flags,
все 512 base cases, отказ при противоречии constructor / Start / SDK version,
пропущенных PC/capture, дубликате override, повреждённом manifest и изменённой
dependency. При неудаче build не сохраняет новый профиль. Прежние reports
и профили не редактируются.

В release-update-targets.json у Start обновлены точные границы и required check,
а profile_assembly хранит tool, SHA и offline_candidate_only. Автоматическая
проверка текущих входов разрешена; runtime promotion остаётся отдельным этапом.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Base replay: `code-clues/gmc2-base-11316/9e51498c82c4f5b24c84808e7af80eff36fec25f1b8c55c03d5fd37c4e882b75/manifest.json`.
- Кандидат: `sdk-source-profiles/a67d0f9716fa6a23a97e01028c3d741d7be48d13ac82986fe7d781d7ae73549b/manifest.json`.
- Пути / SHA остальных пяти native reports закреплены в REPORTS сборщика
  и скопированы в evidence кандидата вместе с их fixture limits.

Далее сверить current NID caller inputs и source guards auth lifecycle,
подключить профиль явно и отдельно проверить живой вход при доступности серверов.
Согласованный offline profile сам по себе не доказывает принятие сервером.
