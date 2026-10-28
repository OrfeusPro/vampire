# Автоматический Login: подготовка и SDK-getters 20 → 22

Target EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Reviewed база обоих семейств 1.13.20:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Машинные указатели, результаты и измерения — в
[AUTO-LOGIN-PREPARE-11322.json](AUTO-LOGIN-PREPARE-11322.json).

## Базовая подготовка

`login-prepare-v1` переносит prepare `0x1467d14e0 → 0x1467d1530` и constructor
`0x1456d7540 → 0x1456d7590`. Packet table `0x149928e90` связана с опубликованным
Login writer того же target SHA. Проверяются целые инструкции, локальные ветвления,
вызовы, RIP-ссылки, 32 роли fixture и 19 типизированных входов.
Изменение данных или неоднозначная связь оставляет конкретный блокер.

21 fixture имеет настоящую unwind boundary, ещё 11 — явно ограниченные тела
без unwind, целиком сравненные с источником. Эти тела здесь не исполняются.
Compiled tag pointer связан с новой строкой `4138E0A8C7421BE4F7F7078FF635DAD5`,
platform literals и enum default проверяются отдельно от BSS inputs и logging.
BSS принимается только внутри доказанного PE zero-fill interval.
Format literal — `RdPeer::Login() - ServerId( %d )`, без завершающего пробела.

672 native случая покрывают 14 сценариев × 6 selectors × пустой / непустой ввод
× 2 send results × 2 poison patterns. Проверяются поля пакета, порядок вызовов,
reset owner, allocations / cleanup, canaries и Win64 ABI, включая XMM6–XMM15.
SDK, strings, allocation, metadata, logging и send остаются именованными fixtures;
`native_sdk_used` и `native_metadata_used` равны false.

## Интеграция SDK-getters

`login-sdk-v1` использует подтверждённую базовую подготовку target SHA и отдельно
сравнивает её с последней reviewed базой своего семейства. Исполняются пять roots:
prepare, constructor и три getters — `0x14560aec0`, `0x14560b060`, `0x145609e40`.
Ещё шесть returning leaves проверяются по полным bytes, инструкциям и данным:
manager, owner number, language, flags manager и два flag getters.
Roots, листья, оставшиеся outer fixtures и шесть inner fixtures не могут подменять
друг друга совпавшими адресами.

2016 native случаев расширяют ту же матрицу тремя состояниями синтетического кэша:
`warm`, `resolve`, `absent`. `native_sdk_used` равен true, `native_metadata_used` —
false. Store, cache resolver, string assignment и backend остаются fixtures.
Cache resolver допускается только как точный unexecuted dispatch thunk
`48 8b 01 48 ff a0 10 04 00 00` с шестью padding bytes CC и alignment 16.
Это не разрешение исполнять произвольные косвенные переходы.

Связи 27 metadata fields, ключи и consumer проверены статически по collector
`0x14560b0c0` и consumer `0x145601830`. Исполнение collector и происхождение
настоящих SDK values этим пакетом не подтверждаются. Native SDK helpers здесь
читают искусственные owner / manager / language / flags objects.

Оба допуска проверяют точную полную матрицу, а не только число строк отчёта:
дубли не заменяют пропущенные сочетания. Отрицательные synthetic tests охватывают
подмену layout, proof, source, scopes, fixture boundaries и неполные matrices.

## Обновление, кэш и остаток

Оба правила зарегистрированы в [native-check-adapters.json](../../native-check-adapters.json)
и подключены к обычному `update --auto`, общему Journal и missing-only collector.
Пять отсутствовавших roots собраны одним Ghidra пакетом с переиспользованием
проекта. Предварительный request из двух roots заменён общим и отдельно не собирался.
Полный анализ EXE, новое подключение к игре и игровые команды не выполнялись.

Базовый native proof сохранился до обрыва процесса при следующем plan stage.
После проверки отсутствия прежнего владельца и его детей продолжение восстановило
журнал, пересчитало незавершённый plan и использовало готовый native report.
Три последовательных прохода после восстановления не повторяли base suite.
После единственного SDK исполнения два повтора использовали готовый report.
Итоговый общий проход шести drivers
переиспользовал 18 этапов: ноль новых JVM и native replay. Прежние UTF-8 / writer /
archive / Version suites не исполнялись заново. Измерения selected drivers не
включают предшествующий сбор экспортов и полный аудит установки.

Context, transfer proof и native report сохраняются неизменяемыми. Только после
проверки всех ссылок обновляются `generated-login-prepare/index.json` и
`generated-login-sdk/index.json` в библиотеке ресурсов. Same-target повтор
использует прежний proof без self-transfer. Это базы семейств, не runtime profiles.

Код двух adapters подготовили субагенты; независимая проверка нашла и закрыла
пробел допуска неполной матрицы. Координатор выполнил интеграцию и serialized
native / cache acceptance. 15 base tests и 23 SDK tests входят в штатный tooling
aggregate. 672 + 2016 случая имеют пересекающееся исполнение подготовки;
складывать их как независимые функции или доказательства целого входа нельзя.

Остаются native helper integration Version, Login metadata и настоящий SDK
backend, остальные response readers / handlers / registration / composition,
clock / heartbeat и world contracts. Runtime admission и онлайн-вход 1.13.22
не выданы; текущая игровая сессия и назначенный ей пакет не меняются.
