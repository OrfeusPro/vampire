# Пакет whole Version prepare 1.13.18

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Предыдущие [constructors/tag](HEADLESS-TAG-CONSTRUCTORS-11318.md) и
[wire слой](HEADLESS-WIRE-BATCH-11318.md) используются как готовые результаты.
Сокеты, авторизация и активация профиля не запускались.

## Воспроизводимый перенос

`align-version-contexts-11318.py` начинает с трёх известных пар
prepare/constructor/wrapper и фиксированного списка 20 roots. Он проверяет
полную последовательность инструкций, локальные control-flow edges и связи
прямых вызовов/RIP references, затем переносит десять contexts. Произвольные
callees не обходятся; отсутствие соответствия, неоднозначность или изменение
формы отклоняется. Пара адресов сама по себе не подтверждает семантику.

17 отсутствовавших helper roots получены одним collect:
`run-f808531f96e5/details.json`, SHA256
`b0c641b4af6e227ca2fece365d842fac58c069fe3b333652be397c4477151478`.
Три caller roots повторно не экспортировались: используется
`run-b92399af7eb5/details.json`, SHA256
`960ac4e0d502d7290284acfe31c3e733d0e843231ba04c05ba12976a18fb102b`.
При replay проверяются whole source ranges, blocks, direct flow и conditional
fallthroughs. Явный бюджет итоговой композиции сохранён: 19 roots.

| Часть | Текущие roots |
| --- | --- |
| Prepare / constructor | 1467CEB70 / 1456D7FC0 |
| NM provider / getter | 1445CD1E0 / 1444ECB90 |
| Platform selector / context store / lookup | 1445CE5E0 / 1445C4E90 / 1416DD660 |
| Windows suffix | 1415C9380 |
| CPU formatter / first / second | 14144D1A0 / 1415C6E80 / 1415C6E60 |
| CPU trim / end / start | 141439FC0 / 141439DB0 / 14143A030 |
| Combiners first / second / copy / append / grow | 14142BC30 / 14142BB60 / 1414266A0 / 141429E10 / 141438050 |

Контексты закрепляют актуальные globals, imports, fixture targets, call sites,
wrapper table/send slot и compiled tag source. Tag literal теперь выбирается
из source-specific metadata; исторический fallback разрешён только для
полного SHA 1.13.16. Новый SHA без metadata или с неверным literal отклоняется.
Существующие contexts 1.13.16 сохранены.

## 1072 native сценария

| Контекст | Случаев |
| --- | ---: |
| Whole prepare с boundary fixtures | 64 |
| NM provider/getter | 36 |
| CPU formatter/getters/trim | 72 |
| Windows suffix | 48 |
| Combiners/copy/append/grow | 256 |
| Platform selector/store/lookup | 116 |
| Prepare + native NM | 64 |
| Prepare + native system/NM | 64 |
| Prepare + native combiners/system/NM | 64 |
| Prepare + native platform/combiners/system/NM | 288 |

Проверены empty/Unicode, context present/absent, enum 0/max, send return 0/1,
poison, ABI/guards и cleanup. Итоговая композиция проверяет cold/warm cache,
duplicate/missing/negative count, Windows/Android/IOS/unknown, index projection
и окончательные packet fields. Helper результаты передаются через общую
память; итоговые CPU/Windows/combiner/platform строки не подставляются fixture.
Подробный первый отчёт полной композиции:
`knowledge/native-version-prepare-checks/4f9bff5926a97629093386c77b2f2f1885c715964addb271938bc6d23cc90c23/manifest.json`.

## Автоматизация и ограничения

Семь существующих offline checks получили текущий SHA, contexts и exports;
`on_update` сохранён. В Version contract перенесены 15 helper bindings.
Новые contexts формирует общий alignment tool, а тесты выполняют native replay;
неподтверждённый matching не используется как допуск runtime.

Все семь штатных наборов прошли: 28 тестов вместе с прежними регрессиями.
Отчёты закреплены в research request
`ff4a3cb1220a7c1fa2911228eeed83e6db627093622e2762b2f92e16f159d1fb`.
Alignment report:
`knowledge/version-context-alignment-11318/9d9a2ee8939b8788d431afc60c94edf58ce1e85f855a602df7d05ddd7667bc48/manifest.json`.

Реальные OS/CRT/TLS, CPU initializer, SDK/storage/GUID, platform text/FName,
type/resolver/value-at, allocation/copy/free/destructor/log и send остаются
явными fixtures. NM в композиции использует initialized synthetic cache;
реальные identity values не читались. Полная подготовка исполняется до send
capture и cleanup, но wire/send composition и серверное принятие не доказаны.
VersionResult, Login preparation и остальные SDK/GMC2/NID зависимости требуют
отдельного пакета. Профиль пока не активирован.
