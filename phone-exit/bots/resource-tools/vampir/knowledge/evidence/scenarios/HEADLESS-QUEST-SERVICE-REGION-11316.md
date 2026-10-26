# Service RegionType: native lookup и миграция ключа настроек

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Навигационный request
`bc0a0c8386556425ce206626692771e48b8d3b0632ca96c5a7ee97e56b5d091b`
нашёл отсутствующие материалы. Getter `14556ae90` не имеет unwind root;
exact 8-byte leaf `488b05f1980706c3` читает pointer global `14b5e4788`.
Для него Ghidra collection не запускалась. Actual lookup root экспортирован
через request `0a9415b7a8fc389e8ffb21019a6fbde9420ad7c741e215673d471b897b639bd8`.
Run-f7f3737dd318, SHA
`062c124a787b27dc6af3a7a6982905887b4b989d0279b6ae89b9769e39672b06`.
Whole `14556b8b0` имеет block/direct-flow coverage.

## Проверенная совместная цепочка

В [service setup replay](HEADLESS-QUEST-SERVICE-SETUP-11316.md) добавлен explicit
режим, где getter leaf и lookup root выполняются native вместо двух прежних
fixtures. Setter `145c21f20` остаётся native. Global provider pointer задан
synthetic; current RegionType / actual user settings этим не устанавливаются.

Lookup сначала обнуляет output uint32, получает dynamic key через `14556b740`
и вызывает `1445ceaa0` с key, output и пустым FString аргументом. При неудаче
строит literal key `RegionSelect` из UTF-16 source `1498fd668` и повторяет чтение.
Если и оно неуспешно, возвращает false; setter читает provider+А8 как fallback.

Если legacy key прочитан успешно, lookup вызывает `1445d7220` дважды:
для dynamic key и `RegionSelect_PreLogin` (source literal `1498fd638`), с тем же
найденным числовым значением. Затем возвращает true. При успехе primary read
записей нет. Эти вызовы похожи на миграцию ключа; реальные storage semantics
`1445ceaa0`/`1445d7220` ещё не доказаны, поэтому fixture хранит только намерения.

**Реальных config writes нет:** code выполняется в Unicorn, обе операции IO
перехватываются bounded fixtures и записываются в массив test report.
Действующие профили / настройки игры / owner не читаются и не меняются.

## 216 native случаев

Прежняя matrix 3 region values × 3 server values × dirty flag × equal/different
old region × equal/different old server дополнена тремя путями lookup:

- Primary read success — 72 случая, без writes.
- Primary missing / RegionSelect success — 72 случая, две записи в заданном
  порядке, primary dynamic key затем RegionSelect_PreLogin.
- Оба чтения missing — 72 случая, без writes, native getter вызывается снова
  и native setter читает fallback+А8.

Конечные manager+78/+7C и dirty+80/ready+81 проверены как прежде. Порядок key/read/
write callback вызовов, result values, string ownership/cleanup, provider bytes,
все остальные manager fields и guards проверены. Остаточных fixture allocations
нет. Legacy literal names проверяются по переданным native строкам, не
подставляются вместо соответствующих инструкций.

## Fixtures и ограничения

`14556b740` (динамический ключ), config read/write, FString initialization/free
остаются fixtures. Dynamic key явно `SyntheticRegionKey`; это **не имя реального
настроечного ключа**. Config read success/values синтетические. Пустые строковые
descriptors имеют count=0, allocations успешны. Настоящая конфигурация, cache+A8
и связь числа со строковым JP/HK ещё неизвестны.

`active_region_verified=false`, `order_admitted=false`. Whole login handler
не выполняется, игровая сеть / команды / перезапуск сессии не используются.
Далее — dynamic key builder `14556b740`, readers/writers `1445ceaa0`/`1445d7220`,
источник fallback+A8; затем native ServicePhase / current policy / full catalog.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_region_11316.py
```

Общий replay `replay-quest-service-setup-11316.py`, контекст
`knowledge/native-contexts/quest-service-region-11316.json`, offline check
`native-quest-service-region-11316`; старый fixture mode остаётся отдельным check.
Артефакт:
`code-clues/quest-service-region-11316/23960c98fca0b91da0cdc4345130bb02d193a2a17394f74272fd2a3dd659fa47/manifest.json`.
