# Общий пакет сериализации Version/Login 1.13.18

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Общий код проверен один раз для обоих контрактов. Предыдущий результат:
[архив 1.13.16](HEADLESS-ARCHIVE-WIRE-11316.md).

## Поиск и экспорт

Готового BinDiff сравнения 1.13.16 → 1.13.18 в библиотеке нет. Кандидаты найдены
в пределах ±64 KiB каждого объявленного старого root: сначала 12 байт префикса,
затем полная последовательность инструкций с маскированием branch immediates
и RIP displacements. Это только поиск кандидата; роли далее проверены через
реальные вызовы, vtables и native replay. Не выполнялся анализ всего EXE.

Первый collect с дополнительным growth root сохранил отказ Ghidra:
`run-0498d77af615/headless.log`, decompiler block outside unwind ranges.
Growth не исполнялся и в прежнем preallocated proof; его body исключён из
нового задания, вызов остаётся явно запрещённым fixture. Повторный collect
с 14 исполняемыми roots завершился успешно:
`run-c95a2683d479/details.json`, SHA256
`2f85577e334153842614e86fb10d9de508459a072da2d507ffb5af9c32e63b41`.

## Проверенные связи

| Часть | Адреса текущего SHA |
| --- | --- |
| UTF-8 length / converter | 14144C550 / 1414465F0 |
| Scalar encoder leaf | 14143F320, 317 закреплённых байт |
| String writer | 144AAD610 |
| Archive base / constructor | 144AAC9B0 / 144AACED0 |
| Archive string / u8 / u16 / u32 | 144AACBC0 / 144AACC10 / 144AACC40 / 144AACC70 |
| Archive raw / u64 / bool | 144AACD00 / 144AACDC0 / 144AACDF0 |
| Version / Login writer | 1456E8C10 / 1456E8750 |

Constructor указывает на archive table149672120. Сверены slots string+28,
u16+60, raw+88, u64+B8, u32+C8, u8+E0, bool+F0. Таблицы пакетов149928508 и
149927BD0 указывают на соответствующий writer в slot+10. Encoder и два
archive leaves имеют буквальные bytes/SHA и замкнутые переходы; они не
объявляются unwind functions. Для остальных roots дополнительно проверяются
полные исходные диапазоны, blocks, direct flow и conditional fallthroughs.

Перенесены source-bound metadata, а не только адреса: memcpy thunk1487F60D9,
allocator146908E50, security helper1487E9300 и cookie14B273780. Реальные
RIP links сверяются перед исполнением. IAT14899C018 проверен по PE как
`api-ms-win-crt-runtime-l1-1-0.dll!_invalid_parameter_noinfo_noreturn`;
обе ссылки writer должны вести в этот slot. Error path не исполняется.
Старые адреса metadata допускаются по умолчанию только для прежнего полного
SHA; новый source требует явные metadata.

## 559 сценариев

- 142 строковых и 80 scalar UTF-8 случаев: ёмкость, malformed units,
  replacement, pointers и canaries;
- 228 whole string writer случаев: NUL/count gate, inline/heap/aligned
  storage, return byte и cleanup с явными allocator/free/security fixtures;
- 45 archive/scalar случаев и 64 целых тела Version/Login: native writers,
  UTF-8 и archive methods формируют байты, совпадающие с независимым ожиданием.
  Login тела также проходят portable decode/encode roundtrip.

12 unittest тестов прошли: прежние регрессии и новые проверки 1.13.18,
включая отказ при неверном cookie link, отсутствии явных metadata и неверном
archive helper. Запуск auth/сокетов и активация профиля отсутствуют.

Текущие подробные reports в библиотеке ресурсов:

- `knowledge/native-utf8-checks/ed442135de52bac039aca980862f08aae874830dc0f580c2b42ebba194039ddc/manifest.json`;
- `knowledge/native-string-writer-checks/38380fcdf1aac1872b87ab064bd3d20d0d1964b852c7a8fca771c823abd5ba35/manifest.json`;
- `knowledge/native-archive-wire-checks/08ff05dc6b26da8ef9eda8dfca6f4dbce830b601d54c553c809d414dc603f5d3/manifest.json`.

## Автоматизация и границы

Три существующих checks получили новый SHA, contexts и dependencies; `on_update`
сохранён. Они используются обоими контрактами, результаты кэшируются по inputs.
Для Version/Login внесены четыре reviewed bindings: packet writer и общий
string writer для каждого. В update targets закреплены источники, проверки
и ограничения. Старые contexts и facts не переписаны.

Буфер архива заранее выделен, 16384 байта. Growth отклоняется; реальные
allocation/free/memcpy/security, allocation failure, framing и строки 65535
байт не доказаны. Подготовка объектов Version/Login, SDK context, result
readers/handlers и онлайн-сессия остаются отдельными проверками. Совпадение
wire bodies не является допуском профиля или подтверждением входа.
