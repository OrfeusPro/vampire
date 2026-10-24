# Native объединение строк Version 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Два последовательных экспорта получили четыре недостающих roots; copy constructor
найден в готовом экспорте. Общий проект Ghidra использован повторно.

| Экспорт | SHA256 |
| --- | --- |
| `run-ba23b5dcaf08/details.json` | `47c4f0b3e5bcebd5e8e37b886c953d23972612431dc7f3702ec59f56e18633d9` |
| `run-6b15c7b74a42/details.json` | `2b6c75ac3935d9f3ae9fae69eb8a1f539c0261929c0c985e1562eb605b8f974d` |
| `run-1740fcc91625/details.json` | `f2cdd2d5e37669d223dbbf74217780bed1c64090827b75d3b62c78d99f7dce38` |

## Проверенный результат

В 256 сценариях исполнены целые combiners `14142bc30` / `14142bb60`, copy
`1414266a0`, append `141429e10` и capacity grow `141438050`.
Первый combiner при пустой левой строке передаёт выходу владение правой строкой;
при непустой создаёт отдельный буфер. Второй при непустой левой строке забирает
её буфер, при пустой — копирует правую. Исходные дескрипторы после move обнуляются.

Проверены четыре poison pattern, пустой FString с / без allocation, пустые и
непустые части, Windows suffix, Unicode / surrogate pair, embedded NUL, длинные
строки, точная и запасная capacity. Результат соответствует объединению UTF-16
данных с учётом count, включая NUL внутри строки. Проверены ownership, отсутствие
лишних живых allocations, canaries, nonvolatile registers и RSP.
Два дополнительных случая длины int32 max + 1 дошли до overflow handler;
он остановлен fixture до trap / обращения к несуществующему большому буферу.

В 64 whole Version prepare сценариях вместо двух final-text fixtures теперь
исполняются эти пять функций вместе с native Windows / CPU / NM. В поле `+28`
попадает `context + "_" + Windows suffix`; при отсутствии context остаётся `_`
перед suffix, при ошибке Windows API — завершающий `_`. Caller fields, cleanup,
входные данные, owner reset, send 0 / 1 и ABI прошли проверку на общей памяти.
Это не сборка поля из результатов отдельных replay.

## Оставшиеся границы

Resize, append-grow, allocator, size quantization и внутренний copy — явные
fixtures. Copy возвращает destination; возможное другое short-copy поведение
внутренней функции `141453890` и реальные allocation failures не подтверждены.
Allocation fixtures сохраняют прежние байты и учитывают владение. Aliasing
дескрипторов не проверялся. Методы heap / CRT целиком не исполнялись.

Platform/context в общей цепочке ещё fixtures. OS / CPU cache и NM cache
синтетические; реальное окружение и CPU initializer не проверены. String
constructors, destructor, logs и send остаются fixtures. Login prepare/result,
framing, сеть, runtime promotion и смена baseline не выполнялись.

[Контекст combiners](../../native-contexts/version-combiner-11316.json),
[контекст whole prepare](../../native-contexts/version-prepare-combiner-11316.json),
[машинные результаты](VERSION-COMBINERS-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_combiner_context.py
```

## Автоматизация

`native-version-combiner-context` включён в game-version / update. В зависимости
входят verifier, оба fixture-модуля интеграции, contexts, tests, pinned runtime
и восемь exports. Подмена call site, helper binding или SHA экспорта отклоняется.
Готовые результаты повторно используются при тех же входах; посторонняя документация
не запускает replay. Для нового SHA переносить явные caller/callee связи и ownership,
не копировать адреса автоматически. Следующий этап — реальные platform/context
в whole Version prepare, затем целый Login prepare и result readers.
