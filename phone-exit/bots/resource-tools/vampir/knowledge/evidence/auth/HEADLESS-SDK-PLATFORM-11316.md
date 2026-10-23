# PC platform getter и полнота switch в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки GMC2 headers](HEADLESS-GMC2-HEADERS-NATIVE-11316.md).
Источник — сохранённый EXE; native replay работает только в синтетической
памяти. Авторизация, сеть и процесс игры не используются.

## Поиск и найденная неполнота

Полная UTF-16 строка PC `0x14952b6b0` имеет 17 roots с проверенными RIP LEA.
Выбранный кандидат initializer `0x1411b5c10` передаёт её в global
`0x14b562888`. По явному этому destination найден один raw MOV RIP candidate
в root `0x144532410`, инструкция `0x144532477`. До экспорта это был кандидат,
а не доказанная роль getter. Простой whole-unwind decode остановился на
таблице переходов: её байты нельзя выдавать за инструкции.

Первый Ghidra export `run-c3ce8f5a8a15` дал псевдокод switch, но только
21 инструкцию входного / default блоков. Список инструкций снимался до
декомпиляции; case blocks ещё не были disassembled. Материал сохранён.
Индекс теперь помечает его incomplete: switch с unresolved indirect dispatch
и без block coverage не считается готовым для reuse.

## Исправление экспорта

Collector передаёт явные unwind ranges только запрошенных roots: максимум
32 диапазона / 65 536 байт на функцию. Экспортёр включает HighFunction blocks,
декомпилирует, затем ограниченно disassemble каждый блок внутри этих диапазонов.
Максимум 512 блоков, code analysis отключён. Ни соседние функции, ни дерево
вызовов автоматически не добавляются. Instruction listing снимается после
этого; сохраняются decompiler_block_starts и block_coverage_complete.

Новое сохранение export требует положительную block coverage. Индекс также
отклоняет claim полноты, если начало блока отсутствует в instructions.
Исторические exports без switch остаются доступными; массового повторного
анализа не выполнялось. По новому request повторно получен только неполный
getter. Новый export `run-cbdf156bd3fe`: 75 инструкций, 11 блоков.
Последующее уточнение exporter отклоняет пустые blocks / отсутствующий
HighFunction; Java-код успешно скомпилирован закреплённым JDK / Ghidra.

## Native-проверка

`replay-sdk-platform-11316.py` проверяет полный SHA EXE, два exports,
байты всех исполняемых инструкций и наличие начал case blocks. Используются
actual initializer, getter и таблица switch из EXE. Capstone 5.0.6 / Unicorn 2.1.4.

12 случаев: poison fills 0 / 0x55 / 0xaa / 0xff × platform bytes 3 / 2 / 255.
Во всех четырёх заполнениях 3 возвращает PC, 2 и 255 — пустую строку.
Return receiver, FString counts / termination и canaries до / после результата
проверены. Другие platform labels не заявляются.

Fixtures: FString constructor / allocation, проверенный memcpy import,
регистрация завершения. PC byte 3 — явный локальный выбор; фактический NID
caller новой сборки и его console / TLS overrides здесь не исполнены.
Полный startup / auth lifecycle / серверная совместимость не доказаны.

## Проверки и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-platform-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_platform_11316.py
```

Три platform-теста: результаты 12 случаев, blocks и отказ при изменённых
source / export. Восемь collector tests покрывают source ranges и запрет
сохранения exports без block coverage. Семь index tests дополнительно
проверяют, что неполный switch / отсутствующий block не заменяет полный
вариант. Двенадцать lifecycle tests прошли после изменения importer.
Mock collector tests не доказывают реальную Ghidra-выгрузку; её подтверждает
отдельный завершённый collect с сохранённым project / provenance.

В release-update-targets.json записаны source-bound адреса, проверки и границы
автоматизации. Поиск по PC остаётся assisted из-за множества references.
Проверка текущего SHA автоматическая; новый SHA требует выбора кандидатов
и переноса тестов, runtime автоматически не продвигается.

Библиотека `F:/PhoneExit Resources/Vampir/`:

| Материал | Путь / SHA256 |
| --- | --- |
| Initializer и прежний incomplete getter | `ghidra/request-exports/<SHA>/run-c3ce8f5a8a15/details.json` / `73bb7ecedbe7e575570f7897964d72ffea43833a75d964613a05321d15c85470` |
| Getter с blocks | `ghidra/request-exports/<SHA>/run-cbdf156bd3fe/details.json` / `08c859aeb566cbf9b51838965a43d3a9ee02837c2a9de2fc5099b9d8b4ac4e9c` |
| Replay | `code-clues/sdk-platform-11316/10192549a166a8f1d6db5a4f7f9e89accc5499ce0412db530f20ff1f9984e828/manifest.json` |

Далее собрать новый SDK source profile из актуальных reports; проверить
его consistency / provenance и отдельно NID caller inputs перед живым входом.
