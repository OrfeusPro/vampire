# Дополнительные параметры NID в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [базовых context pairs](HEADLESS-NID-CONTEXT-11316.md).
Проверка сохранённого EXE в synthetic memory, без сети и процесса игры.

## Проверенное поведение

`replay-nid-extensions-11316.py` исполняет участок текущего
FNetmarbleIDContent::CheckPossibleToOpen `0x1450e3c80`:
`0x1450e43d3..0x1450e48aa`, до следующего account getter.
Проверяются полный SHA EXE, SHA готового export и байты инструкций.
Capstone 5.0.6 / Unicorn 2.1.4; конечные instruction / string / heap budgets.

| Значение owner +0x150 | authType | Аргумент converter для webViewType | Получение credential |
| --- | --- | --- | --- |
| 0 | signin | 0 | Нет |
| 1 | linkidp | 0 | Нет |
| 2 | withdraw | 0 | Нет |
| 3 | agreements | 0 | Нет |
| 4 | signin | byte по 0x14b5d5268 | Да, при непустом optional object |
| 5 | linkidp | byte по 0x14b5d5268 | Да, при непустом optional object |
| 6 / 0xffffffff | Поле не добавляется | 0 | Нет |

Это фактические имена ключей и строковые значения из текущего EXE.
Не следует заменять `webViewType` сокращением `webV` в запросе.
Значение `webViewType` здесь намеренно помечено `fixture-web-<byte>`:
converter `0x1450ed350` ещё не исполнен. Его аргумент и gate подтверждены,
реальное строковое преобразование остаётся неизвестным.

Для modes 4 / 5 optional getter `0x1450e9720` получает owner +0x28 и тот же
byte. При непустом объекте вызывается virtual slot +0x8, затем serializer
`0x144488e50` с mode 1; его результат добавляется как `credential`.
В тесте это исключительно `fixture-extra`, без настоящих учётных данных.

256 сценариев: четыре poison fills × восемь modes × четыре значения byte
(0 / 1 / 2 / 255) × пустой / непустой optional object. Проверены порядок
добавляемых pairs, отсутствие authType у неизвестных modes, short circuit
optional path, receiver / destination / serializer mode и canaries.

## Границы доказательства

Map insertion, converter, optional getter / virtual object / serializer /
cleanup и FString storage / free — fixtures. Shared pointer не имеет reference
controller; refcount / destructor branches не покрыты. Базовые десять pairs
проверены отдельно, единое исполнение всей функции здесь не заявляется.
Ранние URL / availability gates, последующие account additions, query encoding,
browser callbacks и авторизация ещё не проверены. Runtime profile не включён.

Готовый Ghidra export отмечает decompilation / block coverage как завершённые,
но в instruction list отсутствуют шесть коротких cleanup tails. Native guard
остановил выполнение на первом таком переходе. Исходный export сохранён;
для этого replay отдельно закреплены точные 64 байта по адресам
`0x1450e463f`, `0x1450e46b8`, `0x1450e4731`, `0x1450e47aa`,
`0x1450e4823`, `0x1450e4899`: MOV загружает указатель строки, JMP ведёт к
общему cleanup `0x1450e48a0` (последний MOV переходит туда последовательно).
Каждая инструкция сверяется с EXE и декодируется отдельно; произвольные
неэкспортированные переходы по-прежнему запрещены. Завершённый decompiler
block не гарантирует полноту instruction list; эту особенность нужно учитывать
при следующем экспорте / проверке collector.

## Воспроизведение и обновление

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-extensions-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_extensions_11316.py
```

Три теста: 256 сценариев, отказ при подмене cleanup bytes и повреждении export.
Check `nid-extensions-native-11316` связан с SHA / tool dependencies / export.
Повтор при тех же входах использует кэш. Новая сборка требует поиска кандидата,
сверки инструкции / literals / jump table / tails и переноса проверки;
автоматическое разрешение runtime этим не выдаётся. Scope и required_checks
записаны в `knowledge/release-update-targets.json`.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Export: `ghidra/request-exports/<SHA>/run-988ec3bf8f0a/details.json`,
  SHA `ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd`.
- Replay: `code-clues/nid-extensions-11316/9c8058380a39b5aaa51037fdd7fefa0c7324dda06277e764f71d63bf0d8f3ffd/manifest.json`.
- Literals: `0x1497390e0` webViewType, `0x1497390f0` credential,
  `0x149739100` authType; switch table `0x1450e4e14`.

Далее: converter `0x1450ed350`, ранние gates и последующие account additions,
затем auth source guards и подключение SDK profile с отдельной живой проверкой.
