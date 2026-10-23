# Настоящие numeric / channel helpers и OnResult в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [OnResult с return fixtures](HEADLESS-NID-RESULT-NATIVE-11316.md).
Сохранённый EXE / synthetic memory; без сети, браузера, игры и реальных аккаунтов.

## Исполненный код и источники

Явный prepare / collect получил два текущих CALL targets из готового OnResult:
numeric parser `0x1415e4460` (72 инструкции) и channel mapper `0x144531900`
(251 инструкция). Полные SHA EXE / трёх exports и все выполняемые байты проверены.
Исполняются целые helpers, настоящий case-insensitive compare leaf
`0x14145f1e0` (71 байт), его таблица из EXE, прежний OnResult slice и FString copy.
Capstone 5.0.6 / Unicorn 2.1.4; instruction / string / heap budgets конечны.

Compare SHA `591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0`.
Mapper descriptors связаны с 13 настоящими UTF-16 literals через семь инструкций
каждого маленького initializer. Поиск ограничен 16 самостоятельными roots до
64 байт и не расширяется на chained fragments. Initializers здесь статические;
их FString storage задаётся в отдельной постоянной synthetic arena по точным
literals. Полный результат bindings / инструкции сохранены в report.

## Numeric parser и Windows CRT

Проверены четыре named IAT calls текущего parser: `_wtoi`, `_finite`, два
`iswspace`, вместе с соответствующими DLL import identities. Они вызывают
настоящие функции локальной `C:/Windows/System32/ucrtbase.dll`, а не Python
`int()` / `isdigit()`. Library загружается по полному пути из Windows system
directory; путь реально загруженного module повторно сверяется.

CRT SHA `dedb7611e1abc1ff3852dcac3d4c93a048d729e25b061973b9969f22698f14ca`.
Observed locale, без изменения:
`LC_COLLATE=C;LC_CTYPE=Ukrainian_Ukraine.1251;LC_MONETARY=C;LC_NUMERIC=C;LC_TIME=C`.
Этот replay требует данную проверенную locale и сверяет её / SHA после выполнения.
Другие Windows locales и Android parity не подтверждены.

112 случаев: четыре poison fills × 28 строк, включая empty / zero / signs /
spaces / prefixes / overflow / два Unicode whitespace. Empty и abc дают false;
0 / 00 / +0 / -0 / пробелы / 0.0 дают true и 0. В конкретных fixtures 0abc,
0x10, 0e9, 0.1 тоже дают true и 0; 1abc даёт 1. Переполнение насыщается до
INT_MAX / INT_MIN. Это наблюдения указанных inputs на данной CRT, не полная
спецификация числового синтаксиса или Unicode.

## Channel mapping

176 случаев: четыре poison fills × 44 printable ASCII inputs. Для каждого
из 13 ключей проверены original / uppercase / swapcase, дополнительно empty /
unknown / email / trailing / leading space. Actual native results:

| Ключ, без учёта ASCII-регистра | Channel byte |
| --- | --- |
| facebookKey | 1 |
| googleKey | 5 |
| gameCenterKey | 6 |
| twitterKey | 12 |
| mailUserKey | 20 |
| signInWithAppleKey | 26 |
| googleIdKey | 29 |
| steamKey | 30 |
| epicKey | 31 |
| playStationKey | 32 |
| netmarbleKey | 33 |
| xboxKey | 34 |
| guest | 100 |

Unknown / empty / email и mailUserKey с пробелом дают 0. Whitespace trimming
не выполняется. Unicode channel names здесь не проверяются.

## Совместное выполнение

1124 OnResult / copy / real helpers cases: прежние 1100 сценариев и шесть новых
inputs × четыре poison fills. Numeric / channel return fixtures вообще не
установлены; events не содержат integer_fixture / channel_fixture.

Проверены missing / empty / mode gates, раздельные adoption captures и дополнительные
связки: 0abc + MAILUSERKEY достигает captures, 1abc и + отклоняются numeric gate,
unknown и пробелы вокруг channel отклоняются channel gate. Реальные credentials
не используются. Синтетические hash / map, allocation / memcpy / free, CDO getter,
settings captures и country assignment остаются fixtures. Null faults missing rows
сохраняют прежний смысл synthetic map contract, не наблюдения живой игры.
Setters / persistence, callbacks и вся авторизация не исполнены.

Portable decoder по-прежнему требует точный resultCode 0 и проверяет наличие
полей до дальнейшей работы. Его более строгая политика не ослабляется до
permissive native syntax. Runtime profile этой проверкой ещё не включается.

## Воспроизведение, кэш и следующее обновление

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-primitives-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_primitives_11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_research_workflow.py
```

Два helper-теста: поведение / integration и отказ при повреждённом export.
14 workflow-тестов включают cache invalidation при изменении системной DLL,
отказ при её изменении во время проверки и отклонение произвольных runtime paths.
Check `nid-primitives-native-11316` зависит от полного SHA, exports, tools,
закреплённых Python packages и явного `system_runtime_files: ["ucrtbase.dll"]`.
Runner добавляет реальную DLL / SHA и текущую locale в ключ кэша и проверяет
неизменность после теста. Другие системные файлы этим не разрешаются.

В release-update-targets.json отмечены текущие helper addresses / scopes /
required_checks. Для новой сборки нужно сверить CALL targets из OnResult,
imports, compare / table и 13 initializer bindings, затем перенести проверку.
Поиск кандидата и автоматическая проверка текущего SHA не разрешают runtime
новой сборки. Проверки не выполняют авторизацию или игровые действия.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Helpers export: `ghidra/request-exports/<SHA>/run-37fa5992ea23/details.json`,
  SHA `2327d837934b6ea6f6709411b31d9746a46219b27cb7091e5bdf5cb4bb8966ab`.
- Native report: `code-clues/nid-primitives-11316/fc36df990225b72dd298bac3da0795dfc1e7d66ab0a1784425f62c7720d540bb/manifest.json`.
- OnResult / copy exports — в предыдущем evidence по ссылке выше.

Далее — оставшиеся auth source guards / browser-result boundary и явное
подключение profile 1.13.16, затем живая проверка после доступности серверов.
