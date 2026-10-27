# Автоматическое продолжение переноса 1.13.20

28 октября 2026. Продолжение [подготовки входа](HEADLESS-ENTRY-BATCH-11320.md).
Полный SHA текущего EXE:
`544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c`.
Готовые источники и выгрузки использованы повторно; новый Ghidra, игра,
авторизация и сетевые команды не запускались.

## Что прошло автоматически

| Проверка | Результат |
| --- | --- |
| Constructors / compiled tag / tag consumers Version и Login | 4 + 4 native сценария |
| Whole packet writers с отказом на каждой операции | 56 Version + 104 Login сценария |
| Перенос привязок preparation Version по готовому native пакету | 16 привязок, без перезаписи конфликтующих значений |

Итого **168 новых сценариев**, независимо от ранее проверенных wire bodies.
Для compiled tag проверены текущие pointer / literal / packet table, numeric ID,
имя пакета, constructor и ограниченный consumer slice. Для writers — точный
порядок аргументов, возврат после отказа каждого поля, ABI и canaries.
Archive / string / allocation effects остаются объявленными fixtures;
это не повторное исполнение готовых 559 wire / UTF-8 сценариев.

`verify-entry-contracts-11320.py` берёт действующий граф и explicit текущие
contexts. Полные SHA exports сверяются с ранее закреплёнными декларациями.
Новый tag spec и writer field spec проверены обычными verifiers; адреса
переиспользованы по source-bound связям, без выбора ближайшего кандидата.
У `compiled-tag-native-11316` и `packet-writer-context` добавлены отдельные
source variants 1.13.20 с воспроизводимыми тестами и `on_update` / кэшем.
Старые варианты 1.13.16 и 1.13.18 сохраняются.

Отчёты находятся в библиотеке ресурсов:

- Version tag: `knowledge/tag-followup-11320/ca3abdef041e908ca9a915db156c6794d4e316ca31ab1b4d69eadbb3d3b26cbe/manifest.json`.
- Login tag: `knowledge/tag-followup-11320/56b26cc412dd56d491cb966c5dcd18dcb021e67de87325898f481734692a7dae/manifest.json`.
- Оба writers: `knowledge/entry-contract-checks-11320/180a350261ad8d618adb87557d35b58ecd4d26d87732d275c5202a3135726997/manifest.json`.

`binding_proposals()` использует уже проверенный cached пакет
`5d8d52caf23644079d5d3663cf167432ce6617a2208960df6207fa66a8fb8ad2`,
полный SHA и ограниченный preparation set из сохранённого alignment.
В граф внесены wrapper constructor, platform selector / store / lookup,
Windows suffix, CPU helpers и combiner helpers — всего 16 отсутствовавших
привязок. Result / input роли этим предложением не добавляются. Тест проверяет
точную пару baseline / target и отказ при конфликте. Это bounded preparation
с явно указанными fixtures, а не строгий полный `closed_shape` или допуск runtime.

## Что автомат оставил в очереди

`align-login-continuation-11320.py` проверил два полных roots и explicit
code / data anchors прежней continuation. Он использует source SHA,
ограниченные окна ±65536, полные формы инструкций и уже известные callee / RIP
ссылки для разрешения неоднозначностей. Окно factory удалось связать по
известному constructor / singleton; последний anchor прежнего LoginResult
handler `0x14679b6ff` остался неоднозначным. Кандидат не выбран наугад.

Content-addressed отчёт:
`knowledge/continuation-alignment-11320/2eceb627fb270c255abbdcf3c1eaada97e08c9e4d669403b48fc34dfb946cfd5/manifest.json`.
Статус `requires_review`, `semantic_verification=false`, текущий context не
сгенерирован и native continuation не допущена. Отдельная проверка
`continuation-candidates-11320` включена в `on_update`: она сохраняет этот
точный пробел и проверяет отсутствие ложного допуска. Она не используется
как доказательство клиентского контракта.

## Проверки и границы

Три tag-теста, два writer-теста и один candidate-тест прошли, включая отказ
при неверных data / ID / field order / table / конфликтующей привязке.
Проверены схема контрактов и выбор source variants. Обычный `collect` вернул
reuse для четырёх готовых tag roots, без нового Ghidra.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-entry-contracts-11320.py --kind tags
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-entry-contracts-11320.py --kind writers
python -X utf8 phone-exit/bots/resource-tools/vampir/align-login-continuation-11320.py
```

Полный game contract, строгая очередь функций и runtime не объявлены закрытыми.
Изменившийся LoginResult / post-state и continuation anchor требуют дальнейших
доказательств; они не превращаются в автоматическое подтверждение. Следующий
пакет может использовать готовые tag / writer / preparation checks из кэша.
