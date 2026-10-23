# Ответ индивидуальных условий: NO DATA до игрового перехода

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [запроса и диспетчера](HEADLESS-RELEASE-INDIVIDUAL-TERMS-DISPATCH.md).
Это offline native replay; авторизация аккаунтов и сетевой SDK SignUp не выполнялись.

## Проверенная цепочка

[replay-release-individual-terms-response.py](../../../replay-release-individual-terms-response.py)
исполняет целый `14456b510` для принятых HTTP / JSON с ненулевым resultCode,
настоящий конструктор `144517fd0`, dispatcher `144580990`, thunk `1445742c0`,
игровой adapter `145608200`, callback `145604f00`, source-bound virtual bridges,
success / error closures и classifier. Конечный SDK handoff остаётся capture.

В отличие от предыдущего теста, result object и UI state теперь создаёт
настоящий обработчик ответа; они не подставляются перед игровым callback.
Все экспортированные инструкции сверены с полным SHA текущего EXE.

`14561ace0` устанавливает descriptor `145608200`. Его восемь байт:
`0fb612e9f8ccffff` — `movzx edx, byte ptr [rdx]`, затем jump к `145604f00`.
Диспетчер передаёт **адрес** byte state; adapter читает значение для игрового
callback. Прямой вызов callback с адресом вместо byte не воспроизводит контракт.
Leaf проверен по точным байтам и target, без отдельного запуска Ghidra.

## Настоящий result object

Обработчик вызывает `144517fd0` с domain `0x1c20`, base `0x1ca86d0`, step 9,
context, исходным телом и служебным текстом. Конструктор записывает:

| Поле | Значение в проверенной ветви |
| --- | --- |
| `+0` | domain `0x1c20` / 7200 |
| `+4` | base `0x1ca86d0` / 30050000 |
| `+8` | step 9 |
| `+c` | сумма трёх полей: **30057209** / `0x1caa2f9` |
| `+20` | наличие непустого тела: true |
| `+28` | signed context, исходный resultCode |
| `+30` | FString тела, копирование — fixture |

Таким образом, `0x1ca86d0` в аргументах не является итоговым кодом getter `+c`.
Это уточняет смысл прежних статических записей; их неизменяемые evidence
не переписываются. Getter `141a2d1b0` исполняется по source-bound байтам.
Конструктор также вызывает error observer через `144550280`; в replay этот
вызов фиксируется, внутренние действия наблюдателя не исполняются.

## 40 сценариев и результат

Матрица: resultCode -1 / 1 / 1203 / INT32_MIN / INT32_MAX,
callback задан / отсутствует, heap / inline storage, resultMessage задан /
отсутствует. Всего **40 сценариев**. Ответы синтетические; существование
каждого такого ответа на публичном сервере не утверждается.

- Для -1 создаются state 2 и context -1. При callback binding настоящий
  игровой consumer вызывает success delegate, classifier с явно заданным
  Netmarble-профилем выбирает channel 33 / step 13. Четыре сценария дошли до
  SDK SignUp handoff capture. Ненулевой aggregate result при этом сохраняется.
- Остальные ненулевые коды создают state 3, тот же aggregate code 30057209 и
  свой signed context. При binding выполняются error text и message selector 20;
  перехода к SignUp нет.
- Без callback binding переходов нет. Для state 2 / 3 флаг показа очищается.
  Пара result / control block сохраняется, очередь удерживает одну ссылку;
  strong count игрового owner после callback возвращается к 4.

Это конкретный native-путь продолжения **при отсутствии данных условий**,
а не доказательство пользовательского согласия и не разрешение пропускать
доступные условия. Перед сетевым продолжением нужны настоящий ответ и корректные
входы того же SDK-контекста; успешный HTTP 200 сам по себе недостаточен.

Fixtures: HTTP body getter, JSON parser / getters, FString construction / copy /
release, успешная allocation, service acquisition и error observer, scheduler
ownership и callable getter, Netmarble identity / IDP count, logging, error text,
конечный SDK handoff и уже существующая tracked-запись. Эти границы перечислены
в manifest; JSON engine, сервисы и SDK целиком не воспроизводятся.

Не проверены HTTP failure, malformed JSON, нулевой resultCode с content / UI,
allocation failure, queue destructor / release, гонки времени жизни и реальные
side effects наблюдателя ошибок. Ни один тест не выполняет сетевые запросы.

## Материалы и воспроизведение

Новый полный Ghidra export constructor / content / continuation:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-8c0479e8b8bd/details.json`.
SHA256: `c0e9b7937e1d716ecbf03759a5449a60a2f7e4e7fee46fda852643067b4d1cd5`.
Все восемь привязок source / export перечислены в replay manifest
и сверяются инструментом до выполнения. Готовые экспорты использованы повторно.

Replay:
`F:/PhoneExit Resources/Vampir/code-clues/release-individual-terms-response/4e3cca707106f4364f7211aa132f7223f4c7c4dc7fc15b1a5e4c54efa4968ccb/manifest.json`.
SHA256 совпадает с именем каталога. Два offline-теста проверяют цепочку,
layout / context / handoff и отказ при повреждении экспорта конструктора.
Check `release-individual-terms-response` включён в workflow.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_individual_terms_response.py
```

Следующий шаг — связать первый SDK вход через точную Fetch challenge и реальные
ответы BasicTerms / IndividualTerms. Обычный launcher SignIn 1203 не использовать
как автоматическое основание SignUp. Ветвь с доступными условиями должна отдельно
останавливаться до реализации показа / принятия; повторная NID-регистрация не нужна.
Полные `1445a5f70` и `14457a520` уже получены для этой успешной content-ветви.
