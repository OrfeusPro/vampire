# Текущий mapper ответа лобби 10036

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [живого первого SDK-входа](../auth/HEADLESS-FIRST-SDK-LIVE-AND-NID-HINTS.md).

## Поиск без переноса старого адреса

Текущий ASCII literal `IsInspect` найден по `149952d40`. RIP candidates
дали четыре unwind roots: `1457c7ae0`, `1457da4e0`, `145810700`, `145814800`.
Общий Capstone decode отказал на неполном fragment: это не доказательство роли.
Готовый export `145814800` использован повторно. Явный collect трёх недостающих
адресов получил полные `1457c7ae0` / `145810700`; `1457da4e0` остался missing
с объяснением в очереди. Автоматического расширения дерева функций не было.

`145810700` — current result-to-key mapper. Проверенные E8 callers:
`145fd5120` / callsite `145fd51d1`, `14667f6e0` / callsite `14667f783`.
Первый выгружен отдельно. Он сначала проверяет table override через
`145bce1c0` / `145bd6e90`, а при отсутствии использует `145810700`.
Для 10036 / 10048 есть отдельный вызов `144a526c0`; другие коды имеют общий
путь UI lookup. Это статический разбор helper, не исполнение popup.

## Native replay

[replay-release-lobby-errors.py](../../../replay-release-lobby-errors.py)
использует прежний bounded harness с новыми **явными** entry `145810700`
и constructor fixture `141426a30`. Проверяются полный SHA EXE, SHA экспортов,
все инструкции mapper / caller и точные байты fallback E8.
Исполняются целые достигнутые пути entry → return; неизвестный native вызов
за пределами диапазонов отклоняется. FString constructor — fixture, которая
считывает достигнутый ASCII literal из проверенного EXE.

| Вход | Ключ |
| --- | --- |
| 0 | Success |
| 10036 | IsInspect |
| 10048 | BlockedInfo |
| 1 | пустая строка |
| UINT32_MAX | пустая строка |

Историческое соответствие IsInspect → Under maintenance описано в
[прежнем разборе](HEADLESS-LOGIN-LANGUAGE.md#расшифровка-10036-isinspect--технические-работы).
Текущий replay подтверждает **ключ**, а не свежую локализацию, фактический popup,
длительность техработ или серверную причину отказа конкретного аккаунта.
Table override и весь вызывающий helper native-сценариями не исполнялись.

Runtime `describe_lobby_login_error` сохраняет прежние описания. Account worker
теперь добавляет фиксированное описание к коду отказа лобби: для 10036 —
«Сервер сообщил о технических работах». Произвольный текст ответа не выводится.
Переход к игровому Login, повтор или смена назначения этим не разрешаются.

## Материалы и проверки

Относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-88a1dfed6648/details.json` | `2932518bc30a1c7c09a79b99d1497e7374d4d3b1f1c7ff8a6741036e0a30fbb8` |
| `details/run-116ea21f2ddb/details.json` | `eff8ba1fe14ba36d29ca14a96e8278c1e14d93b9b8e181d37042354e9518eb7b` |
| `sdk-reference-candidates/ba5d8736bf898ffbf48472995d802295ccf0b09ab27592a1e1407dcc4c901289/manifest.json` | SHA совпадает с именем каталога |

Replay:
`F:/PhoneExit Resources/Vampir/code-clues/release-lobby-errors/9c6a71c178425bddef45332604b7604359a59a012df8854b21642e44e767a9b3/manifest.json`.
SHA совпадает с именем каталога. Два offline-теста проверяют пять native путей,
соответствие runtime labels и отказ повреждённого EXE. 20 account console tests
также прошли; они не выполняют авторизацию. Check `release-lobby-errors`
включён в workflow. Нет сети, процесса игры или чтения его памяти.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_lobby_errors.py
```

Следующий шаг: при новом принятом входе проверить список Aria 1, сохраняя
назначение. Если 10036 повторится, сравнить вход уже существующего аккаунта
на том же сервере без изменения его назначения в базе; одни flags каталога
не доказывают работоспособность. Создание возможно только после принятого
пустого списка. SDK-профиль nightraven уже создан, его SignUp не повторять.
