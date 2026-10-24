# Целая подготовка Login 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Повторно использован готовый `run-7c5a462e9d0c/details.json`, SHA
`c94200451d70a9eb459767aa9076b5f98a90325605c135686db082f31a290619`.
Ghidra, авторизация и игровые подключения не запускались.

Целиком исполнены инструкции prepare `1467ce030` и constructor `1456d7570`.
Проверены все call sites обеих функций, constructor → table `1499263d0`,
compiled tag pointer → literal и происхождение memcpy import. Неизвестный
исполняемый адрес отклоняется harness. SDK и вспомогательные функции заменены
явными fixtures: это проверка проекции caller, не перенос всего Login SDK.

## Поля пакета

Смещения ниже шестнадцатеричные. Назначение неизвестных чисел не угадывается.

| Поле | Источник в проверенном caller |
| --- | --- |
| `+10`, `+20`, `+88` | Строки owner `+f0`, `+e0`, `+100` соответственно |
| `+30`, `+a0` | Основной SDK handle `manager+38`, только при доступности |
| `+40`, `+50` | Global FString `14b592080` и u32 `14b592028` |
| `+78` | NM provider `1445ccee0` |
| `+98` | Selector 1/2/3/4 → 1/2/3/5; остальные → 0 |
| `+99` | Android → 0, IOS → 1, остальные → 3; Windows с основным SDK и mode ровно 1 → 6 |
| `+b0` | Результат `144ab0c80(owner)` |
| `+d8` | SDK handle `manager+48`, только при доступности |
| `+f8` | Константа 207 |
| `+110`, `+120` | Compiled tag и raw global enum `14b194560` |
| `+124` | Byte объекта `14556ae90()+18`, заменяет constructor default 7 |
| `+128` | Остаётся 0 |
| `+130` | Raw byte `145ccd310(145cc6a80())`, когда SDK включён; не зависит от наличия manager |
| `+131` | Raw byte handle `manager+68`, только при доступности |

Остальные шесть строк остаются пустыми: `+58`, `+68`, `+b8`, `+c8`, `+e8`,
`+100`. Необязательная SDK-строка также пуста при отсутствии её источника. Всего проверены
15 строковых полей; обязательные / необязательные источники перечислены в таблице.

## Сценарии и lifecycle

Матрица: 14 SDK/platform сценариев × 6 selector values × пустые / Unicode
строки × send 0 / 1 × 2 poison pattern = 672 случая.

Проверены SDK disabled, отсутствующий manager, все отсутствующие handles,
отсутствие каждого из трёх handles отдельно и полностью доступный SDK.
Windows mode проверен на 0, 1, 2 и ffffffff; платформы — Windows, Android,
IOS, неизвестная Linux и пустая строка. Raw flags 80/ff сохраняются в пакете
без выдуманного преобразования в boolean. Это Windows code branches с fixtures,
а не доказательство Android / IOS runtime.

Send fixture получает session receiver, пакет, третий аргумент 4 и четвёртый
аргумент из `1496706d8`. После send выполняется уведомление `145639100` с
форматированным числом owner. При доступном основном SDK строится variant array
из одного числа и отправляется event через `145618990`. Затем уничтожается пакет.
Порядок сохраняется и при send return 0: caller не ветвится по этому результату.
Это не утверждение о доставке пакета или значении возврата реального send.

Проверены аргументы и количество SDK вызовов, число чтений owner number,
порядок уведомлений, отсутствие повторного free / утечек temporary allocations,
canaries, неизменность входных объектов / буферов и сохранение восьми nonvolatile
регистров / RSP. SDK manager и handles стабильны внутри одного replay.
Конкурентная смена SDK state не моделируется.

## Границы и автоматизация

Строковые операции, allocator/free/destructor, SDK getters, platform/selector,
language/number, send и post-send объекты — fixtures. Поэтому ownership
SDK getters, реальные ключи / metadata / язык / clock и result reader остаются
неизвестными. Отдельно проверенные writer/archive ещё не включены в этот caller.
Игровой source guard, baseline и рабочие профили не менялись.

[Контекст](../../native-contexts/login-prepare-11316.json),
[квитанция результата](LOGIN-PREPARE-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_prepare_context.py
```

Три теста прошли за 11,868 секунды на текущем ПК, включая 672 replay и отказы
при подмене SHA, export, callee, packet table и fixture binding. Это время
этого набора, не полного обновления игры.

`native-login-prepare-context` подключён к game-login и offline update.
Кэш зависит от полного SHA, context/verifier/harness, pinned runtime, тестов
и единственного готового export. При следующем патче проверять constructor/table,
все call sites, globals, поля и SDK gates; совпадения внешнего тела недостаточно.
Новый SHA требует переноса проверки, неизвестное остаётся в ручной очереди.
Готовность game-login остаётся partial, runtime promotion запрещён.

Следующий шаг — реальные SDK/string/selector/language/number зависимости Login,
интеграция writer/archive и текущий result reader. Готовые roots не извлекать снова.
