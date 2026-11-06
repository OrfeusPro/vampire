# Текущий первый SDK-профиль: общий сбор и native continuation

6 ноября 2026. Источник — полный SHA256 EXE
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Продолжение [отказа Silvercrow и Fetch-only](HEADLESS-SDK-FETCH-READ-ONLINE.md).
Сетевых попыток, SDK SignUp и игровых действий в этом пакете нет.

## Один пакет материалов

Ограниченный поиск использовал сохранённый EXE базы `98802d550890…` и текущий
EXE. В окне ±128 KiB найдены кандидаты для 30 roots. Неоднозначные callback /
dispatcher / handoff уточнены по прямым вызовам; virtual bridges и getter типа
индивидуальных условий — по реальным слотам таблиц `+60` и `+30`.
Сам поиск кандидатов не является переносом роли или semantic доказательством.

Запрос `4525d634390b2f1d066f2246e922f51ef91e8b65c01817837b0b69f05253165d`
в `knowledge/research-scoped-v2-requests/` собрал один общий экспорт
`ghidra/request-exports/03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f/run-9e904f43767e/details.json`.
SHA256 отчёта — `3293865aed8adb18291bddf8c441c29a49b759fdbce6bffe3b1730ca9f441f28`.
Collection `939f33d9287d2c587eba7cba18f3042cc1a36920bb4897c26e7a77cfaedf8016`
имеет 30 ready functions и пустую очередь. Использован существующий Ghidra project;
новый экспорт запущен одним пакетом. Повторять этот сбор для оставшихся функций
цепочки не нужно.

Помимо семи исполняемых roots в отчёте уже есть текущие Basic/Individual loaders
и responses, result constructor, SignUp request / response / callback / wrappers,
direct SignIn request / wrapper и CreateGet. Наличие полного экспорта само по себе
не подтверждает их payload, parser, полную композицию или runtime admission.

## Исполненная часть на текущем SHA

[Контекст](../../native-contexts/first-sdk-continuation-11322.json) закрепляет
экспорт, семь roots, три result getter leaves, два virtual slots, manager global
и исчерпывающий набор fixtures.
[Проверяющий инструмент](../../../verify-first-sdk-continuation-current.py)
использует общий source-bound native harness с Capstone 5.0.6 / Unicorn 2.1.4.

| Root | Проверяемая роль |
|---|---|
| `0x1456022f0` | Fetch game callback |
| `0x145603740` | Individual Terms game callback |
| `0x145609970` / `0x145609830` | Native virtual bridges success / error |
| `0x145604530` / `0x145604ed0` | Success / error closures |
| `0x144531480` | Guest / Netmarble classifier |

27 Fetch случаев: success всегда передаёт channel 33 / step 15; только отказ
с aggregate code **30050027** и context **1203** вызывает BasicTerms. Остальные
ошибки идут в error text / message selector 6. Проверены null control, expired
owner и null owner без действий; strong count после обычного callback равен 4.

99 Terms случаев: шесть SDK-профилей, четыре raw UI state, bound / unbound,
два result code и три owner gates. State 2 при binding даёт 12 captured SignUp
handoffs: восемь Netmarble 33 / step 13 и четыре Guest 100 / step 12. State 3
для специального кода повторяет Individual Terms, для другого даёт message 20.
Проверены реальные current vtable slots и баланс ссылок.

Неизменяемый native report:
`F:/PhoneExit Resources/Vampir/code-clues/first-sdk-continuation-current-v1/a0ecb2e69e8207db86e21a9014017b8bcb49728a3f0540a270bde5366ed89272/manifest.json`.
SHA256 совпадает с именем каталога. Он содержит inputs и все 126 случаев.

HTTP/JSON construction, Basic/Individual parsers, реальное окно и согласие не
исполнялись. UI state и results синтетические. Service acquisition, IDP count,
существующая tracked-запись, logger/UI и конечные Terms/SDK handoffs — fixtures
или captures. Allocation/growth, final destructors и lifetime races открыты.

## Автообновление и следующий пакет

Check `first-sdk-continuation-current` имеет `on_update`, точный SHA, зависимости
и retained export. Четыре tooling теста проверяют native матрицу и отклонение
чужого SHA, подмены исполняемого bridge capture и переставленных virtual tables.
Модуль зарегистрирован в `MODULES` и одной группе с обычным SHA-кэшем.
Contract `sdk-first-profile` остаётся **partial**, без builder и runtime admission.
Контекст привязан к этому SHA; автоматический перенос на следующий EXE ещё
нуждается в зарегистрированном правиле и новом доказательстве.

Далее использовать уже готовый общий экспорт: связать фактический Fetch error
с Basic/Individual NO DATA, подтвердить текущие request/response и owner keys
SignUp / direct SignIn, затем собрать отдельный одноразовый runtime scope первого
профиля. Доступные условия требуют просмотра; state 2 не означает согласие.
Launcher SignIn 1203 не запускает SignUp. Только после этих контрактов нужна
новая живая попытка Silvercrow; остальные семь ещё не запускались.
