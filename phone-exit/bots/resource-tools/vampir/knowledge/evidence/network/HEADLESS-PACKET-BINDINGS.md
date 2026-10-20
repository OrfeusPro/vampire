# Vampir: пакеты входа, персонажа и heartbeat — H02

## Уточнение CharacterListRead, 19 октября

Writer ID 101 теперь проверен native-исполнением: leaf 0x140bb4a10 возвращает 1
и не меняет archive. Две actual request routines создают packet и вызывают
virtual send (capture). Старое замечание ниже описывает пределы исходного
статического этапа. [Новые источники и границы](../characters/HEADLESS-CHARACTER-LIST-BOUNDARY.md).

18 октября 2026. Общий [указатель функций](../../../../../vampir/FUNCTION-INDEX.md),
[задачи сетевого бота](../../../../../vampir-headless/TASKS.md). Статическое исследование
собранного Windows-клиента; не исходный C++ проект и не готовый протокол.

## Источник и воспроизведение

`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Версия Windows ещё unknown; соответствие Android не установлено.
Все адреса ниже VA при image base `0x140000000`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-packet-bindings.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_packet_bindings.py -v
```

Вход: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Выход: `code-clues/headless-packet-bindings.json` в той же библиотеке;
SHA256 `35d1a72b6302a66cd19548b3da7caef362ccbd67d98eb8d26621d3c04512c508`.
Capstone 5.0.6, Unicorn 2.1.4 закреплены в requirements-native.txt;
это исследовательские инструменты, не зависимости runtime бота.

## Что подтверждено

Цепочка для каждого из 10 типов: точная строка из H01 → функция со ссылкой →
единственный aligned pointer в .rdata → предполагаемое начало таблицы →
проверка этого начала записью vptr в [this] внутри конструктора.
Начало конструктора подтверждено прямым E8 из полностью декодированного
unwind-фрагмента. Для leaf-функций без .pdata граница взята из такой цели
вызова; разрешены только прямолинейные инструкции до RET в пределах 128 байт.
Деструктор с похожей записью vptr не подменяет доказательство конструктора.

В packet vtable: name slot+0x38, ID slot+0x28, writer target+0x10,
reader target+0x20. Последние названия соответствуют ранее проверенной
packet hierarchy; порядок полей, primitive encoding и полные тела здесь
не восстановлены. ID-функции имеют MOV EAX, imm; RET и дополнительно реально
исполнены в изолированном Unicorn с ограничением числа инструкций.

| Тип | ID | Vtable | Constructor | Writer target | Reader target |
|---|---:|---|---|---|---|
| PktLogin | 3 | 0x1498d6058 | 0x1456d4c80 | 0x1456e57c0 | 0x1456d9370 |
| PktLoginResult | 4 | 0x1498d6218 | 0x1456d4da0 | 0x1456e5a20 | 0x1456d9600 |
| PktLobbyLogin | 3 | 0x1498f0258 | 0x145744fa0 | 0x145756e80 | 0x14574a970 |
| PktLobbyLoginResult | 4 | 0x1498f02b8 | 0x145745000 | 0x145756f80 | 0x14574aa80 |
| PktCharacterListRead | 101 | 0x1498d84d8 | 0x1456d4780 | 0x140bb4a10 | 0x140bb4a10 |
| PktCharacterListReadResult | 102 | 0x1498d8540 | 0x1456d47a0 | 0x1456e51e0 | 0x1456d8d80 |
| PktCharacterSelect | 109 | 0x1498d87d0 | 0x1456d4850 | 0x1456e53a0 | 0x1456d8f20 |
| PktCharacterSelectResult | 110 | 0x1498d8a80 | 0x1456d4a40 | 0x1456e5410 | 0x1456d8f80 |
| PktPing | 16 | 0x1498d66c0 | 0x1456d5040 | 0x1456d15c0 | 0x1456c1810 |
| PktPingResult | 17 | 0x1498d6718 | 0x1456d5060 | 0x1456e4ac0 | 0x1456d8600 |

Одинаковые reader/writer targets у CharacterListRead не являются сами по себе
доказательством пустого wire payload: могут существовать общий header/base IO.

## Регистрация пяти ответов

| Тип | Handler table | Slot+0x10 target | Registration call |
|---|---|---|---|
| PktLoginResult | 0x149d81080 | 0x146765540 | 0x14678ecfa |
| PktPingResult | 0x149d810f8 | 0x1467670c0 | 0x14678ef52 |
| PktCharacterListReadResult | 0x149d81368 | 0x14675dce0 | 0x14678f2d6 |
| PktCharacterSelectResult | 0x149d813b0 | 0x14675e9a0 | 0x14678f402 |
| PktLobbyLoginResult | 0x149d802e8 | 0x14677ec50 | 0x14678e80a |

Для каждого проверены constructor call, handler-table LEA/store, packet/handler
аргументы в RDX/R8 и вызов регистрации. У первых четырёх factory root 14678ec40
и target 1467a7250; у LobbyLoginResult factory root 14678e750 и target 1467a7150.
Оба регистратора вызывают packet slot+0x28, сохраняют AX как word key и
передают пару в 14678e3e0. У варианта 1467a7150 дополнительно явно вызывается
name slot+0x38 в диагностической ветке. Эти факты подтверждают назначение
слотов ID/name, а не только их положение рядом с другими функциями.

**ID не глобален:** Login и LobbyLogin возвращают 3, оба ответа возвращают 4,
но их vtables и сериализаторы различны. Доказаны разные статические пути
регистрации; runtime-выбор соединения/dispatcher ещё не прослежен.
Будущий codec должен учитывать подтверждённый контекст, не иметь один
безусловный dictionary ID→schema для всей игры.

## Проверки, ограничения и продолжение

Отчёт содержит 10packet bindings, 5 registrations, 11 проверенных прямых вызовов
конструкторов, 17unwind fragments/20007 instructions, 17leaf checks и 72data anchors.
Четыре независимых теста сверили исходный SHA, fragment hashes/байты, vtable
slots, границы вызовов/запись vptr, регистрацию и коллизии контекстов.
10 native ID getter executions прошли. Это не запуск игры и не live packet test.

При попытке линейного декодирования всех vtable refs встречен root 1457491b0,
который не декодируется полностью существующим helper. Он не включён в
доказательства: использованы прямые вызовы конструкторов и проверенные
фабрики. Отсутствие unwind у leaf не считалось отсутствием функции.

H02 закрыт только для этих 10 типов/5 ответов. Следом H03: начать с Ping/Result,
проследить primitive IO из writer/reader до реальных байтов, затем framing,
контексты dispatch и send/receive. SDK-вход/почта/пароль остаются H04.
Сеть, аккаунты, процесс игры и память процесса не использовались;
`network_ready=false`, `wire_schema_verified=false` для всех типов.
