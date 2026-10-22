# Пустой список и отдельный запрос создания персонажа

22 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Проверено предположение пользователя о другой функции при отсутствии персонажей.
Последний [живой EU Login](../network/HEADLESS-LIVE-GLOBAL-EU.md) вернул 59
до списка. Нулевое число персонажей пока не подтверждено сервером.

## Отказ и пустой список

Текущий LoginResult handler `0x14679c4f0` вызывает gate `0x1467cee40`
с code packet+0x10 и packet ID 4. В проверенных случаях 57 / 58 / 59
успешное продолжение не проходит. Вызывается transport `0x144ab1f70` с 0,
затем при пустой строке packet+0x38 — controller virtual+0x38, иначе popup
`0x144a526f0`. Callback popup не исполнен. Запрос создания здесь не отправляется.

Успешный ID 102 с count 0 проходит ListResult handler `0x146797990`:
прежние записи очищаются, count становится 0. При наличии UI сохраняется
индекс 0; это значение UI, а не существующий персонаж. Продолжение вызывает
owner virtual+0xa00, завершение UI и event 6. Эти действия — captures;
полный переход в экран создания ещё не исполнен.

[replay-release-empty-character-entry.py](../../../replay-release-empty-character-entry.py)
проверяет целые текущие native функции:

- 16 случаев успешного пустого списка: gate state 0 / 1, UI / owner есть или
  нет, прежний список пустой или две записи. Readers / handler / gate /
  predicate исполняются; список очищается без ветки отказа.
- 18 случаев Login 57 / 58 / 59: gate state 0 / 1, строка отсутствует /
  пустая / непустая. Целые Login handler и gate исполняются; transport capture
  получает 0, затем выбирается выход или popup.

Login packet layout — synthetic fixture, не native reader / live capture.
Engine state, policy, globals, строки, allocation и UI — fixtures / captures.
Неизвестные execution targets отклоняются. Сеть и создание не выполняются.
Отчёты сохраняются content-addressed в comparison
`run-fd4956a37b3c/empty-character-entry-replay/` библиотеки ресурсов.

Сводка `game_login_probe` различает `login_rejected`, `awaiting_list`,
`empty_list`, `characters_available`. Пустой список появляется только после
принятого ID 102; автоматического создания нет. Socketpair-проверки подтвердили,
что пустой список и Login 59 не отправляют выбор / создание персонажа.

## Отдельная операция создания

Compiled имена связаны с name getter / table / ID getter и constructor.
Это игровые ID; их нельзя смешивать с одноимёнными числами протокола лобби.

| Пакет | ID | Table | Constructor | Writer / reader |
| --- | --- | --- | --- | --- |
| PktCharacterCreate | 103 | 0x14992a3a8 | 0x1456d8120 | 0x1456bb7d0 / 0x1456b83a0 |
| PktCharacterCreateResult | 104 | 0x14992a468 | 0x1456d8150 | 0x1456bbe70 / 0x1456b8a30 |

Request constructor создаёт вложенный объект packet+0x10 через leaf
`0x145784790`, table `0x14992a360` / CharacterCreateData.
Writer `0x14578e120` / reader `0x145789090`: data+0x08 передаётся scalar
virtual+0xc8, строка data+0x10 — в `0x144aae660`, appearance data+0x20 —
в object serializer `0x144aae8c0`. Для полного wire codec ещё нужны scalar /
string bindings, actual appearance и целый writer / reader replay.

Единственный найденный прямой E8 caller constructor — `0x146449dc0`.
Число из owner virtual+0x90 сравнивается с sentinel `0x1496726a0`; при
несовпадении и наличии UI строка UI+0x368 копируется в create data+0x10,
число — в data+0x08. Appearance получает байты owner и строку helper
`0x146447e50`. Send `0x144aafc50` ожидает result ID 104. Virtual+0x90 ещё
не связан с конкретной строкой класса; произвольное число классом не считать.
Поиск прямых calls не покрывает indirect / tail / inline callers.

Factory связывает CreateResult handler table `0x149dc8788` с `0x146796690`.
При code 0 он передаёт record packet+0x18 state helper и обновляет UI;
при ненулевом code вызывает error helper и сбрасывает ожидание UI.
Это static-разбор, не подтверждение создания на сервере.

## Evidence и продолжение

Все пути ниже относительно comparison
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

- `bootstrap/run-887dcf19fe4a/export/bootstrap.json`, SHA256 `7f245fa66bbeceee87fd7933b9c6376079e1b7779493d7255463b2105c3c6aed` — Login handler.
- `details/run-ab4ca396be23/details.json`, SHA256 `64a07328ba5dc14b901dc01005a8515a0a102a893eb750d4e3fa309a92040767` — List handler.
- `details/run-7862c6b69a2a/details.json`, SHA256 `9d9837e711ae068aff760f3b5efe743c78d1d944e18de2be167b807274712f25` — gate / predicate.
- `details/run-dbbbcb857839/details.json`, SHA256 `e3438a98efdd8b403847bd3b68095abe4a8f7b666a24be1fc0c893e8d6432a11` — create packet / result / handler.
- `details/run-33b73b3d42b9/details.json`, SHA256 `977ff56c28a82d5ee388b4e464802f2675d0fbe7c2374fe99d16ccddb1e2f460` — CreateData writer / reader и caller.

`0x144aae8c0` оставлен в очереди collect: нет однозначного unwind root.
Не повторять экспорт без доказательства leaf-границ. Следом — actual appearance,
источник класса и полная wire-проверка. Login 59 остаётся отдельной задачей;
создание вместо принятого входа не отправлять.
