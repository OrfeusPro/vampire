# Наблюдаемое окружение: create / leave и изоляция

Источник EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это частичная модель полученных событий, а не полная видимость движка.
Начальный SightEnter, другие игроки, имена монстров, применение движения и
последующие изменения NPC stats остаются открытыми. Живой игровой вход на этом
этапе не выполнялся; предыдущая OPPO-сессия остаётся закрыта.

## Связи текущего клиента

`inspect-world-registrations-11316.py` проверяет полный SHA, E8 boundaries,
14 конкретных инструкций и handler tables. Успешные пути выделения связывают:

| Пакет | Constructor / call | Handler table / slot +10 |
| --- | --- | --- |
| ID 324 NPC create | 1456c01c0 / 1467b65ee | 149dc6090 / 14679b630 |
| ID 302 Sight leave | 1456c0360 / 1467b60a8 | 149dc6138 / 14679c710 |

Общий dispatcher registration — `1467cb6c0`; в обоих случаях RDX получает
packet, R8 — handler. Большой owner `1467b4c60` не выгружался целиком Ghidra:
collector отказал по бюджету. Проверены конкретные source instructions;
выгружены отдельные небольшие handlers и нужные callees.

Create handler после gate `1445d2970` передаёт `packet+18` в `145d74330`.
Initializer копирует CreateData+10 (NPC+8) в model+8, CreateData+18 (NPC+10)
в model+10 и CreateData+20..30 (NPC+18..28) в model+20..30.
`14567e720` использует model+8 при lookup/create actor. NPC+58 / +60 через
CreateData+60 / +68 передаются `1455f10f0` с типами 4 / 5 — Hp / MaxHp.
18 точных field anchors автоматически сверяются с PE на границах инструкций.
Это статическая привязка значений; полный actor / UObject / listener путь
native здесь не исполнялся. Код NPC+10 показывается как raw `wire_id`, без
обещания подтверждённого названия монстра из текущей таблицы.

Leave handler `14679c710` отдельно обрабатывает QuestVisibleActor records из
packet+20, затем ключи из packet+10. Для каждого ключа вызывает `145512800`
через service `145515dc0`; найденный actor идёт в дальнейшую обработку
`14679d960` с reason packet+30. Реальное удаление может быть отложено / зависеть
от состояния движка. Наблюдаемая модель убирает ключ при получении sight leave,
не заявляя мгновенного уничтожения actor. QuestVisibleActor triples не являются
дополнительным списком удаляемых ключей.

## ID 302: полный reader

Reader `1456c5550`, generic vector `144aac530`, callbacks `1456c6960` и
`1456c65f0`, visible record constructor `1457a2ad0` / reader `1457a68b0`
исполняются вместе с настоящим input/archive. Wire:
`u16 count; count × uint64; u16 count; count × (uint64,uint64,uint64); byte`.
Последний byte clamp 32. Native stride второго массива — 32 с vptr.
Оба массива и повторы сохраняются; семантика трёх полей QuestVisibleActor
дальше не угадывается. Leaf constructor / resize не выдаются за unwind roots.

3726 native сценариев: пустые / граничные / повторные uint64 keys, отдельные
triples, reasons 0 / 1 / 31 / 32 / 33 / 255, каждый префикс малых тел и выбранные
границы массива 64 keys. Проверены значения, cursor и guards ввода / объектов /
хранилища. Fixtures — выделенные заранее массивы и пустое прежнее хранилище;
рост / reuse не подтверждены. Portable строже native по trailing bytes.
[Контекст и SHA exports](../../native-contexts/sight-leave-11316.json).

`sight_leave_event.py` требует явный SHA, bytes, максимум 64 KiB и общий лимит
0–4096 entries (по умолчанию 1024) для обоих массивов вместе.
Окружение использует [полный source-bound NPC create decoder](HEADLESS-NPC-CREATE-11316.md).

## Runtime и API

`ObservedEnvironment` принадлежит одному `LiveSession`, максимум 512 NPC.
События принимаются только при проверенном source SHA и явном world ID из
владельца с завершённым world entry. Мир не угадывается по координатам.
Повторный create заменяет ту же запись; leave удаляет только actor keys.
При смене мира / переходе в незавершённый world / close записи очищаются.
Ошибка decoder очищает наблюдаемый subset и выставляет `decode_error`;
неполный разбор не меняет отдельные поля старой записи.

Snapshot содержит key как decimal uint64 string, kind `npc`, `wire_id`, world,
начальные HP / MaxHP, XYZ, время события и источник. Небезопасные для JS HP и
нечисловые / nonfinite координаты становятся неизвестными. Имя и уровень — null.
`stats_semantics=server_create_stats`, `stats_current=false`,
`position_semantics=server_create_position`, `position_current=false`:
это полученные при появлении значения, а не обновляемые текущие HP и позиция.
Демо / own-character stats не используются для заполнения NPC.

HTTP state отдаёт до 256 NPC: `?entity_page=0` (по умолчанию) или `1`.
`environment.known_count`, `entity_page`, `page_size`, `shown_count` описывают
страницу текущего снимка. Это страницы изменяемого списка, не зафиксированный
архив между запросами. Python snapshot без `for_api` сохраняет все 512 записей.
Общий адаптер переключает страницу, отменяя предыдущий запрос; отдельного
таймера / fetch у карточки нет. Поздний ответ предыдущей страницы игнорируется.

`coverage.entities` — `not_received`, `partial` или `decode_error`; неподдержанный
source остаётся `not_verified`. Модель никогда не объявляет полное покрытие.
`environment.complete=false`, `players_received=false`, `movement_applied=false`.
После пустого leave нулевой размер всё ещё partial и не доказывает отсутствие NPC.
При заполнении 512 записей новые ключи отклоняются с `limit_reached`; существующие
можно обновлять и удалять. Samples и тела пакетов модель не хранит.

Обновление UI-снимка окружения происходит только при изменении revision, а не на
каждом idle pump. Используется общий session lock. Строки разных аккаунтов, даже
с одинаковым ключом 42, не разделяют storage и не меняют HP основного персонажа.
HP/MP персонажа при смене мира заново применяются из своей stats-модели.

## Проверки и интерфейс

6 environment-тестов включают статические source anchors, 50 синтетических
сессий с одним ключом и разными NPC HP, own HP isolation, duplicate create /
leave, quest triples, world / waiting / close, decoder error, nonfinite /
unsafe values и capacity. Максимальные 512 NPC с uint64 keys, JS-safe HP,
крайними float32 XYZ и 1024 stats остаются в модели; каждая из двух API-страниц
меньше 262144 bytes, объединение содержит все 512 ключей. Неверные / повторные
параметры страницы отклоняются; после уменьшения списка страница сбрасывается. Пройдены 12 live API /
diagnostics, 42 socket probe и 9 connection тестов. Native leave — 2 теста,
включающие 3726 сценариев и portable guards. UI: 66 Node проверок и live adapter.

Основной прототип получает тот же snapshot через один адаптер. Кнопка
«Окружение» показывает таблицу наблюдаемых NPC и явную пометку partial.
Это временное окно наблюдения, не восстановленное игровое окно / native layout.
На карте NPC пока не рисуются: актуальная проекция и движение не подтверждены.

В браузере использован реальный loopback `LiveSessionServer` с синтетическим
owner и `mode=fixture`. Проверены 512 тестовых NPC, обе страницы, HP / XYZ, предупреждение о
неполноте и очистка открытой карточки после закрытия API. Fixture закрыт;
игрового SDK / Login / транспорта не запускалось. Кадр:
`F:/PhoneExit Resources/Vampir/ui-prototype-checks/environment-fixture.png`, SHA256
`f77d764bf0bb40f534b1db58303237bdf97dfd76384b145fbd39e81f8d0c1ba3`.
Snapshot UI `03bec9057d8657096a99b1dde7963405ceb9193637887f1ce70bf8473bdaae6a`
прошёл verifier: 1970 ресурсов, 1507 textures; это byte/provenance, не игровой live proof.

Материалы вне Git, корень `F:/PhoneExit Resources/Vampir/`:

- Native leave: `code-clues/sight-leave-11316/e4d8e5895d42528f8455b44ec170a2b6d6735e84a1456112a71df3802cedb6c1/manifest.json`.
- Статические anchors: `code-clues/world-registrations-11316/3fb07bced4dde27d7cece52fc75af38c8c38a5390de03cea32524c8d8ba81b8c/manifest.json`.
- Handlers / callbacks: `ghidra/request-exports/<SHA>/run-1c32ee68f2e9/details.json`.
- Initializer / lookup / QuestVisibleActor: `ghidra/request-exports/<SHA>/run-41f06459e5e2/details.json`.

Следом — начальный SightEnter, другие игроки, обновления NPC stats / движения,
current Map / World projection и live проверка потока на том же владельце сессии.
Это оставшаяся часть общей цели; частичный subset её не завершает.
