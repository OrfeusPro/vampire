# Полный CharacterOther и общий курсор вложенных записей

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Whole `PktCharacterOther`: constructor `145783670`, reader `145788180`,
vtable `149921ca8`, native stride 230 hex. Это wire proof; actor / world
применение и живая видимость другого игрока ещё не доказаны.

## Уточнение типа +f8

В [предыдущем описании вложений](HEADLESS-SIGHT-EFFECTS-11316.md) descriptor
`149948d70` был назван ground effects. Это неверная классификация для
CharacterOther+f8. Source callback `145789c10` создаёт **PktActorAction**,
vtable `149921ad8`, reader `145786190`, stride 78 hex.
Он использует optional wrapper `1456b7060` и `PktPositionData`,
vtable `149921a70`, constructor `1457a2530`, reader `1457a5b60`.
Ранее подключённый runtime этот массив не использовал; ошибка осталась в
статическом описании и исправлена до native проверки / подключения CharacterOther.

ActorAction wire: `byte clamp5; u32; u64; raw time u64; bool optionalPosition;`
`if true: float32 XYZ; byte yaw`. Это 22 bytes без PositionData и 35 с ней.
Optional wrapper лежит в action+20, данные PositionData — в action+30.
Последний содержит XYZ в +8 и yaw в +20. Отсутствующая позиция возвращается
как `None`; незаполненные native поля не превращаются в координаты.
Это не наземные эффекты внешнего SightEnter, несмотря на одинаковый stride 78.

## Полная форма

Порядок CharacterOther: два u64, u32, UTF8 string, два u32, byte clamp6, u32,
CharacterAppearance, u16, float32 XYZ, yaw, массив Stat, u64, массив EffectData,
bool, массив ActorAction, GuildTinyInfo, optional PartyTag, optional byte-key map,
bool / byte clamp3 / bool / byte clamp3. Имена / уровни / HP по величине не назначаются.
Все поля сохраняются с native offsets; stat values / time остаются raw uint64.
Внешность, effects и map используют ранее проверенные текущие readers.
Для Guild / Party используются [готовые декодеры](HEADLESS-SIGHT-SOCIAL-11316.md).

`current_record_reader.py` задаёт один source-bound cursor и общий бюджет.
Он поддерживает последовательные записи без угадывания границ по native stride.
Бюджет 0–4096 (default 1024) списывается за каждую wire запись массива / map,
включая повторные map keys до их замены. Максимальный input — 64 KiB, только
immutable bytes; источник должен совпасть с полным SHA. UTF8 / text policy общая.
Guild / Party boundary scanners только выделяют проверенные variable-length
тела; значения читает существующий decoder. Отдельные public wrappers требуют
точного конца тела; общий reader может читать несколько записей с одним бюджетом.

NPC create переведён на тот же reader: публичный результат / поля / лимиты
сохранены. Причина переноса — необходимость вложенного чтения и общего бюджета
CharacterOther / будущего SightEnter. Его прежние 323 native / portable сценария,
454 префикса и guards прошли после переноса; проверки знаний учитывают новый файл.

## Проверки

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_character_other_11316.py
```

Три теста прошли. 1797 native сценариев исполняют весь CharacterOther вместе с
непустыми appearance / stats / effects / ActorAction / Guild / Party / map,
настоящими input / UTF8 / XYZ / yaw. Optional Party / map absent / present,
позиция action absent / present, повторные map keys с заменой, высокие uint64,
nonfinite float bits, Unicode и все 256 root heading bytes.
Для трёх богатых тел проверен каждый префикс. Сопоставлены acceptance, cursor,
scalar / text / vector / optional / map values и guards объекта / archive /
input / allocations. Native trailing cursor проверен отдельно; portable строже
и отвергает trailing. Raw heading не смешивается с native canonical yaw.

Guard-тесты проверяют лимиты / источник / immutable input / malformed text,
общий бюджет вложений, списание duplicate map entries и две последовательные
записи с одним cursor / budget. Разные результаты не разделяют изменяемое состояние.
Это не новый тест двух игровых аккаунтов или UI.

Fixtures: свежие пустые объекты; до 8 slots в array / map storage, фактические
array counts в этих сценариях 0 / 1 / 2, map wire entries до 3; bounded string /
vector / sparse-map allocation, assign / free / rehash / cookie. Wire readers,
callbacks, constructors и nested optional / map insert исполняются native.
Reuse, growth, allocator и engine эффекты не доказаны. Sparse-map storage fixture
переиспользована с явной привязкой к CharacterOther+1d8, без изменения engine.
Yaw использует source SSE2 branch и реальные UCRT `atan2` / `fmod`; import
descriptors проверены, SHA DLL записан. AVX не проверен.

Harness scope `sight-character-other` допускает ровно 57 явных функций и до
25 source-bound exports, с точным набором адресов и main constructor / reader.
Произвольный scope / подмена функции отклоняются тестом. Прежние budgets не
расширены. Контекст: [sight-character-other-11316.json](../../native-contexts/sight-character-other-11316.json).
`live-sight-character-other-11316` фиксирует исходники, fixtures, exports,
Capstone / Unicorn и UCRT / CRT locale. Проверки NPC / environment дополнены
зависимостью общего reader, чтобы его изменение инвалидировало их кэш.

Отчёт вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/sight-character-other-11316/d8d0128e30a90fe24940df8f7f52ef8d0d359bd609e7c19bed6899168a6ca6ad/manifest.json`.
SHA256 отчёта совпадает с именем каталога.

Новые exports в `ghidra/request-exports/<SHA>/` библиотеки ресурсов:

| Экспорт | SHA256 details.json | Состав |
| --- | --- | --- |
| run-305db971767d | 8b245d94fb41ad6431a3ed51cd9137ec14e39d8dd1bbb0308445374c1eb7a4fe | ActorAction callback / resize |
| run-d7330363dde5 | b5fb1e025cfc2cc3dda422dce68bb57b4769df870faa5a2ad5c1be62644e406b | ActorAction reader, PositionData constructor / reader / cleanup |

Следом — полный mixed-array SightEnter с настоящими outer callbacks, общим
бюджетом, handler / actor / world связью и подключением initial entities.
Runtime ID 301 пока не подключён; [наблюдаемый NPC subset](HEADLESS-OBSERVED-ENVIRONMENT-11316.md)
остаётся partial. Живой вход и multi-account integration в этом этапе не выполнялись;
общая цель не завершена.
