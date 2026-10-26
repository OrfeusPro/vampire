# SightEnter: native копирование вложений

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [outer copy / cleanup](HEADLESS-SIGHT-ENTER-COPY-11316.md).
Этот этап проверяет вложенные copy функции, нужные для целого SightEnter.
Runtime ID 301 не подключён; целый outer reader / callbacks ещё не исполнялся.

## Native границы

| Копия | Entry | Проверенный размер / граница |
| --- | --- | --- |
| FString | 1414266a0 | отдельный UTF16 buffer, пустой / Unicode / 31 ASCII chars |
| CharacterAppearance | 1456beaa0 | строка и 0 / 1 / 2 / 8 item records |
| GuildTinyInfo | 1456bfad0 | строка, scalar fields, emblem / time |
| ActorAction array | 1456bbc50 | 0 / 1 / 2 / 8 records, stride 78 hex |
| Sparse map | 1456c08d0 | 0 / 1 / 2 / 8 slots, occupied / alternating holes |
| Bitmap | 14143b910 | inline bitmap, до 8 bits |
| Fresh map reset | 1456c7280 | пустой destination, последующее выделение nodes |

Полное native тело appearance-item copy `1456b5280..1456b52cb` — leaf без
unwind-записи: 76 bytes, два внутренних перехода, нет calls, завершается ret.
Стандартный collector отклонил mixed request с этим адресом; leaf сохранён как
явные source bytes и исполняется native. Тест проверяет полноту декодирования,
конец и внутренние targets; harness сверяет все bytes с полным SHA клиента.
Остальные семь entries используют явные Ghidra exports. Бюджет harness не расширен.

62 сценария исполняют эти функции, а не Python-модель копии. Для непустых строк,
appearance items, map nodes / heap buckets проверены разные pointers; исходные
buffers после копии заполняются DD, результат сохраняется. Для actions проверены
scalar / optional-position / XYZ / heading bytes и сохранность после изменения
исходного массива. Сверены native vtables, counts и bounds объекта / heap guards.
Source object до намеренного изменения остаётся неизменным.

Sparse map проверен с 0 / 1 / 2 / 4 / 8 hash buckets, пустыми и непустыми nodes,
всеми занятыми и чередующимися свободными slots. Native copy сохраняет allocation
bitmap и free-list поля; занятые записи копируются по полям, свободные — как
free-list pairs. Wire map / вставка / повторные ключи здесь не конструируются;
их отдельный decoder proof не подменяется этим memory-copy тестом.

Fixtures только storage: выделение UTF16 / appearance / node / bucket buffers,
проверка receiver / count / свежего owner и обычный memcpy import. FString и
appearance / Guild / action / map / bitmap interpretation исполняются native.
Неожиданные growth, bitmap heap allocation и cleanup непустого destination
останавливают тест. UTF16 storage до 2048 units; фактические строки до 32 units
с terminator, остальные allocations до 8 элементов, heap ограничен. Fixture
allocator не является проверкой настоящего allocator / OOM.

## Воспроизведение и источники

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_nested_copy_11316.py
```

Два теста прошли: 62 native сценария и проверка source leaf boundaries.
Контекст: [sight-nested-copy-11316.json](../../native-contexts/sight-nested-copy-11316.json).
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/sight-nested-copy-11316/2e612e6b2f2e742d55afcc3c362888f2e053a825e223262b00d1f0adacfa6c12/manifest.json`.
SHA256 отчёта совпадает с именем каталога.

Новые `ghidra/request-exports/<SHA>/` в библиотеке ресурсов:

| Export | SHA256 details.json |
| --- | --- |
| run-cf2ead9edc66 | ea01815605d6684b52107b757bbfda996edf7f8f65e410d02fa4e8767119bec6 |
| run-b4bb65aa6eaa | 2ccd20934b715805ec9444292e63ffcd3d8d733ec85c05a77203ecd5c43787bd |

FString / fresh map reset взяты из прежних exports, полные SHA включены в context.
Зарегистрированная проверка учитывает source / context / scripts / exports и
закреплённые Capstone / Unicorn. Приватного сетевого трафика в fixtures нет.

## Что осталось

Изменение source buffers проверяет независимость копии, но не исполняет настоящий
destructor/free исходной записи. Reuse / heap bitmap / большие counts / OOM,
полные CharacterOther/NPC/Gadget copy + cleanup и outer callback ownership ещё
не проверены. Следующий шаг — объединить имеющиеся native readers и copies с
настоящими outer callbacks, временными owners и проверяемым free/cleanup; выполнить
whole mixed SightEnter, затем handler → actor / world и initial entities.
Игровой вход, multi-account integration, движение и актуальная карта не проверялись.
