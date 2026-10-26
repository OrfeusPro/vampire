# CharacterOther: native чтение, копия и очистка двух владельцев

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [whole reader](HEADLESS-CHARACTER-OTHER-11316.md) и
[nested copy](HEADLESS-SIGHT-NESTED-COPY-11316.md). Это проверка одной цепочки
записи для будущих outer callbacks SightEnter; целый SightEnter и live ещё открыты.

## Исполненная цепочка

Общий replay теперь имеет отдельный optional lifecycle hook; обычная проверка
reader сохраняет прежний путь. Lifecycle использует отдельный context и native
`145788180` reader, `1456bedd0` copy и `145785200` destructor. Reader исполняет
прежние вложенные appearance / stats / effects / ActorAction / Guild / Party / map,
настоящие input / UTF8 / XYZ и source SSE2 yaw с реальными UCRT imports.

После успешного чтения создаётся fresh final object и исполняется native copy:
FString, appearance, Guild, stat / effect / action arrays и sparse-map copy.
Значения сравниваются с полным portable decoder до очистки source. У непустых
вложений проверяются отдельные живые pointers. Затем native destructor очищает
source, каждый освобождённый buffer заполняется DD и copied object проверяется
повторно. После этого исполняется его native destructor. При отказе reader
исполняется только destructor частично прочитанного source.

Native cleanup включает Party `1457a3700`, Guild `14579ac40`, stat / appearance
array cleanup `1456b5990` / `1456b59c0`, effect array `1456bcc10` с прежним
effect destructor и action array `1456bc920` с `145784630` / PositionData cleanup.
Фикстуры пустого предыдущего массива не перекрывают эти native функции в lifecycle.

Leaf stat copy `1456bc800..1456bc842` (67 bytes) и effect copy
`1456bc700..1456bc7fa` (251 bytes), а также прежний appearance item leaf,
сохранены полными source bytes. У них нет unwind roots; проверены отсутствие
calls, полнота декодирования, ret и внутренние переходы. Harness сверяет каждый
byte с EXE. Они исполняются native, не заменяются Python копированием полей.

## Проверки и фактические числа

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_character_lifecycle_11316.py
```

Три теста прошли. Использованы прежние 1797 recorded сценариев: 280 полных тел
и 1517 обрезанных префиксов, плюс 280 отдельных проверок trailing cursor.
Итого 2077 чтений, 560 successful copies, 2637 native destructors и 14226
освобождённых tracked buffers, включая input/string temporaries. Каждый prefix
трёх богатых тел проверен. Все 256 root yaw bytes, optional Party / map,
position action, высокие uint64, Unicode / длинная строка и nonfinite XYZ сохранены.

После каждого сценария нет неосвобождённых tracked allocations. Free fixture
отклоняет неизвестный pointer и повторное освобождение; buffer poisoning выявляет
alias при повторной сверке копии. Guards source / final objects, input / archive
и всех выделений сохранены. Empty copied map может иметь null storage при count 0;
сверка reader теперь допускает этот настоящий результат native copy, сохраняя
проверку непустого owner/count. Пустой map не превращается в absent optional.

Scope `sight-character-other-lifecycle` допускает ровно 72 явных roots и до 31
проверенного export, только при точном наборе и read / copy / destroy entries.
Подмена entry / набора отклоняется тестом. Старые scope budgets не расширены.
Контекст: [sight-character-other-lifecycle-11316.json](../../native-contexts/sight-character-other-lifecycle-11316.json).

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/sight-character-other-lifecycle-11316/9ae5dd38b7c4c70ea399ff5a314f181ad9b41c1daa0fb5ccb42895fd01f4ba0e/manifest.json`.
SHA256 отчёта совпадает с каталогом. Зарегистрированная проверка учитывает common
replay, lifecycle module, source/context/fixtures/exports, Python, Capstone/Unicorn
и UCRT DLL. Старые reader / другие harness consumers проходят свои regression checks.

Новые exports в `F:/PhoneExit Resources/Vampir/ghidra/request-exports/<SHA>/`:

| Export | SHA256 details.json |
| --- | --- |
| run-cb6ca5ce1299 | d0ce522b151f4d98c1b660d75893fe80719149fca8bcb876b57dc3c251025aeb |
| run-7af156bf0ebc | 6049816ff5a9562558f6af937d6a6467f3069fe092311fc3f5ae09bc61a409ef |

## Ограничения и продолжение

Storage fixtures: bounded fresh string/vector/map allocation, FString assign,
ordinary memcpy и отслеживаемое free. Map reset/clear остаётся storage fixture:
source чтение использует прежний ограниченный sparse-map storage; final copy
исполняет native map / bitmap copy, очистка снимает count, а native CharacterOther
destructor освобождает buffers. Настоящая map cleanup iteration этим не доказана.
До 8 reserved slots, фактические component array counts 0/1/2, map до 3 wire entries;
inline bitmap. Реальный allocator, OOM, heap bitmap, reuse и engine не проверены.

Это два memory owners одной записи, а не два игровых аккаунта. Нет нового входа,
actor/world semantics или полной проверки видимости. Следом — настоящий outer
SightEnter с временными stack owners/callbacks и NPC/Gadget lifecycle, затем
handler → actor / world и initial entities в изолированной модели. ID 301 пока
не включён в runtime; живая multi-account интеграция остаётся обязательной.
