# SightEnter: владение временными записями

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [композиции wire reader](HEADLESS-SIGHT-ENTER-COMPOSITION-11316.md).
Это статическая проверка существующих callbacks и семи новых explicit exports;
native исполнение copy / cleanup на этом этапе не выполнено.

## Подтверждённая цепочка

| Запись | Callback | Copy | Cleanup временной записи |
| --- | --- | --- | --- |
| CharacterOther | 1456c5e60 | 1456bedd0 | 145785200 |
| NpcCreateData | 1456c6400 | 1456bfe20 | 14579b810 |
| Gadget | 1456c6270 | 1456bf7a0 | 1457911d0 |
| GroundEffectData | 1456c62f0 | inline scalar / nested heading stores | 145791230 |
| TetherEffectData | 1456c67a0 | inline scalar / nested heading stores | 1457a44c0 |

Callbacks из `run-81dc5e726695` создают временную stack запись, вызывают virtual
reader и при успехе увеличивают count, при необходимости расширяют массив,
копируют в final slot, затем очищают временную запись. Native strides по-прежнему
230 / 240 / d0 / 78 / 90 hex; они не используются как wire lengths.

CharacterOther copy не является общим memcpy. Он вызывает FString copy
`1414266a0`, appearance copy `1456beaa0`, Guild copy `1456bfad0`, map copy
`1456c08d0`; создаёт отдельное storage stats / effects / actions через
`141539310` / `141afa010` / `143767860` и копирует элементы через
`1456bc800` / `1456bc700` / `1456bbc50`. В cleanup есть освобождение строк,
map storage и массивов, nested Party / Guild / effect / action cleanup.
Поэтому shallow-copy fixture с последующей пустой cleanup fixture не доказывает
владение этой записью. Прежний component replay читает прямо в final object и
не покрывает эту дополнительную цепочку.

NpcCreateData copy также отдельно обрабатывает effects / appearance / map /
stats / move / owner. Gadget copy создаёт отдельный uint64 vector, копирует
его через импорт memcpy и вызывает FString copy для owner. Его cleanup вызывает
owner cleanup `1457846a0` и освобождает vector storage. Ground / tether callback
копируют поля непосредственно; cleanup меняет vtables и вызывает heading cleanup
`1456b66c0`. Эти наблюдения не доказывают отсутствие других engine эффектов.

## Источники и следующий эксперимент

Новый export: `ghidra/request-exports/<SHA>/run-b99c0915056c/details.json`
в `F:/PhoneExit Resources/Vampir/`. SHA документа details фиксируется completion
manifest и facts; collector проверил семь выбранных unwind roots без общей
декомпиляции EXE. `14579b810` уже был доступен и повторно не выгружался.

Следом использовать эти exports для whole native SightEnter. Нужны точные
source-bound nested copy / cleanup и bounded allocation/free с проверкой отдельных
owners, временных адресов, duplicate keys и guards после очистки. Начать с
CharacterOther copy: `1414266a0`, `1456beaa0`, `1456bfad0`, `1456c08d0`,
`1456bbc50`, затем их явные недостающие callees. Внешние callbacks / resize должны
исполняться native, а fixtures оставаться на границе storage. После этого —
handler → actor / world и initial entities. Runtime ID 301 не подключён;
нового игрового входа и проверки нескольких живых аккаунтов не было.
