# QuestTask: ненулевой ServerServiceGroupId и native policy

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`bd5f1d04e25bdc6a04818b712ce85ef56c18d63f73252ad44292422a0b2f9094`.
Новый getter export run-c9ac9c288a06, SHA
`c7b122492bc128e6ff2f359120bcb62c9c447b02d6ba31aa7cd6d87443a5b9bd`.
Gate/policy export run-ad5876ba33cb, SHA
`b269cb2cbd38d2b4f56d20de65759281e1386379cf567ebd4005f44fca45a2aa`.

## Исполненная цепочка

Whole `145a4d2f0` читает ненулевую service cell через exact getter/SSO leaf и
actual local Windows atoi. Затем вызываются настоящий environment getter
`145bfe3d0` и целая policy `145c022b0`. Gate возвращает skip byte: 0 — оставить
строку, 1 — пропустить. Source group 10000 задан в synthetic cell; это не
actual CSV row creation в данном replay. Прежние
[zero-gate случаи](HEADLESS-QUEST-EMPTY-GROUP-11316.md) сохраняются отдельно.

Getter возвращает singleton `14b1c7890`. Policy читает его map nodes +28,
count +30, free count +5C, inline buckets +60 / external +68, bucket count +70.
Node stride 32, uint32 group key +0, TArray value +8, chain next +18.
Текущие uint32 fields singleton+78/+7C участвуют в дальнейших условиях.
Их продуктовые имена и актуальные значения ещё не доказаны; «type» и «server»
в коде replay — только аналитические labels по offsets.

Getter/policy содержат TLS static-init check. Replay задаёт GS/TLS array,
TLS index 0, epoch stamp 0 и global epoch 0: исполняется already-initialized
путь. Cold init, atexit/registration и thread concurrency не проверяются.
Неизвестный initialization target остаётся запрещённым, fixtures для него нет.

## 30 native случаев

15 manager/layout scenarios × inline/external buckets:

- Пустая map, отсутствующий group key и пустой TArray дают skip=1.
- При непустой найденной группе и current field +7C=0 получается skip=0.
- При ненулевом +7C, если ни одна record не совпала по record+0C и current+78,
  получается skip=1.
- Совпадение current +7C в списке record+18 даёт skip=1 до проверки следующего
  списка, даже если current ID находится и в record+28.
- Совпадение в record+28 даёт skip=0 без version lookup.
- Если списки не совпали, missing version даёт skip=1. При version ниже
  record+10 или выше record+14 — также 1; на min/max и внутри диапазона — 0.
- Несовпадающие непустые списки проходят к version comparison.

Каждый вызов gate выполняет ровно один actual atoi для `10000`. Native policy
сама обходит buckets, group array, записи и списки, сравнивает поля и выбирает
ветвь/результат. Version manager/getter — fixtures; чтение version result+28 и
signed bound comparisons — native. Входные manager/nodes/record/cell bytes и
guards не меняются, все временные string/list allocations освобождены.

## Fixtures и ограничения

Synthetic manager records, current numeric fields, list contents и version
result заданы явно. Numeric-ID→FString, split, string resize/copy/compare,
array cleanup/free и version lookup — bounded fixtures. Аллокатор успешен,
не более четырёх элементов списка и 64 UTF-16 units на строку. Системная CRT
вызвана через проверенный IAT bridge, SHA/locale System32/ucrtbase.dll сохранены
до/после. Native substring/string implementation не выполняется.

Это proof policy control flow при указанных inputs. Actual current service
table loading, значения singleton+78/+7C и active server/config не проверены.
Нельзя трактовать synthetic group 10000/ID42/version15 как текущую игровую
конфигурацию или пропускать все непустые строки на основании этого теста.
Whole catalog/file/header/active policy admission остаётся открытым;
`order_admitted=false`, gameplay и owner API не используются.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_policy_11316.py
```

`replay-quest-service-policy-11316.py`, контекст
`knowledge/native-contexts/quest-service-policy-11316.json`, offline check
`native-quest-service-policy-11316`. Артефакт:
`code-clues/quest-service-policy-11316/a2eea01371d1cb37d4b13a854e1680c25a692901d81c58c45a6d7d90fac94b40/manifest.json`.

Далее — связать current service table / numeric environment с этим policy и
проверять whole QuestTask catalog. Действующая сессия не прерывалась.
