# Fetch текущего SDK: точные материалы после отказа 1203

Target EXE SHA256:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
База Fetch — `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Этот пакет собирает текущие whole exports и уточняет callback. Он не предоставляет
допуска операции Fetch, создания SDK-профиля или игрового мира.

## Ограниченный поиск и callback

Поиск ограничен unwind roots в окне ±128 KiB относительно трёх прежних roots.
Использованы полные SHA сохранённых EXE и формы целых инструкций. Найден один
кандидат Fetch request: `0x1444e7b80` (621 инструкция). Для Fetch response найдено
два похожих тела; выбор сделан по source bytes самого request:
`0x1444deed0` содержит `e9abadfeff`, переход в `0x1444c9c80`.
Это whole unwind root с 667 инструкциями. Второй кандидат response не выбран
только по похожему коду.

Поле scope ведёт в global `0x14b564c10`; из трёх literal-кандидатов initializer
только `0x1411b0620` обращается к этому global. Его 39 исходных байт содержат
семь инструкций, вызов `0x141426b90` и E9 в `0x1487ec32c` внутри CRT-функции.
Whole Ghidra export initializer остановился на строгом запрете выхода block за
unwind ranges. Это отдельная граница, проверка не отключалась. Его декомпилированный
текст из failed run не используется как завершённое доказательство.

## Успешный пакет тел

Initializer исключён из нового запроса с явной причиной; request и response
выгружены целиком в `run-74606681db58` существующего target project. Исходный
неизменный failed request не повторялся. В request сохранены сборка credential /
scope, suffix endpoint и callback pointer; их callees / данные ещё требуют
source contract до runtime допуска.

| Материал в библиотеке ресурсов | Результат |
| --- | --- |
| `knowledge/sdk-fetch-current-navigation.json` | Bounded candidates и полные source SHA; не admission |
| `knowledge/sdk-fetch-current-link.json` | Точные E9 bytes / callback target |
| `knowledge/research-scoped-v2-requests/756575e033efd936a8a4394cc770b7766fc1c281ab2ce302a3363aff860f681c/manifest.json` | Исходный запрос трёх roots; collect остановлен |
| `knowledge/research-scoped-v2-requests/4f4bc10fdd235eccf380b7a9bcb921a1c1486a167f920945f897964e7a67cfa4/manifest.json` | Запрос двух тел с причиной изменения |
| `knowledge/research-scoped-v2-collections/72734dbc07c9f7e804a782a4eac4df7f1ec3b3f9b156b40531f552a85dd3d101/manifest.json` | Оба тела ready |
| `ghidra/request-exports/03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f/run-74606681db58/details.json` | Завершённые exports request / response |

Старый [Fetch-контракт](HEADLESS-RELEASE-FETCH-CONTRACT.md) остаётся базой для
нового source contract. Следующий пакет должен проверить payload / headers /
response subset и необходимые callees на target, отдельно от initializer CRT tail,
затем собрать точный immutable Fetch-only scope. Нынешний SDK Launcher scope
явно запрещает direct Fetch / SignUp, его guard не расширен. Ни один дополнительный
запрос к Silvercrow или другим аккаунтам здесь не отправлялся. Ненулевой код
launcher SignIn не интерпретируется как автоматическое разрешение SDK SignUp.
