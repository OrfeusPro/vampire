# LoginResult: вставка в контейнер, rehash и владение именем

31 октября 2026. Источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинные доказательства, reports и замеры](AUTO-LOGIN-CONTAINER-11322.json).

## Исполняемая область

`container-v1` / `login-container` добавляет целый native insert, rehash, name getter
и signed-byte ANSI → UTF-16 constructor к готовому регистрационному helper.
Пять функций содержат 556 инструкций / 2087 байт; отдельно исполняется ID 4 leaf.
Reference seed того же SHA — проекция исходных связей и экспортов, не старый
native report новой композиции. Новое native доказательство обязательно.

| Роль | Адрес | Инструкций | Байт |
| --- | --- | ---: | ---: |
| Registration helper | `0x1467cebc0` | 101 | 395 |
| Insert | `0x1467b77e0` | 204 | 760 |
| Rehash | `0x1467ceeb0` | 113 | 429 |
| Name getter | `0x1456e6290` | 10 | 33 |
| String constructor | `0x1414269b0` | 128 | 470 |

Rehash включает chained unwind; прежний planning-only размер 50 байт не описывал
всю функцию. Новый collector экспортировал все 429 байт с полными block/direct-flow
coverage flags. Прежний однофункциональный report регистрации не переписывался.

Owner проверочного стенда занимает 72 байта: контейнер начинается с `owner+8`
и занимает 64 байта. Node — 40 байт: next / prev, u16 key, packet / handler pair.
Запрос выделения packet — 344 байта; прежний storage extent 352 байта хранится
отдельно. Packet constructor, owner/window и handler в этом пакете не исполняются.

Insert выделяет candidate node до поиска дубликата. При дубликате возвращает
существующий node и status 0, освобождает только свежий candidate размером 40 байт.
Новый payload не заменяет сохранённый. Уникальная вставка и native rehash меняют
list links и bucket first / last; high-level oracle проверяет множество key→payload,
двусвязный цикл, непрерывность bucket segments, размер, mask, count и отсутствие
потерянных nodes. Порядок итерации oracle не фиксирует.

## Name ownership

Native getter принимает RDX как destination, передаёт его constructor и возвращает
тот же указатель. Он заменяет прежний insert outpair строковым descriptor.
Результат insert наблюдается сразу после native возврата, до этого изменения.
Constructor сначала обнуляет 16 байт descriptor, не освобождая прежний pointer.
Null/empty источник оставляет Data / Num / Max равными 0 без reserve.

Непустой ASCII/ANSI источник сканируется до NUL; Num равен длине плюс NUL.
Преобразование знаковое: `80 → ff80`, `ff → ffff`; это не UTF-8 decoding.
Скалярные и SIMD пути пишут UTF-16 из исходных байтов. Reserve fixture выдаёт
свежий buffer и меняет только Data / Max, Num и строку пишет native constructor.
Проверяются exact / rounded capacity, untouched spare bytes и NUL.

В совместном duplicate-сценарии native getter создаёт имя `PktLoginResult` вместо
insert outpair. Последующий helper cleanup освобождает именно name buffer,
сохраняя node / packet / handler. Это уточнение доказано новым контрактом;
прежний preserve-outparam fixture остаётся отдельным историческим сценарием.

## Матрица и ограничения

120 сценариев: 68 constructor, 4 getter, 24 insert, 12 rehash, 12 совместных.
Проверяются null/empty, embedded NUL, scalar/SIMD length thresholds и high bytes,
два poison, точный load threshold, collisions, duplicates first/middle/last,
growth 8 → 64 и ключи `0x100`, `0x101`, `0x104`, `0xffff` для обоих байтов FNV.

Ожидаемые результаты отделены от фактического чтения Unicorn memory. Стенд
наблюдает входные указатели, native call counters и returned outpair; ограничивает
native и fixture writes разными диапазонами. Payloads / source literals защищены
от любых записей, включая совпадающие байты. Canaries, ABI и retired allocations
проверяются; zero-length memory operations отдельно покрыты tooling regression.

Node allocation / sized free, bucket-vector reset и fresh reserve остаются
явными fixtures. Bucket reset меняет только descriptor / собственный buffer:
при росте моделирует storage replacement, иначе заполняет весь прежний range,
сохраняя end/capacity. Native rehash сам меняет nodes / buckets / header.
OS allocators, arbitrary allocator rounding, OOM, SEH/failure, FString grow,
negative/overflow length, malformed maps и concurrent mutation не подтверждены.
`0x1487f7f66` — failure boundary, а не security cookie check. UTF-8 / logger /
security effects также остаются fixtures. Native dispatch и онлайн не исполнялись.

## Автоматизация и повтор

Пять roots покрыты точными whole exports; instructions/calls/RIP data/ID leaf
сверяются по полному SHA. Новое правило связывает их с опубликованными registration
proof и report. Seed вытесняется доказанной ролью; следующая база выбирается по
этой роли. Новый источник требует полного переноса и собственного native report.

Parent validation memo живёт только в текущем SourceStore. Ключ содержит точные
роли context / report, их pointers, source, tools и полную lineage. SHA материалов
повторно проверяются до cache hit; одинаковый union не позволяет переставить
роли. Source barrier в конце сохраняется. Namespace изолирован от направленного
memo frozen input recipe. Старые proof engines не менялись.

Семейство зарегистрировано в [native-check-adapters.json](../../native-check-adapters.json),
обычном `update --auto`, resumable journal и publication cache. Указатель —
`generated-login-container/index.json` в библиотеке ресурсов; он не активирует
игровой профиль. Три субагента подготовили независимый oracle, native стенд
и review; координатор связал source rules, registry, приёмку и публикацию.

Пройдено тестов общего набора: 655; 120 новых native случаев прошли.
Первый проход семейства с новым native доказательством: 578.926169 с.
Два повтора семейства не запускали native / JVM; последний использовал 3 этапа и одну publication receipt, 7.435301 с.
Первый общий проход 27 drivers: 475.521926 с; тёплый: 93.517172 с.
Оба использовали 81 готовый semantic stage без native replay и JVM.
Тёплый проход: publications reused 27, полных publish/transfer 0, PE rebuild 0.
Prepare/collect переиспользовали один root и собрали четыре missing функции одним запуском JVM; очередь пуста.
Byte SHA 48 инструментов / contexts совпали с результатом Git checkout.
В первом проходе parent validation выполнена один раз и переиспользована 3 раза внутри того же SourceStore.
Замеры относятся к выбранным drivers; глобальная сверка исторического индекса учитывается отдельно.

## Следующий общий блокер

По точным RIP-ссылкам на текущие literals найдены candidates dispatch
`0x1467c8f00` (154 инструкции / 647 байт) и lookup `0x1467c9240` (45 / 171).
Их инструкции используют FNV по u16, те же container / node offsets и виртуальные
reader / handler calls; это source-bound навигация, не semantic report.
Экспортов этих двух функций пока нет. Archive constructor `0x144aacc30` уже готов;
wrapper `0x14153bd00`, TLS leaf `0x144aacc10` и cleanup tail `0x144aacc70` требуют
собственного допуска. Подробная planning-only запись включена в next package.

Нужна проверка этих lookup / entry / wrapper и dispatch, связи реальной записи
контейнера с готовым reader → handler, TLS / archive cleanup. Старый Ping dispatch
другого SHA не доказывает эту роль. Интеграции post-state / continuation,
clock / heartbeat, world и настоящий SDK backend остаются отдельными пробелами.
Целый онлайн-вход этим пакетом не допускается. Ordered-pair input seed,
глобальный исторический индекс и холодная публикация других frozen families
остаются инфраструктурными задачами. Профиль и сессия не менялись.
