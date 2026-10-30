# LoginResult: автоматическая композиция native reader и handler

30 октября 2026. Источник 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинные доказательства, reports и замеры](AUTO-LOGIN-COMPOSITION-11322.json).

## Что исполняется

`login-composition-v1` соединяет готовые `login-strings-buffer` и
`login-full-handler` в новый самостоятельный контракт. Native constructor,
buffer construction, scalar / string / UTF-8 readers заполняют пакет 352 байта;
native handler и общий gate получают тот же указатель и те же decoded strings.
Это 22 native roots и шесть leaves. Python-координатор вызывает handler только
после AL success reader; native dispatch, registration и работа онлайн этим
вызовом не подтверждаются.

77 новых сценариев: 48 полных service / error / success ответов, 28 усечений
по одному байту перед концом каждого логического поля и один полный ответ
с хвостом. Проверяются все 28 операций, 20 scalar values, восемь строк, cursor,
ABI, порядок и аргументы, точные handler events / writes / state. При усечении
handler не вызывается. Прежние 506 input-сценариев и standalone handler suite
повторно не исполняются: новый пакет проверяет их композицию.

До чтения пакет заполняет native constructor. После чтения ProtectedMemory
блокирует даже повторную запись тех же байтов в packet / archive / body и
reader-owned allocations. Ограничение действует на native writes, fixture API
и bounded memcpy. Указатели входа reader и handler наблюдаются при исполнении;
до / после дополнительно сверяются bytes, canaries и source strings.
Reader heap и handler heap разделены; shared free не освобождает input allocation.
Два совпавших fixture адреса переключаются по фазе, без shadowing roots / leaves.

Первая native приёмка выявила пропуск в новом tracer: native `time` читает
внутренний u64 во временную переменную на стеке. Observer теперь считает вход
`time` для шести временных полей и прямой `u64` для двух обычных полей; внутренний
stack read не создаёт второго события. Метод и destination сверяются точно,
добавлены два regression-теста. Исходный неуспешный журнал сохранён, исправленный
verifier получает отдельный tools SHA и новое native доказательство.

Storage / growth / assignment / free / security, SDK / UI / clock / persistence,
post-state и continuation effects сохраняют явные fixture границы. Их отдельные
reports не расширяются на реальную сессию и не заменяют integration.

## Перенос и повтор

Seed текущего SHA содержит только проекцию двух уже проверенных child contexts
и их указатели. Новая composition suite обязательна; самостоятельные native
reports не считаются доказательством same-packet передачи. После публикации
доказанная composition роль заменяет seed при выборе следующей базы, включая
равный order и лексически больший путь seed. Этот случай закрыт regression-тестом.

Первый план до native-исполнения выявил ещё одну неоднозначность кэша: frozen
input seed использует union транзитивной lineage без направления переноса.
Наборы для 20→22 и 22→22 совпали, вернулась прежняя mapping. Новый composition
adapter переиспользует точно совпавший child pointer после полной проверки;
cross-source transfer получает отдельный mapping namespace с общим SourceStore.
Тесты проверяют отсутствие self-transfer, сохранность source barrier и parent memo.
Исходный остановленный план сохранён; новый tools SHA создаёт отдельный проход.
Общий ordered-pair memo требует новой версии input recipe и остаётся отдельной
задачей; frozen код и исторические доказательства этим исправлением не менялись.

Точно совпавшие child pointers переиспользуются после полной проверки. При
разных источниках оба child transfer сверяются с независимо доказанными target
contexts. Правило
проверяет source, table, ID 4, memcpy, leaf bytes, aliases и отсутствие конфликтов
общих mappings. Exact exports покрывают все 22 roots с whole coverage flags;
21 обычное тело нормализуется целиком, gate использует своё code/data правило.
Повреждённый proof, изменённый layout, лишняя функция или несовпавшая зависимость
дают конкретный блокер.

Семейство зарегистрировано в [native-check-adapters.json](../../native-check-adapters.json)
и подключено к `update --auto`, resumable journal и publication cache.
Указатель результата — `generated-login-composition/index.json` в библиотеке
ресурсов. Прежние proof engines и документы доказательств не переписывались.
Три субагента подготовили правило, verifier / contract и независимую ревизию;
координатор выполнил регистрацию, приёмку, публикацию и проверку кэша.

Пройдено тестов общего набора: 564; 77 новых native случаев прошли.
Два повтора семейства не запускали native / JVM; последний использовал 3 этапа и одну publication receipt, 26.063749 с.
Первый общий проход 25 drivers: 704.45477 с; тёплый: 162.331708 с.
Оба использовали 75 готовых semantic stages без native replay и JVM.
Тёплый проход: publications reused 25, полных publish/transfer 0, PE rebuild 0.
22 функции взяты из четырёх готовых exports; missing 0, Ghidra не запускался.
Byte SHA 43 инструментов / contexts совпали с результатом Git checkout.
Замеры относятся к выбранным drivers; глобальная сверка исторического индекса учитывается отдельно.

## Остаток

Далее registration owner/window и native dispatch с готовым контрактом
reader→handler, затем недостающая integration post-state / continuation,
clock / heartbeat и world. Настоящий SDK backend и целый онлайн-вход остаются
открытыми. Этот пакет не выполнял авторизацию, игровые команды или назначение
профиля и не менял текущую сессию.
