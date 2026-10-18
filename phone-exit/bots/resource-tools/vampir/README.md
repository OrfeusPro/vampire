# Исследование ресурсов Vampir

`build-headless-sdk-config.py` → `code-clues/headless-sdk-config.json`:
7 SDK diagnostic literals, 8 LEA, 7 roots, 48 constants и 256 native mode cases.
[HEADLESS-SDK-CONFIG.md](HEADLESS-SDK-CONFIG.md): GMC2 address selection и
статические части URL; активная конфигурация/ответ/декодирование ещё неизвестны.

`build-headless-auth-index.py` → `code-clues/headless-auth-index.json`:
24 selected SDK symbols/34 LEA/24 roots, 143 constants, 512 native escaping calls.
[HEADLESS-AUTH.md](HEADLESS-AUTH.md), общий auth_request.py создаёт offline
code/refresh form plans; нет получения пароля/токена, HTTP или игровой сессии.

`build-headless-send-drain.py` → `code-clues/headless-send-drain.json`:
61 native drain/partial/error cases, ordinal Winsock import проверен по local DLL.
[HEADLESS-SEND-DRAIN.md](HEADLESS-SEND-DRAIN.md), shared socket_send.py,
real local IPv4 TCP test. Connect/auth/live game этим не подтверждаются.

`build-headless-send-b.py` → `code-clues/headless-send-b.json`:
40 native send-B/CRC/keyed XOR/queue-copy cases, Ping/KeyChanged.
[HEADLESS-SEND-B.md](HEADLESS-SEND-B.md), общий send_frame.py/outbound.py;
allocator growth, drain/socket и весь Notify→wire остаются открытыми.

`build-headless-receive-b.py` → `code-clues/headless-receive-b.json`:
39 native B/keyed XOR/ID lookup-remove/Dispatch cases, notification list empty.
[HEADLESS-RECEIVE-B.md](HEADLESS-RECEIVE-B.md), общие receive-B helpers;
семантика manager/подписчиков и whole transport integrity остаются открытыми.

`build-headless-dispatch.py` → `code-clues/headless-dispatch.json`:
24 native receive-A→Dispatch→PingResult reader→OnHandler entry scenarios;
handler body capture, registry/lifecycle fixtures, diagnostic formatting skip.
[HEADLESS-DISPATCH.md](HEADLESS-DISPATCH.md), общий receive_packet.py.

`build-headless-listener-loop.py` → `code-clues/headless-listener-loop.json`:
44 native loop cases; real probe/broadcast/receive-A/XOR/compaction,
container lifecycle fixtures и final callback capture.
[HEADLESS-LISTENER-LOOP.md](HEADLESS-LISTENER-LOOP.md), shared take_receive_a_frame.

`build-headless-block-decode.py` → `code-clues/headless-block-decode.json`:
166 valid / 86 invalid native cases; shared block_decode.py и take_transport_frame.
[HEADLESS-BLOCK-DECODE.md](HEADLESS-BLOCK-DECODE.md): распаковка с повторами,
статическая связь listener slots +0x38/+0x40; полный receive pipeline ещё не готов.

Начинать разработку с [главного файла модуля](../../vampir/README.md).

`build-headless-transport-stage.py` → `code-clues/headless-transport-stage.json`:
62 native receive-stage сценария, length 23/compressed flag/native decompressor.
[HEADLESS-TRANSPORT-STAGE.md](HEADLESS-TRANSPORT-STAGE.md), shared transport_header.py;
распаковка расширена в HEADLESS-BLOCK-DECODE.md; доставка слушателям/CRC ещё требуют проверки.

`build-headless-key-change.py` → `code-clues/headless-key-change.json`:
Notify11/ack12,10 native payload roundtrips/16 shortcases/20 handler slices.
[HEADLESS-KEY-CHANGE.md](HEADLESS-KEY-CHANGE.md): send-before-key-update,
registration/source/limitations; общий key_change.py не управляет сессией.

H03b.2b partial: `build-headless-receive-envelope.py` → `code-clues/headless-receive-envelope.json`.
Length probe 156 cases, receive wrapper 13 cases, static callback→Dispatch;
[HEADLESS-RECEIVE-ENVELOPE.md](HEADLESS-RECEIVE-ENVELOPE.md). Shared receive_frame.py
добавляет localbounds, полный transport/CRC/keyflow ещё unknown.

H03b.2a: `build-headless-send-frame.py` → `code-clues/headless-send-frame.json`.
Цельная native сборка Ping send-A, 20 cases, shared `vampir_core/send_frame.py`.
[HEADLESS-SEND-FRAME.md](HEADLESS-SEND-FRAME.md): length/CRC/ID/sequence/body/XOR,
explicit environment и ограничения; receive validation ещё H03b.2b.

H03b.1: `build-headless-frame-primitives.py` → `code-clues/headless-frame-primitives.json`.
252 native executions CRC32/XOR, без shims; shared runtime в
`vampir-shared/vampir_core/frame_primitives.py`.
[HEADLESS-FRAME-PRIMITIVES.md](HEADLESS-FRAME-PRIMITIVES.md): callers и ограничения;
полный frame/key/context ещё H03b.2.
Общие найденные функции всех направлений — [FUNCTION-INDEX](../../vampir/FUNCTION-INDEX.md).
Самостоятельный сетевой бот: [README/задачи/журнал](../../vampir-headless/README.md).
`build-headless-network-index.py` строит SHA-bound индекс выбранных сетевых
строк и проверенных LEA в `code-clues/headless-network-index.json` библиотеки.
Это статические привязки, не готовый сетевой протокол.

H02: `build-headless-packet-bindings.py` → `code-clues/headless-packet-bindings.json`.
10 типов/5 регистраций, constructor/vtable/ID/IO targets, контекстные коллизии
Login/LobbyLogin; [HEADLESS-PACKET-BINDINGS.md](HEADLESS-PACKET-BINDINGS.md).
Не готовый wire codec; общий реестр обновляется вместе с отчётом.

H03a: `build-headless-ping-codec.py` → `code-clues/headless-ping-codec.json`.
Native constructors/primitive/raw buffer IO, 126 scenarios; только memcpy shim.
Переносимые Ping payloads — `vampir-shared/vampir_core/ping.py`.
[HEADLESS-PING-CODEC.md](HEADLESS-PING-CODEC.md): реальные bytes и границы
подтверждения. Framing/transport остаются H03b/H03c.

Данные: `F:/PhoneExit Resources/Vampir`.
Установка: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
Переопределение: `PHONEEXIT_VAMPIR_RESOURCES`, `PHONEEXIT_VAMPIR_INSTALL`.
Оригиналы не меняются. Не сохранять секреты, файлы аккаунта или дампы памяти.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/scan-resources.py
python -X utf8 phone-exit/bots/resource-tools/vampir/export-images.py
python -X utf8 phone-exit/bots/resource-tools/vampir/assemble-nocturne.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-ui.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-tables.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-tables.py --archive pakchunk1-Windows
python -X utf8 phone-exit/bots/resource-tools/vampir/find-code-clues.py
python -X utf8 phone-exit/bots/resource-tools/vampir/find-quest-tables.py
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-dependencies.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-ui.py --tutorial-controls
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-native-enums.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-quest-graph.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-reward-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-shop-links.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-canvas-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/decode-panel-slots.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ui-topology.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-runtime-chain.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-tutorial-bindings.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-gallery.py
```

`scan-resources.py` сохраняет инвентаризацию `.pak/.utoc/.ucas`, размер,
mtime_ns и SHA256 первых+последних 64KiB. Это отпечаток для обнаружения изменения,
а не полный SHA256 исходного архива. Читает записи PAKv11, ограничивает
декодирование существующим reader RF; шифрованные записи пропускает.
`source.json` рядом с entries.json предотвращает использование старых
результатов после смены архива. pak-scan-progress.json обновляется атомарно.
После обновления игры рекомендуется новая папка библиотеки, чтобы сохранить
старые ресурсы; в прежней папке повторный запуск пересканирует изменённые PAK.

Общий reader: `../rfnext/scan-pak.py`; используется уже установленный локальный
Oodle DLL из `F:/PhoneExit Resources/RF Online Next/tools`. Его происхождение
зафиксировано там в oodle-source.json. DLL и извлечённые данные не входят в Git.
Общая библиотека декодирования не означает совместимости игровых таблиц RF.

`export-images.py` использует общий декодер DXT1/DXT5/BC7/BGRA и сохраняет:

- archive-image-catalog.json — все варианты PNG и источники;
- archive-image-latest.json — рабочий выбор по наибольшему `_sN`;
- map-image-catalog.json — выделенные текстуры карт;
- texture-export-errors.json — ошибки, не подменяемые успешными изображениями.

Выбор `_sN` предварительный: перед игровым применением сверять с manifest
установки и экраном Android. Положение плитки нельзя выводить только из
порядка файлов. Отдельно проверяются оси, прозрачные поля, сетка, подписи,
координаты и преобразование мир→пиксели. Эти проверки пока не завершены.

Текущее состояние бота и живые проверки: [../../vampir.md](../../vampir.md).

## SDK settings и game override, 19 октября

Подтверждены 9 полей NMSDKSettings и начальные значения (4 native replays).
Найдена игровая InitSetting: compiled globals market nmp/game thered/client ID,
13 native сценариев сравнения environment → production при real без учёта ASCII
регистра, иначе Dev. Общий select_game_sdk_zone требует явного environment.
[Источники, SHA и границы](HEADLESS-SDK-SETTINGS.md). Активный environment и его загрузка пока неизвестны.

## Индексы обновлённых ресурсов, 19 октября

Построены свежие SHA-bound индексы всех 35 изменённых/новых архивов:
127 375 записей, ограниченный разбор без каталога PAK. Из pakchunk1 заново
извлечены 1565 CSV: 1267 точных совпадений со старым содержимым, 298 без
точного совпадения. Старые данные сохранены. [Результат, SHA и границы](CLIENT-RELEASE-INDEX.md).
U02 частичен; производные графы/карты ещё не обновлены, совместимость не доказана.

## Аудит обновления клиента, 19 октября

Перед повторным извлечением запускать [audit-client-release.py](audit-client-release.py).
[Результат проверки и ограничения](CLIENT-RELEASE-AUDIT.md): 34 изменённых
архива и один новый, EXE прежний. Старые индексы этих архивов не применять.
Прежний scan-resources.py заменяет baseline/cache: для обновлённого клиента
сохранять отдельный снимок и следовать порядку U02 из отчёта.

## Быстрый поиск и границы разбора

[RESOURCE-INDEX.md](RESOURCE-INDEX.md) — основной указатель по картам, таблицам,
квестам, объектам интерфейса и происхождению данных. Его копия хранится в корне
библиотеки на F:.

`assemble-nocturne.py` собирает плитки и записывает оценку швов и источники.
`inspect-ui.py` извлекает имена и диапазоны экспортов WidgetBlueprint;
координаты unversioned properties пока не декодирует.
`extract-tables.py` сохраняет открытые CSV с UTF-8 BOM из ProjectRED-Windows
(записи до 16 MiB), заголовки, количество строк и SHA256. Это ограниченная
проверка одного архива, не полный поиск всех форматов таблиц во всех PAK.
`build-gallery.py` создаёт локальный индекс картинок.

Текущее извлечение CSV: ProjectRED — 125 таблиц, pakchunk1 — 1565 таблиц,
ошибок декодирования 0. Индексы — table-study/index.json и
index-pakchunk1-Windows.json. Реальные строки квестов и обучения найдены;
зависимости описаны в [QUEST-DEPENDENCIES.md](QUEST-DEPENDENCIES.md).
Текущая стадия персонажа и автоматическое выполнение всего графа не реализованы.

`build-reward-links.py` также соединяет ContentsLock (69) и
ContentsLockCondition (70) и записывает contents-locks.json / early-unlock-chain.json.
См. [CONTENTS-LOCKS.md](CONTENTS-LOCKS.md): 269 блокировок, 330 условий,
109 ссылок квестов; числовые сравнения и AND/OR не предполагаются автоматически.

`build-tutorial-bindings.py` обновляет vision.json и tutorial-reference.json:
связывает только 18 явно проверенных экранов с исходными шагами. Проверяет хеши
CSV и точные UI-ключи. Не генерирует клики для остальных шагов, покупок или разбора.
Исполнение требует свежих совпадений шаблонов. minimum_delay_sec берётся из
следующих строк TaskType=4; трактовка как ожидания отмечена отдельно от чисел.
Защитная задержка 2 с сохраняется, если значение меньше. Цикл телефона может
длиться дольше паузы; точность субсекундных интервалов не гарантируется.

Нативные значения типов и полный путь магазинных задач:
[NATIVE-SEMANTICS.md](NATIVE-SEMANTICS.md).

Полный каталог найденного UI и попапов: [UI-CATALOG.md](UI-CATALOG.md).
Для воспроизведения всего каталога использовать `inspect-ui.py --tutorial-controls
--all-widgets`, затем decode-canvas-slots, decode-panel-slots, build-ui-topology,
build-ui-catalog. Для привязок сообщений — build-window-bindings.py.
Перед build-ui-catalog также выполнить extract-ui-properties.py и
decode-size-boxes.py, чтобы связать собственные размеры контейнеров, а не только слоты.
Затем decode-scale-boxes.py добавляет режимы масштабирования и наследуемые
свойства ScaleBox. Общий декодер — decode-widget-properties.py; схема подтверждена
массивами Widget/WidgetTransform в EXE, источник и индексы сохранены в библиотеке.
Для магазинного этапа — build-shop-templates.py (нужны сохранённые кадры),
build-shop-binding.py. После них повторить build-window-bindings.py.

Сначала извлекать enum из текущего
EXE, затем строить quest/reward/shop отчёты: генераторы сверяют SHA256 EXE.
Панельные слоты и порядок дочерних элементов описаны в
[REWARDS-AND-LAYOUT.md](REWARDS-AND-LAYOUT.md). Абсолютная геометрия не доказана.

Пресеты UI Scale и полная цепочка настройки: [UI-SCALE.md](UI-SCALE.md).
build-ui-scale-reference.py соединяет 25 коэффициентов, Option137, подписи и
вкладки, проверяя хеши. find-ui-scale-config.py сохраняет ограниченный поиск
настроек DPI в пяти стартовых архивах; неизвестное активное значение не подставляется.
verify-ui-links.py повторно проверяет native дескрипторы, контейнеры и строки
настройки масштаба по исходным CSV.

`replay-shop.py` проверяет настоящий bot.py на сохранённых кадрах и синтетических
отрицательных изменениях, включая смену масштаба и перезапуск с reserved-журналом.
См. [SHOP-REPLAY.md](SHOP-REPLAY.md): 32 случая, параметры и хеши; ни одного
обращения к телефону. Перед ним выполнить генераторы shop-templates/shop-binding
и window-bindings. Резервные текстовые образцы имеют собственный reference_size.


Вход по макетам: [ENTRY-FLOW.md](ENTRY-FLOW.md). После decode-deferred-panels.py
выполнить build-entry-reference.py: ссылки UserWidget подтверждаются по байтам.
Нативные ветви входа: [NATIVE-ENTRY.md](NATIVE-ENTRY.md). Требуется закреплённый
Capstone из requirements-native.txt в игнорируемом .tools/vampir-analysis;
build-native-entry-code.py читает EXE статически, учитывает chained unwind и
проверяет инструкции. Runtime-переходы и Android-соответствие ещё не доказаны.
Для изолированной проверки математики лифтов там же закреплён Unicorn2.1.4
с SHA Windows x64 wheel. build-lift-rotation-evidence.py эмулирует только
разрешённые диапазоны math-кода с константами EXE; игру не запускает.
Установка: `python -m pip install --no-deps --target phone-exit/.tools/vampir-analysis -r phone-exit/bots/resource-tools/vampir/requirements-native.txt`.
Результаты/ограничения и порядок построения карты — [MAP-ATLAS.md](MAP-ATLAS.md).

Привязки кнопок к полям и сравнению в native: build-entry-button-links.py,
[ENTRY-BUTTONS.md](ENTRY-BUTTONS.md). Генератор требует entry-reference и entry-code
текущей версии; читает только EXE, не обращается к телефону.

Нативные ссылки на окна: [NATIVE-UI-LINKS.md](NATIVE-UI-LINKS.md).
build-native-ui-links.py строит индекс; query-native-ui.py принимает точное имя
WBP или путь и проверяет хеши перед выдачей. Неподтверждённые кандидаты и ошибки
линейного разбора сохранены отдельно, по ним клики не строятся.

Получение/показ входных окон: build-entry-window-code.py и
[ENTRY-WINDOWS.md](ENTRY-WINDOWS.md). Зависит от native-ui-links; прямые E8
проверяются по декодированным границам, непрямые/хвостовые пути не покрыты.

UI-менеджер и побочные эффекты проверки окна: build-ui-manager-code.py,
[UI-MANAGER.md](UI-MANAGER.md). Зависит от entry-window-code.json;
не считать 0x144a1cbf0 чистым IsVisible/Contains.

Обычный переход: build-ui-transition-code.py и [UI-TRANSITION.md](UI-TRANSITION.md).
Отчёт связывает настройку/copy callback с FNnEasingVar::Start и завершением,
сохраняет диагностические отказы и отдельно кандидаты ImageFader.

Точная Windows-связь FaderUI с native: build-fader-class-link.py,
[FADER-CLASS.md](FADER-CLASS.md). SuperIndex/import-chain читается из uasset,
затем соединяется с регистрацией NkFaderUI и vtable.

Прямые callers остановки easing: build-easing-stop-links.py, отчёт
code-clues/easing-stop-links.json. Очистку callback не считать выполнением;
полная reset→stop-связь пока не доказана.

Карта native ConditionType вне reflected enum: build-lock-condition-types.py,
[CONDITION-TYPES.md](CONDITION-TYPES.md), quest-graph/condition-types.json.
Подтверждённые имена не заменяют evaluator/состояние персонажа.

build-lock-loader-links.py: проверка нативного загрузчика условий, шага записей,
полей и пустых post-load слотов; code-clues/lock-loader-links.json.
Доказательства и ограничения — в CONDITION-TYPES.md, раздел загрузчика.
Дополнительно проверяются пять исходных заголовков колонок и построение индекса
GroupId → массив указателей на объекты условий; AND/OR не интерпретируется.

Клиентский dispatch и обычный AND-путь с исключениями:
[CONDITION-PREDICATE.md](CONDITION-PREDICATE.md), build-lock-predicate-code.py,
code-clues/lock-predicate-code.json. Таблица переходов хранится отдельно от кода;
gate/состояния ещё не позволяют вычислять доступность персонажа.

Поля ContentsLock и пять прямых вызовов предиката:
[CONTENTS-LOCK-FIELDS.md](CONTENTS-LOCK-FIELDS.md), build-contents-lock-fields.py,
code-clues/contents-lock-fields.json. SaveType=2 во всех 269 исходных строках;
символическое имя 2 пока неизвестно. Соединение со справочником — referenceRevision4,
clientPredicateReference; вычисление для персонажа не включено.

Обновление контекста и источники кешированных уровней:
[CONDITION-STATE.md](CONDITION-STATE.md), build-lock-state-code.py,
code-clues/lock-state-code.json. Два флага готовности, замена/добавление ID,
refresh перед пересчётом. Происхождение входного массива и gate пока неизвестно.

Следующий результат V32/V33:
[UNLOCK-RESULTS.md](UNLOCK-RESULTS.md), build-lock-packet-links.py,
code-clues/lock-packet-links.json — точные OnHandler чтения списка и результата
запроса, два tail-jump в update; это приём результата, не отправка запросов.
[CONDITION-GATE.md](CONDITION-GATE.md), build-lock-gate-code.py,
code-clues/lock-gate-code.json — reset0..10, getter/setter готовности и EnterArea.
Готовность не равна выполнению условия; события setter/dispatcher ещё искать.


Регистрация двух unlock-handler и прямые события готовности:
[UNLOCK-REGISTRATION.md](UNLOCK-REGISTRATION.md), build-lock-registration-events.py,
code-clues/lock-registration-events.json. Две packet/handler пары в
PacketDispatcher::_AddPacketHandler, таблицы методов/ID и 7 setter-вызовов;
CharacterSelect/Engraving связаны точными диагностическими именами. Принимающая
диспетчеризация и другие события не объявляются завершёнными.

Guard перед обновлением разрешений и сообщения:
[PACKET-RESULT-GUARD.md](PACKET-RESULT-GUARD.md), build-packet-result-guard.py,
code-clues/packet-result-guard.json.25 опорных инструкций, 227 selector-записей,
5 точных ключей EXE→CSV405; исключение 4503 не заменено правилом result==0.
Общий UI-путь содержит ограничения и пока не связан с конкретным WBP.


Общий путь ошибки → системный виджет:
[SYSTEM-MESSAGE-UI.md](SYSTEM-MESSAGE-UI.md), build-system-message-link.py,
code-clues/system-message-link.json. WBP_SystemMessageUI → NkSystemMessageUI →
TextMessage+0xa00 и вложенный ImageBackGround; 4 cooked-варианта с хешами.
Отдельный systemMessageReference в ui-window-reference.json не доказывает
привязку KICKOUT_FOR_INSPECT и не включает клики/абсолютную геометрию.


Кандидат именованного содержимого системного сообщения:
[MESSAGE-NAMED-SLOT.md](MESSAGE-NAMED-SLOT.md), decode-message-named-slot.py,
ui-geometry/system-message-named-slot.json. Тип NamedSlotBinding/Name/Content
подтверждён, но unversioned-индекс 59 ещё не связан с полной схемой наследования.
Два префикса сохранены с opaque-хвостом; ребро топологии и координаты не включены.


## Атлас карты (17 октября 2026)

[MAP-ATLAS.md](MAP-ATLAS.md): build-map-atlas.py собирает полные таблицы географии,
связи, исходные точки, NPC/объекты, порталы и цели квестов в maps/atlas/ библиотеки.
Генератор проверяет SHA CSV/PNG/EXE/Nocturne. query-map-atlas.py даёт запросы
--world/--spot/--quest с проверкой производного JSON. map-atlas.html — исходник
локального просмотрщика (копируется генератором). Изображение и координатная
схема разделены до подтверждения преобразования. Маршруты/Android ещё не готовы.


Скрины на большой карте: register-map-screenshot.py (несколько путей кадров),
сохранённое совмещение/накопление наблюдений и ограничения — MAP-ATLAS.md.
Добыча и изображения: [NPC-LOOT.md](NPC-LOOT.md), export-float-icons.py →
build-npc-loot.py → query-npc-loot.py. Проценты выпадения не подтверждены;
исходные rates/условия/источники сохранены. Отдельные справочники вне Git/APK.


build-loot-rate-evidence.py проверяет именованные Load AreaReward/NpcReward/Reward,
привязку rate к 32-битному полю и PE-importatoi. Запускать до build-npc-loot.py,
который включает компактное доказательство и item-origins.json (Item→NPC→цепочки).
Native/CSV версии сверяются. Проценты всё ещё не вычисляются. NPC-LOOT.md.


build-loot-record-links.py продолжает nativeLoad до создания объектов/vtable
NpcReward/Reward: проверяет два пустых ratecallback и 24 опорных инструкции.
После него build-npc-loot.py включает rate-callbacks.json и npc-locations.json.
query-npc-loot.py поддерживает --item/--npc совместно с--world. NPC-LOOT.md.

Nocturne Map10/11: `build-map-projection.py` создаёт проверку XY→атлас;
затем `build-map-atlas.py`. Источники, 7 областей исторического кадра,
фильтр предметов и 33 теста: [MAP-ATLAS.md](MAP-ATLAS.md).

Единая большая Nocturne: `build-world-map.py` / `world-map.html` /
`world-map.js` / `world-map-model.js`, экспорт `render-world-map.py`.
Главный index открывает 36 контекстов вместе; старый просмотрщик —world.html.
Порядок и 51 тест: [MAP-ATLAS.md](MAP-ATLAS.md).
