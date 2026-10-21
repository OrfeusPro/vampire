# Vampir — главный указатель разработки

Цель: самостоятельный сетевой бот без процесса игры, затем управление через
лёгкую 2D-карту, игровые меню, сценарии фарма и переносимый Android runtime.
Исследовательские инструменты и большие данные остаются отдельно от runtime.
Обновления должны обрабатываться автоматически: обнаружение изменений,
переизвлечение и сверка связей; неоднозначные случаи — в очередь ручной доработки.
[Порядок и критерии](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md#автоматизация-следующих-обновлений).

## Что работает и где остановились

**Текущий результат: вход и выбор персонажа прошли.** На JP свежий GMC2 и
metadata 312 байт получили Game Login 0, CharacterList 0 / одну запись и
CharacterSelectResult ID 110 code 0. Тело 4724 байта разобрано полностью;
ошибок нет. Позиция и готовность мира ещё не подтверждены, маршрут закрыт.
[Живой выбор и границы](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#повторная-живая-проверка-выбор-принят).

Следом — consumer позиции и необходимая цепочка инициализации мира. Не повторять
готовый выбор или native readers без нового действия / изменившегося источника.

Полный эталон 4c713eb5 уже дал продолжение: после ID 110 сервер присылает
ID 202 без исходящего ID 201, затем клиент отправляет ID 203 (8 байт), получает
ID 204 и отправляет пустой ID 205. Current apply / receive / start request
прослежены статически. Следом проверить привязки reader 202 и writer 203,
затем продолжить ту же сессию из свежих ответов. Позиция остаётся неизвестной.
[Цепочка из эталона и текущего кода](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#продолжение-по-полному-эталону-4c713eb5).
ID 203 теперь имеет переносимый body codec, сверенный с целыми native constructor /
getters / writer текущего SHA: 20 случаев, три теста. Reader ID 202 и constructor
выгружены; осталось разобрать два вложенных блока, затем подключить продолжение
приёма. Отправка ID 203 и новая живая попытка пока не включены.
[Проверки и следующий точный набор](../resource-tools/vampir/knowledge/evidence/characters/HEADLESS-LIVE-CHARACTER-SELECTION.md#id-203-native-writer-и-переносимый-body-codec).



Ниже сохранён путь предыдущих проверок, включая прежние отказы Login 16;
они не отменяют текущий успешный результат выше.

21 октября после докачки примерно 1,1 ГБ подтверждены новый EXE SHA
98802d550890…, AppVersion 1.13.14 и ClientVersion 261105. Отдельные профили
`recovered-release` для CDN и SDK / NID подключены с проверкой источника;
смешивание старого SDK snapshot с новым профилем отклоняется до авторизации.
Новые settings / GMC2 defaults, PC label, игровой override, base selector,
URL и заголовки проверены native-сценариями. Инструменты остаются вне runtime.

В Game Login была найдена прежняя compiled-строка Version / Login. Новая строка
подтверждена pointer / literal нового EXE, native slice и успешным HK-захватом;
профиль теперь передаёт её в оба пакета и отклоняет смешивание версий.
Новый native mapper подтвердил: код 1 — InvalidPacketVersion.
После исправления через JP и HK SDK / лобби / Game Version приняты, Game Login
дал **16 / InvalidState** в обоих случаях. Список при отказе не отправлялся.
Реальный вход бота, выбор и позиция ещё не получены; временные маршруты закрыты.
[Доказательства, исправление и live результаты](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-WIRE-TAG.md).

Пользователь заменил телефоны; на последней проверке доступны samsung SM-A205F
и Redmi 2201116SI с выходом JP, Redmi M2103K19Y — HK, APK 0.9.6.
Следом сверить оставшиеся поля / источники metadata и ранний обмен с успешным
клиентом; не повторять авторизацию без конкретного подтверждённого изменения.
Обновления данных и остальная цепочка до позиции остаются в общем плане.
Новая официальная запись 2d150317… сделана через HK (уточнение пользователя).
Разобраны 190 игровых пакетов: Login code 0, CharacterList code 0 / один персонаж,
выбор ID 109 → ответ ID 110 и дальнейшая инициализация. Metadata клиента 792 байта
против 219 у бота; ClientVersion 261105, server 256 и raw language byte 1 совпали.
Переход бота на HK при том же subset тоже дал 16; причина не выделена. Позиция
не извлечена. Ключи в Login / metadata трёх успешных захватов затем сравнены
с текущим Windows-хранилищем и привязкой бота: проверенные значения совпали.
Предыдущая запись 8e13f35e… была пустой: ошибка лаунчера вне игрового фильтра.
Для следующей проверки Phone Exit получил явный режим «Весь TCP через телефон»
без списка адресов: до 3 минут, 32 МиБ и 1024 соединения, с автоостановкой.
Охват приложений задаётся режимом VPN; HTTPS остаётся зашифрованным, UDP не
записывается. [Инструкция расширенной записи](../../pc/DIAGNOSTICS.md#как-записывать).
[Разбор и границы сравнения](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#успешный-hk-захват-2d150317-после-обновления).
Новая запись 3f8ab7fe… снова содержит успешные Login / список / выбор:
181 игровой пакет, Login code 0, список code 0 / одна запись, ответ ID 110.
В записи запуска 21fc5087… нет игровых соединений: захват достиг прежних
128 потоков за 33 секунды и выключился. Это ограничение диагностики, не
установленная причина ошибки игры; предел увеличен до 1024 потоков.
[Результаты обеих записей](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#расширенные-записи-3f8ab7fe-и-21fc5087-21-октября).

Пользователь закрепил 4c713eb5… как основной эталон полного успешного входа.
Полная запись проверена: 125 секунд / 97 потоков, лимиты не достигнуты.
Есть список серверов, вход в лобби и одно успешное игровое соединение:
189 пакетов, Login / список code 0, выбор ID 109 → 110. Повторный Game Login
после разрыва мира не наблюдался. Во всех трёх успешных записях до Login идут
IDs 30413 → Version → Ping; бот начинает с Version. Следом доказать источник
и роль предварительного кадра / Ping на новом EXE, затем решить, что менять.
[Полная последовательность и сверка ключей](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#полный-запуск-4c713eb5-и-сверка-идентификаторов).
По новому EXE выгружены constructor / Version callback и source-bound targets
уведомления подключения. Прямой поиск scalar 30413 и wire-константы результата
не дал; роль предварительного кадра ещё не установлена. Эти же literal searches
без изменившихся входов повторять не требуется.
[Проверенные адреса, выгрузки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-BOOTSTRAP.md).
Продолжение: actual send новой версии выгружен; найден producer Ping.
36 native сценариев подтвердили поля «часы / разница», порог >5000, readiness
и recovery branch. Эталонные пять Ping согласуются с producer; часы первого
примерно на 9 часов впереди времени capture. Затем источник часов проверен:
GetSystemTime UTC → календарные ticks → Unix epoch + signed offset в минутах.
24 native clock-сценария и три теста прошли; в обоих lobby ID 2 эталона offset
равен 540. Затем текущая registration связана с ID 2 / PktLobbyVersionResult:
actual reader → handler → clock setter прошли 18 сценариев и 24 длины входа,
три регрессионных теста. Свежий lobby clock context подключён в runner новой
сборки: Version → один ранний Ping → Login. Формула, signed offset, порядок
кадров и отказы проверены локально. Периодический Ping ещё не подключён;
кадр 30413 не найден. Живая JP-проверка: SDK / лобби / Game Version приняты,
получен ID 17, Login снова 16. По запросу пользователя отдельная диагностика
отправила ID 101 после отказа на том же соединении; за 10 секунд ID 102 не пришёл.
Обе проверки завершены, временные маршруты закрыты. Причина 16 остаётся открытой.
[Clock source, native проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-RELEASE-CLOCK.md).
Дополнительная сверка эталона подтвердила session-field handoff лобби → игра:
две строки ответа, SDK token / NID / device / server согласованы с builder.
Полная metadata одинакова в обоих официальных Login — 792 байта. Есть отличие
соединений: официальный ServerList и lobby Login идут в разных TCP-потоках,
у бота — на одном. Причина 16 этим не установлена; следующие источники для
проверки — metadata и lobby lifecycle.
[Сверка полей и границы](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md#дополнительная-сверка-перехода-лобби--игра).
Найдена текущая ветвь заполнения common data: FLogImpl::Start → 0x144555470,
которая записывает строки в сам объект. Выделены source helpers и передача
MakeSessionID в отдельный setter. Восемь native случаев и два теста подтвердили:
setter меняет I_NMSessionID, который collector Login не выбирает. I_TID имеет
отдельный источник settings+0x608 → common data. Формат проверен четырьмя
native случаями; current Save сохраняет это поле. Runtime новой сборки теперь
добавляет собственный постоянный TID бота через CoCreateGuid и отдельное SQLite
состояние, без изменения SaveGame игры. 14 проверок прошли. Живая JP-попытка
подтвердила metadata 262 байта, SDK / лобби / Game Version приняты, но Login
снова 16. Маршрут закрыт. Остальные metadata и lobby lifecycle ещё проверяются.
Следом выгружены шесть current update callees. Целые UpdateGmc2 / UpdateSDKSetting
прошли 31 native сценарий и три теста: источники IP / страны / города / SDK полей,
отсутствие сервиса, lazy initialization, пустые / равные / изменившиеся строки.
Service и FString backend — fixtures. Условные player / NID ветви ещё
открыты; runtime metadata пока не расширена. Источник страны установлен в продолжении ниже.
[Источники, адреса и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-COMMON-DATA.md).
Затем статически прослежен GMC2 callback → response consumer → geo helper:
key clientIp передаётся string helper, результат переносится в settings+0x38,
откуда UpdateGmc2 получает I_ConnectIP / I_NMMobileIP. GeoLocation helper
0x144552430 оказался SetCountryCode: пишет settings+0x3f0 → I_CountryCD,
а A1 сохраняет прежнюю страну только при непустом старом поле. Целый setter
с notify=0 прошёл 14 native случаев и три теста; FString backend — fixtures.
Generic JSON helpers и полный callback native не исполнены, runtime пока не расширен.
[Цепочка, адреса и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md).

По коду новой сборки прослежены поиск JSON-поля, получение вложенного объекта
и преобразование значения в FString. Есть ветви для чисел и логических значений;
приём только объектов и строк в боте будет отдельной локальной политикой.
Следом подключить свежие clientIp / geoLocation с проверками источника, маршрута,
возраста и правила A1. Полный JSON parser и callback этим не проверены.
[Контракты и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md#json-helpers-границы-извлечения-полей).
Теперь runtime новой сборки получает GMC2 перед входом через выбранный маршрут
и использует один ответ для SDK и metadata. Добавлены I_ConnectIP из clientIp
и I_CountryCD из geoLocation, с правилом A1 и пределом возраста 300 секунд.
34 локальные проверки прошли. Следом — живая проверка; Login 16 ещё не устранён.
[Свежий контекст и ограничения](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md#свежий-gmc2-context-в-runtime).


Ниже — состояние предыдущего этапа до дополнительной докачки.
21 октября пользователь подтвердил завершение обновления; сервер ещё на технических
работах. Офлайн-аудит выявил новый EXE и основной ProjectRED-Windows.pak.
От снимка 19 октября 35 архивов совпали по полному SHA, 127 — только по выборочной
проверке. Свежий индекс основного PAK построен; 3210 из 3325 сохранённых файлов
нашлись с прежним содержимым. Patch manifest пока старый; совместимость входа
и прежних адресов функций не установлена. [Результаты и следующий шаг](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md).
Ghidra-сравнение двух EXE дало кандидатов для 239 из 424 исследованных функций;
девять приоритетных пар выгружены с инструкциями и псевдокодом. Структура Login
похожа, но внешние зависимости и совместимость новой сборки ещё проверяются.
На новом EXE reader целого body списка проверен в базовом профиле: 12 полных
ответов совпали с переносимым decoder, 238 коротких префиксов отклонены.
Native archive / UTF-8 / record readers и callbacks выполняются вместе;
контейнерная память остаётся fixture. Непустые extensions / optional map проверены
ещё 31 полным body и 489 префиксами, включая коллизии и замену повторного ключа.
Для списка подтверждены constructor / vtable / ID 102 / reader и ключ регистрации.
Новый handler и его gate / predicate исполнены вместе с reader в 50 сценариях:
проверены применение списка, сохранение прежних записей при отказе и начальный
индекс персонажа. Ещё 25 сценариев выполняют непрерывный путь от списка через
state setter и indexed caller до constructor / writer запроса выбора ID 109.
20 байт тела совпали с переносимым codec; handoff, выходной archive и Engine / UI
остаются fixtures. Новая транспортная цепочка и реальная сессия ещё не подтверждены.

На 20 октября 2026 бот проходит NID / SDK-вход, получает список серверов и
успешный ответ выбранного лобби. Игровой Version принят; Game Login на ID 256
ранее возвращал 16 / InvalidState. Новый launcher-вход принят SDK / лобби,
но Game Login через два JP-телефона и HK вернул 58 / BlockedIp.
После следующей замены телефонов новый JP дал 16 / InvalidState при том же
launcher flow; со вторым новым JP прямой транспорт не установился.
Список персонажей из реальной сессии не получен.
21 октября официальный клиент через выбранный JP вошёл в мир: пользователь
создал Okly на Franz 2. После закрытия игры бот на том же телефоне снова получил
16; три сохранённых ключа устройства совпали с текущими Windows-значениями.
Совпадение остальных полей авторизации не доказано.

Для сравнительной записи добавлен [диагностический режим Phone Exit](../../pc/DIAGNOSTICS.md).
21 октября получена первая реальная запись официального клиента: игровой Login
принят с кодом 0, список содержит одного персонажа, видны запрос выбора и ответ
ID 110. Проверены целостность, framing и исходящие CRC; позиция ещё не извлечена.
[Подробности и воспроизведение](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LIVE-TCP-CAPTURE.md).
Сравнение выявило два отличия: metadata +0xd8 содержит 791 байт вместо пустой
строки; byte +0x124 равен 1 вместо 7. Источники актуального контекста ещё нужно
подключить; причина отказа 16 и достаточность этих отличий не доказаны.
Байт +0x124 связан с языком: 1 / en-US, 7 / ko-KR. Добавлены явный выбор
языка и encoder metadata с DeviceKey; [проверки и реальные попытки](../resource-tools/vampir/knowledge/evidence/network/HEADLESS-LOGIN-LANGUAGE.md).
Две новые попытки с языком 1 остановились раньше Game Login: выбранное лобби
ответило 10036. Последующий native-разбор mapper лобби установил ключ IsInspect:
таблица клиента расшифровывает его как технические работы. Влияние языка на
Game Login пока не проверено.
Добавлены свежая страна SDK / NID и явная частичная metadata из шести полей.
Обе ветви проверены через тот же JP и также получили 10036 до Game Login;
полная metadata официального клиента ещё не собрана. Runtime различает
IsInspect и прежний игровой InvalidState, выводит понятные причины отказа.

У launcher-ветви подтверждены отдельный credential и два HTTP-вызова;
условие выбора проверено локально. Установлены заголовок launcherToken и
различие ответов. Выбор backend по каналу и GetLauncherToken с существующим
NID credential проверены локально. Явный runtime launcher flow проверен на
сервере до отказа Game Login. [Реальные результаты и границы](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

[Сводка по темам](../resource-tools/vampir/knowledge/TOPICS.md) отделяет рабочее,
проверенное локально, статические связи и незавершённое. Актуальные вопросы:
[questions.json](../resource-tools/vampir/knowledge/questions.json).

## Найти накопленные результаты

| Тема | Текущее знание и границы |
| --- | --- |
| Вход, SDK, устройство, metadata | [Авторизация](../resource-tools/vampir/knowledge/topics/auth.md) |
| Кадры, сокеты, лобби, игровой Login | [Сеть](../resource-tools/vampir/knowledge/topics/network.md) |
| Список, выбор, создание, вход в мир | [Персонажи](../resource-tools/vampir/knowledge/topics/characters.md) |
| Атлас, геометрия, сетка и маршруты | [Карта](../resource-tools/vampir/knowledge/topics/maps.md) |
| Окна, контролы, масштаб, будущая оболочка | [Интерфейс](../resource-tools/vampir/knowledge/topics/interface.md) |
| Квесты, обучение, покупки и фарм | [Сценарии](../resource-tools/vampir/knowledge/topics/scenarios.md) |
| NPC, предметы, навыки и каталоги | [Игровые данные](../resource-tools/vampir/knowledge/topics/game-data.md) |
| Версии, SHA, переизвлечение и регрессии | [Обновления](../resource-tools/vampir/knowledge/topics/updates.md) |
| Ghidra, CUE4Parse, Dumper-7 | [Инструменты](../resource-tools/vampir/knowledge/topics/tools.md) |

До нового исследования: [правила базы знаний](../resource-tools/vampir/knowledge/README.md),
затем поиск адреса/имени через `function-registry.py --query`.
[FUNCTION-INDEX.md](FUNCTION-INDEX.md) ведёт к реестру функций и доказательств.
Не повторять разобранную ветвь без нового входа или явно записанного unknown.
[План единого поиска](../resource-tools/vampir/knowledge/INDEX-PLAN.md): объединить
имеющиеся выгрузки по SHA клиента, затем добавить поиск / очередь недостающего
анализа. Учтён обычный выпуск обновлений по средам рано утром; новый baseline
принимается после загрузки и сверки SHA.
[Первый этап индекса](../resource-tools/vampir/knowledge/INDEX-USAGE.md) реализован:
Более 230 отчётов и 600 функций двух версий, поиск текста и прямых вызовов без запуска
Ghidra. Вопросы, доказанные роли и ресурсы пока остаются в отдельных справочниках.
Перед новым экспортом обязательно проверить этот индекс по текущему SHA:
`function` / `search --release installed`, при необходимости `callers`.
Если база отсутствует или появились новые выгрузки, сначала выполнить `build`.
[Автоматизация исследования](../resource-tools/vampir/knowledge/RESEARCH-WORKFLOW.md):
`prepare` объединяет вопрос / SHA / материалы / выбранные проверки; `collect`
выгружает недостающие явные адреса; `finish` сохраняет вывод по версии.
`check` проверяет согласованность перед коммитом; `update` объединяет полный
аудит файлов, resource adapters и очередь перепроверки связей.
Автоматического продвижения runtime profile и фонового расписания нет.

## Код и данные

- `vampir/`: существующий экранный бот Android, его настройки и templates.
  [bot.py](bot.py), [entry.py](entry.py), [quests.py](quests.py), [shop.py](shop.py).
- [vampir-headless](../vampir-headless/README.md): диагностические runners и
  самостоятельный клиент; [TASKS.md](../vampir-headless/TASKS.md) — порядок работ.
- `vampir-shared/vampir_core/`: общие bounded codecs, состояния и соединение.
- [resource-tools/vampir](../resource-tools/vampir/README.md): исследование,
  сборка каталогов и карты; инструменты не включать в приложение бота.
- `F:/PhoneExit Resources/Vampir/`: большие отчёты, extracted assets, карта,
  snapshots и exports. [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md).

Клиент исследования: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR`.
SHA установленного EXE: `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Прежние native-результаты относятся к сохранённому EXE
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`;
перенос связей на новую сборку ещё не проверен.
Это собранный код и cooked-данные клиента; исходного C++ проекта нет.
Совпадение версии Windows и Android автоматически не предполагается.

## История

[RESEARCH-HISTORY.md](RESEARCH-HISTORY.md) сохраняет прежний README целиком:
старые результаты, команды и границы. Он не является текущим состоянием.
Подробные исследования физически разнесены по `knowledge/evidence/<тема>/`;
карта старых и новых путей —
[document-locations.json](../resource-tools/vampir/knowledge/document-locations.json).
Не добавлять новые хронологические отчёты в этот README: обновлять тему,
вопрос и соответствующее доказательство.
