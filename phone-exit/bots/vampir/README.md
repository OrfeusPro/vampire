# Vampir — главный указатель разработки

Цель: самостоятельный сетевой бот без процесса игры, затем управление через
лёгкую 2D-карту, игровые меню, сценарии фарма и переносимый Android runtime.
Исследовательские инструменты и большие данные остаются отдельно от runtime.
Обновления должны обрабатываться автоматически: обнаружение изменений,
переизвлечение и сверка связей; неоднозначные случаи — в очередь ручной доработки.
[Порядок и критерии](../resource-tools/vampir/knowledge/evidence/updates/CLIENT-RELEASE-AUDIT.md#автоматизация-следующих-обновлений).

## Что работает и где остановились

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
Packet bindings, handler и реальная сессия новой сборки ещё не подтверждены.

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
