# Vampir — главный указатель разработки

Цель: самостоятельный сетевой бот без процесса игры, затем управление через
лёгкую 2D-карту, игровые меню, сценарии фарма и переносимый Android runtime.
Исследовательские инструменты и большие данные остаются отдельно от runtime.

## Что работает и где остановились

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
Следующий шаг — сравнить официальный Login с ботом. Отказ бота 16 пока не устранён.

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
SHA EXE: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
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
