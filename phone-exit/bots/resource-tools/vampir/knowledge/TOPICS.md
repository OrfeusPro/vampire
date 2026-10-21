# Vampir — сводка накопленных знаний

Состояние на 21 октября 2026. Это сводка текущих выводов; подробные источники
и границы — в тематических страницах. Старые этапы сохранены отдельно как история.

| Тема | Подтверждено | Ещё не подтверждено |
| --- | --- | --- |
| [Авторизация](topics/auth.md) | NID / SDK, отдельные device keys, свежий GMC2 и metadata; JP Game Login 0 | Остальные common data и отдельная причинная роль полей; полнота launcher context |
| [Сеть](topics/network.md) | Bounded codecs / connection, живые лобби / Game Version / Game Login 0 | Полноценная длительная сессия и восстановление |
| [Персонажи](topics/characters.md) | Local/native codecs / flow; бот получил живой список одной записи | Живой выбор бота, совместимость полного ID 110 и семантическая позиция |
| [Карта](topics/maps.md) | Атлас, ресурсы, геометрия, offline native nav scenarios | Живая позиция и подтверждённое перемещение через сеть |
| [Интерфейс](topics/interface.md) | Виджеты, контролы, layout и scale evidence | Полностью работающие игровые меню вокруг 2D-карты |
| [Сценарии](topics/scenarios.md) | Квестовые связи и bounded проверки экранного бота | Автономный сетевой фарм и контроль живого состояния |
| [Игровые данные](topics/game-data.md) | Каталоги NPC / предметов / навыков и источники | Полная runtime-семантика эффектов, урона и всех условий |
| [Обновления](topics/updates.md) | Аудит, snapshots, SHA, ClientVersion, свежие configs | Единый проверенный pipeline обновления и Android parity |
| [Инструменты](topics/tools.md) | Ghidra export, CUE4Parse headers, собранная DLL Dumper-7 | SDK / mappings живой игры; доступ Dumper-7 остановлен до загрузки |

Приоритет — [вход и персонажи](../../../vampir-headless/TASKS.md).
Следующий эксперимент выбирать по [questions.json](questions.json) и decision_rule.
Готовая карта и её сетка сохраняются для дальнейшего live слоя; повторно
создавать их с нуля не нужно. Исследовательские инструменты в runtime не включать.

[Правила](README.md) · [функции](../../../vampir/FUNCTION-INDEX.md) ·
[карта переносов](document-locations.json).
