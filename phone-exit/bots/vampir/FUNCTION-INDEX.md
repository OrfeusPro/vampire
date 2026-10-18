# Vampir — общий указатель найденных функций и связей

Обновлено 18 октября 2026. Начинать с [README.md](README.md).
Общий для экранного бота, [самостоятельного сетевого бота](../vampir-headless/README.md)
и исследования карты. Это навигационный указатель, не полный список функций EXE.
Подробные доказательства и инструменты остаются у соответствующего направления.

## Как пользоваться и обновлять

Перед новым исследованием искать здесь и в подробном отчёте. Добавлять найденные
функции сюда, а шаги и историю — в TASKS/WORKLOG соответствующего направления.
Запись должна содержать назначение, адрес/тип адреса, источник и SHA, уровень
подтверждения, ограничения, путь отчёта и способ воспроизведения. Большие таблицы
и дизассемблирование здесь не дублировать. Не заменять старые подтверждения новой
гипотезой; при обновлении клиента хранить результаты отдельно по версии/SHA.

Уровни: **байты/строка** → **ссылка из инструкций** → **связь/vtable** →
**изолированное исполнение** → **живая проверка**. Верхний уровень не следует
автоматически из нижнего. В частности, имя пакета не доказывает ID, wire-format
или пригодность его отправки серверу.

## Источник текущих адресов

Windows `ProjectRED-Win64-Shipping.exe`, собранный клиент, не исходный C++ проект.
Путь: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Адреса ниже — VA с image base `0x140000000`, не файловые смещения.
Версия Windows не объявлена равной Android 1.0.14. При другом SHA адреса
не применять без повторной проверки. Полные provenance — в указанных JSON.

## Вход, обмен и состояние персонажа

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Повторение: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-network-index.py`.
27 точных строк, 31 проверенная LEA-ссылка, 27 unwind roots, 32 фрагмента,
1020 инструкций; missing/rejected=0. Для строк подтверждены bytes/offset/SHA,
для ссылок — границы инструкций и chained unwind root. Root со строкой не
объявляется реализацией одноимённого метода. Getter/serializer/ID ещё связать.

| Найденная строка / назначение | Root VA со ссылкой | Подтверждение / следующий пробел |
|---|---|---|
| UTitleUI::OnSuccessNetmarbleSDKAuth() | 0x14641d560 | Строка/ссылки; не восстановлен обмен почты/пароля на сессию |
| UTitleUI::ProcessNetmarbleSDK() | 0x14641ee20 | Строка/ссылки; вызовы SDK и токены ещё исследовать |
| PacketDispatcher::Dispatch | 0x14679f510 | Строка/ссылки; весь путь receive→decode→dispatch не доказан |
| PacketDispatcher::GetPacketHandler | 0x14679f7b0 | Строка/ссылка; семантику lookup ещё проверить |
| PacketDispatcher::_AddPacketHandler | 0x1467a7250 | Регистрация двух пар дополнительно подтверждена, см. ниже |
| PktLobbyLogin / Result | 0x145754ff0 / 0x145755020 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktLogin / Result | 0x1456e3410 / 0x1456e3440 | Строки/ссылки; формат и последовательность входа неизвестны |
| PktCharacterListRead / Result | 0x1456e2f90 / 0x1456e2fc0 | Строки/ссылки; wire-schema неизвестна |
| PktCharacterSelect / Result | 0x1456e30e0 / 0x1456e3140 | Строки/ссылки; отдельно найден result-handler |
| PktCharacterPosition | 0x1456cd420 | Строка/ссылка; поля позиции ещё не восстановлены |
| PktCharacterMove / Result / Notify | 0x1456cd2d0 / 0x1456cd390 / 0x1456cd360 | Строки/ссылки; отправка движения не реализована |
| PktWorldInfo / UpdateNotify | 0x14581bc60 / 0x14584bef0 | Строки/ссылки; live zone/world ещё не получены |
| PktPing / Result | 0x1456e36b0 / 0x1456e36e0 | Строки/ссылки; частота/формат игрового heartbeat неизвестны |
| PktSkillCastingStart / Result | 0x14583e7a0 / 0x14583e800 | Строки/ссылки; боевые команды не реализованы |
| PktSkillStart / Result / Notify | 0x14583eb00 / 0x14583eb90 / 0x14583eb60 | Строки/ссылки; серверный боевой цикл неизвестен |
| PktActorCombatStateChangeNotify | 0x1456b5940 | Строка/ссылка; поля и применение ещё исследовать |

## Более глубокие подтверждения

| Функция/структура | Адреса VA | Подтверждение и подробный источник |
|---|---|---|
| ContentsUnlockListReadResult / RequestResult | handlers 0x146763cd0 / 0x146763da0, registration 0x1467a7250 | Пары handler/packet, vtable и getters ID1007/1009; не сетевой API. [UNLOCK-REGISTRATION.md](../resource-tools/vampir/UNLOCK-REGISTRATION.md), `code-clues/lock-registration-events.json` |
| PktCharacterSelectResultHandler::OnHandler | 0x14675e9a0 (LEA имени 0x14675e9d3) | Имя и отдельные readiness-вызовы; весь state initialization не доказан. Тот же отчёт |
| Guard результата пакета | 0x1467a8e10 | Статические ветви результата/ошибок. [PACKET-RESULT-GUARD.md](../resource-tools/vampir/PACKET-RESULT-GUARD.md) |
| PktStat reader / writer | 0x1457f0540 / 0x1457f4360 | key32/raw64 и native исполнения с synthetic primitive IO, wire неизвестен. [ATTRIBUTES.md](../resource-tools/vampir/ATTRIBUTES.md), `code-clues/stat-packet-evidence.json` |
| PktStatCategoryData reader / writer | 0x1457f0590 / 0x145784940 | category8/raw64, read clamp≤29; реальные категории не установлены. Тот же отчёт |
| Форматирование значения характеристики | 0x145dda3a0 | Native ветви scaling/display; не формулы урона. ATTRIBUTES.md, `code-clues/stat-format-routes.json` |
| Проекция координат на navmesh | 0x1452451b0 | Изолированное исполнение с explicit inputs; не live position. [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md) |
| Polygon query | 0x1452457b0 | Native offline query; active mesh/permissions отдельно. MAP-ATLAS.md |
| Straight path/funnel | 0x145248b20 | Native offline corridors; не подтверждение движения персонажа. MAP-ATLAS.md |
| Базовая инициализация nav-фильтра | 0x1452b7120 | Native explicit SupportedArea/CDO scenarios; live selection отдельно. MAP-ATLAS.md |

## Другие общие индексы

- [RESOURCE-INDEX.md](../resource-tools/vampir/RESOURCE-INDEX.md): CSV, архивы, карты, изображения.
- [NATIVE-UI-LINKS.md](../resource-tools/vampir/NATIVE-UI-LINKS.md): код→окна; `query-native-ui.py` ищет с проверкой источника.
- [UI-CATALOG.md](../resource-tools/vampir/UI-CATALOG.md): окна, контролы, контейнеры и геометрия.
- [QUEST-DEPENDENCIES.md](../resource-tools/vampir/QUEST-DEPENDENCIES.md): квест→задача→действие/обучение.
- [MAP-ATLAS.md](../resource-tools/vampir/MAP-ATLAS.md): полная история карты и специализированные native отчёты.

## Автобой — пока отдельные зацепки

В `native-enums.json`: EAICombatMode Auto=0/Target=1;
ESupportModeBehaviorAutoCombatType CombatStatsRecord=0/LocationMemory=1/Area=2.
В CSV: Skill.SyncAutoCombat (pakchunk1 entry1505), OnEntryAutoCombat/
AutoCombatLeaveWorld/movePacketIntervalTime (entry1574). Источники и SHA CSV —
`table-study/index-pakchunk1-Windows.json`. Это данные/enum, не найденные
реализации функций и не доказательство серверного автономного фарма.
