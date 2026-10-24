# Текущие задачи без доступа к серверам

Выбор пользователя 24 октября: направления **1, 5, 8, 9** из общего плана.
Авторизацию, каталог серверов, создание персонажей и вход в мир пока не запускать.
Номера сохранены, чтобы не смешивать этот выбор с техническими contract IDs.

## 1. Version / Login текущей сборки

- Готовы: packet writers, UTF-8, string writer, archive, whole Version prepare
  с явными fixtures, NM getter и его интеграция с synthetic cache.
- Новый законченный этап: selector / context store / lookup — 116 native случаев,
  готовый экспорт использован повторно без Ghidra.
- Windows helper прошёл 48 сценариев; CPU formatter / getters / trim — 72.
  [Доказательства и границы fixtures](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-SYSTEM-11316.md).
- Windows / CPU / NM теперь исполняются внутри whole Version prepare на общей
  памяти: 64 сценария полей, ownership, cleanup и send 0 / 1.
  [Интеграция и оставшиеся fixtures](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-SYSTEM-11316.md).
- Native combiners / copy / append / grow прошли 256 сценариев и 2 overflow;
  интегрированы в whole prepare ещё на 64 сценариях без готового текста fixture.
  [Сборка поля, ownership и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-COMBINERS-11316.md).
- Selector / store / lookup включены в whole prepare: 288 сценариев с холодным /
  тёплым cache, отсутствием контекста и разными таблицами. Их FName/type/value
  зависимости пока fixtures.
  [Общая цепочка и точные ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PREPARE-PLATFORM-11316.md).
- Целые Login prepare / constructor проверены в 672 сценариях с явными SDK,
  строковыми и post-send fixtures: все поля, gates, cleanup и ABI.
  [Поля и ещё неизвестное](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-11316.md).
- SDK mode/main/value и шесть leaf getters теперь native внутри Login:
  2 016 случаев cache warm/resolve/absent. Закреплены также 27 статических
  metadata key/consumer links, готовый collector повторно не выгружать.
  [Значения, ownership и ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-SDK-11316.md).
- Metadata pipeline из шести roots прошёл 288 сценариев на общей памяти:
  33 field mappings, gates, optional branches и refcounts. Реальные SDK значения,
  строки / map / variants пока fixtures, интеграция в whole Login ещё открыта.
  [Цепочка и следующий патч](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-METADATA-11316.md).
- Далее: реальные platform text / FName / type / resolver / value-at, SDK getters
  и прочие зависимости Login, интеграция writer/archive и result readers. Только после этого готовить
  соответствующую возможность профиля для отдельной живой проверки.

[Точные адреса, доказательства и ограничения fixtures](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-VERSION-PLATFORM-11316.md).

## 5. Панель аккаунтов

- Есть таблица, раздельные DPAPI-пароли, назначения сервера / персонажа,
  настройки создания и отдельные состояния workers.
- Добавлен checklist по сохранённым наблюдениям. Он различает отсутствие списка,
  пустой список и существующего персонажа, сверяет назначение по ключу.
- Добавлен единый пресет устройства / маршрута, настройки аппаратных inputs,
  три постоянных ключа на бота и собственные шаблоны без копирования ключей.
  Профили подтверждённых персонажей сохраняются отдельно по серверному ключу
  и восстанавливаются в форме при переключении.
  [Поля, передача и ещё неизвестное](CONNECTION-PRESETS.md).
- Далее: живая проверка профилей при доступе, актуальность каталога по версии,
  разделение настроек создания и подтверждённого класса. Сохранённые наблюдения
  не считать текущей доступностью сервера.

[Панель и проверенные границы](ACCOUNT-CONSOLE.md).

## 8. Автоматическое обновление

- Уже есть граф контрактов, кэш, продолжение, явный пакетный экспорт,
  offline checks, отдельный подготовленный профиль и ручная очередь.
- Новая platform/context проверка подключена к game-version, её зависимости
  перечислены в реестре. Новый SHA не добавляется в поддержку автоматически.
- `update-status` различает актуальные / изменённые определения и старые журналы,
  в которых SHA определений не сохранялись. Изменение требует продолжения прогона.
  [Поля, проверки и границы](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-UPDATE-DEFINITION-STATUS.md).
- Далее: завершить обязательные game contracts и сборщик игрового профиля,
  повторить пару 1.13.14 → 1.13.16 и измерить весь процесс. Launcher готовность
  не означает готовность world-session. Baseline и рабочие боты не переключаются.

[Команды, кэш и очередь](../resource-tools/vampir/knowledge/RESUMABLE-UPDATE.md).

## 9. Сохранность, нагрузка и Android

- Реальная копия console.sqlite3 и accounts.sqlite3 сохранена и проверена:
  `F:/PhoneExit Backups/Vampir/accounts/20261023T231308Z-0986263f7334`.
- Проверены создание при открытом WAL, integrity / SHA, отказ на повреждении,
  сохранность исходной базы и предыдущей копии. Credentials не расшифровывались.
- Далее: отдельная копия библиотеки исследований на другой носитель, безопасный
  перенос DPAPI credentials, затем нагрузка и Android после готовности сессии.
  Ни копия двух баз, ни локальные fixtures пока не доказывают переносимость runtime.

[Создание, проверка и ручное восстановление](BACKUP.md).
