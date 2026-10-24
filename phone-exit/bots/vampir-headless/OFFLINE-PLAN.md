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
  строки / map / variants пока fixtures; результат интеграции в whole Login — ниже.
  [Цепочка и следующий патч](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-METADATA-11316.md).
- Metadata pipeline включён в whole Login на одной памяти: 448 сценариев
  проверили фактическую проекцию в `+d8`, общий SDK manager и cleanup.
  [Интеграция и следующие проверки](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-PREPARE-METADATA-11316.md).
- Текущие LoginResult/nested constructors/readers проверены с archive fixtures:
  320 полных случаев, 332 коротких префикса, 25 отказов; прежний Python decoder
  совпал по полям. Следующие этапы input primitives/UTF-8 приведены ниже;
  handler/dispatch ещё открыты.
  [Привязки и ограничения](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-11316.md).
- Числовой input archive / raw IO / bool normalization включены в LoginResult:
  320 полных случаев, 332 коротких префикса и 25 отказов повторены native.
  FString/UTF-8 и buffer constructors перенесены следующими этапами ниже.
  [Границы ввода и новые проверки](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-INPUT-11316.md).
- FString/std::string/UTF-8 исполняются native в общем LoginResult: 160 различных
  полных случаев, 4 границы размеров, 332 коротких тела, 25 отказов и 6 специальных
  строк. Storage / buffer fixtures и handler/dispatch ещё открыты.
  [Политика UTF-8 и границы проверки](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-STRING-11316.md).
- Concrete/base buffer constructors включены в общий LoginResult: 72 проверки
  полей / ABI / padding; pointer, size и cursor теперь формирует native код.
  [Границы и автоматическая проверка](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-BUFFER-11316.md).
- Статическая цепочка регистрации ID 4 связана с current handler `14679aec0`.
  [Проверенные связи и следующие gate/post-state](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-REGISTRATION-11316.md).
- Current handler/gate прошли 38 native сценариев на synthetic packet/services.
  [Stores, ошибки и очередь post-state](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-HANDLER-11316.md).
- Reader/FString/UTF-8 и handler/gate работают на одном packet: 44 общих случая
  и 131 отказ без вызова handler. [Границы и следующие связи](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-RESULT-BODY-HANDLER-11316.md).
- Post-state wrapper/tail callee отдельно прошли 44 native сценария; source E9
  model решила отказ export. [Границы и интеграция далее](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-POST-STATE-11316.md).
- Current continuation constructor/getter/final slot28 reset: 8 перенесённых
  сценариев. [Далее current WaitingEndNotify, не повторный поиск внутри reset](../resource-tools/vampir/knowledge/evidence/updates/HEADLESS-LOGIN-CONTINUATION-11316.md).
- Далее: реальные platform text / FName / type / resolver / value-at, SDK getters
  и прочие зависимости Login, интеграция writer/archive, реальные storage primitives
  и handler/dispatch результата. Только после этого готовить
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
