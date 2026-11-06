# Ограниченный игровой вход Vampir 1.13.22

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Отдельный immutable selector `bounded-entry:<SHA>` связывает SDK Launcher,
текущий офлайн-кандидат, native LoginPrepare / sender и перенос readers лобби.
Loader на стандартной библиотеке проверяет полные SHA клиента, базового PAK,
patch manifest, доказательств и runtime consumers.

Область допуска включает CDN, лобби и свежий игровой список персонажей.
Обычные entrypoints используют тот же selector и свежий SDK контекст.
Профиль разрешает launcher auth, текущие layouts и начальный Ping.
Параметры создания, выбора персонажа, мира, tutorial и quest отклоняются.
Во вложенном вызове worker сохраняет один selector.

## Форматы ответов

Для lobby LoginResult 4 и ServerListResult 104 подтверждён перенос
14 целых функций с теми же инструкциями и локальными переходами.
Десять descriptor / vtable блоков замкнуты согласованной картой 71 адреса.
Текущие packet ID getters и связи с INPUT/string/TimeBase сверены.
Использованы прежние 7 полных LoginResult и 10 ServerList native случаев.
Переносимые decoder проверяют все их поля. Нового исполнения этих native
матриц нет. Storage, allocation, cleanup и initialized packet сохраняют
границы исходного стенда.

Игровой LoginResult текущего клиента содержит дополнительные FString
`+0x140` и два u32 `+0x150/+0x154`. Их чтение уже входит в текущий
native input / dispatch proof. Старый переносимый decoder оставлял этот
хвост и отвергал ответ. Новый `CurrentLoginResultBody` удерживает старый
prefix и три дополнительных поля. Выбор схемы ограничен source policy.
Строгая длина и UTF-8 проверяются. Обычный LoginFlow сохраняет диагностику
отказа с ID, размером, стадией и неподтверждённым u32 prefix.

## Онлайн

Silvercrow через прямой выход прошёл SDK и лобби. ServerList вернул код 0,
7 групп и 8 серверов. Canon 1 выбран по свежему ID 387. Игровые Version и
Login приняты с кодом 0. После исправления схемы прочитан ответ Login
размером 170 байт, затем свежий CharacterList с кодом 0 и нулём персонажей.
Результат пустого списка сохранён в существующей панели.
[Машинный результат](SILVERCROW-BOUNDED-ENTRY-CURRENT.json).

Проверочный вход завершён после списка. Создание Viper и постоянная сессия
требуют следующего capability. Текущий профиль не подтверждает loaded asset,
полный world lifecycle и поведение неизвестных ответов.

## Команды

Из корня проекта соберите профиль и сохраните выведенный selector.
Команда входа использует настройки и защищённые credentials существующей панели.
При запросе device/workplace продолжает штатную цепочку в том же SDK контексте.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-bounded-entry-current.py
python -X utf8 phone-exit/bots/vampir-headless/run-bounded-entry.py --account $accountId --profile $entrySelector --output $privateReport
```

Значение `$privateReport` задаёт локальный JSON без токенов, паролей и тела
пакетов. Предназначенные для выбора labels персонажей сохраняются явно.
Профиль закрепляется для одного вызова. Новый EXE, patch manifest или изменение
входов делает прежний пакет неприменимым.

`lobby-results-current`, `bounded-entry-current`, `create-handler-current`
и `viper-appearance-current` включены в штатный `on_update` и кэш.
Результаты Create и кандидата внешности имеют отдельные границы.
