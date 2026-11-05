# Launcher текущего SHA и повторное использование входа

Проверенный target — EXE 1.13.22,
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Launcher база — 1.13.18,
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
[Машинная квитанция](AUTO-LAUNCHER-CONTRACT-CURRENT.json) закрепляет source audit,
контекст и матрицу повторного использования готовых доказательств.

## Существующий путь уже работал

На 1.13.16 подтверждены вход в мир, HP 2700/2700, MP 2000/2000, уровень 1
и 207 stats. [Фактическая сессия и карта](../maps/HEADLESS-LIVE-MAP-11316.md).
На 1.13.18 подтверждена цепочка NID → Launcher → lobby → список серверов /
персонажей → выбор персонажа → мир с Login 0 и PingResult.
[Фактический вход](HEADLESS-LIVE-WORLD-11318.md).

Профиль candidate-11318 разрешал ограниченный живой тест при 36 открытых строках
общей очереди обновления. Полные Version / Login / selection / world / position
контракты тогда оставались неполными.
[Режим и границы](../../RUNTIME-ADMISSION-AUTOMATION-11318.md).

Обработчики и adapters сохраняются в коде. Для текущего EXE требуется перенос
необходимых source proofs. Отсутствие готового нового профиля не является
отсутствием ранее реализованных server-list / character / world / stats flow.
Полное закрытие всех world-session областей не требуется для переноса отдельного
проверочного candidate в прежних границах.

## Текущий Launcher source contract

Сверены 14 полных функций, десять initializers и два request / response пути.
Девять недостающих key roots собраны одним пакетом `run-2af588b5fc98`.
Остальные пять использованы из готовых exports.
Сравнение проверяет bytes каждого unwind fragment и локальные ветвления
по двум полным EXE SHA.

Ключи проверяют UTF-16 literals, RCX/RDX аргументы string constructor и cleanup
E9. Request проверяет globals, endpoints, callback E9 и transport call.
Response проверяет errorCode / resultData, getter / dispatcher links и
CRT import identity. Общая ASCII reference содержит `authUrl`; выполнение
HTTP headers этим значением не подтверждается.

Общий `audit-launcher-contract.py` читает адреса и источники из JSON context.
Три проверки охватывают фактический пакет и отказы при повреждении SHA /
пропущенном ключе. Target-вариант `release-launcher-contract` подключён к
существующему on_update / кэшу. Старые semantic checks и SDK runtime composition
сохраняют отдельные обязательства.

Static audit сохраняет внешние call / RIP пары как открытые зависимости.
JSON/HTTP execution, активные credentials, SDK callbacks и серверная авторизация
в этом пакете не выполнялись. Профиль не активирован.

## Минимальный следующий проход

Из 16 областей прежнего candidate для семи найдены готовые current материалы.
Они требуют проверяемого связывания с новым candidate с сохранением границ.
У raw tag / writer projections остаётся `owner_barrier_pending=true`;
такие отчёты не засчитываются как готовый runtime admission.

Девять оставшихся scope gaps группируются в три пакета.

- VersionResult handler / gate.
- WaitingEnd, CharacterList records / result-handler и выбор.
- Clock / Ping и ограниченный вход в мир.

Повторять готовые standalone native матрицы при неизменных inputs не требуется.
HP / MP source admission связывается отдельно после восстановления входа;
существующие codecs / observer переиспользуются.
Создание Carnage имеет отдельный legacy source guard и требует собственного
текущего подтверждения. Проверочный candidate не получает это действие
из одного успешного входа существующим персонажем.
