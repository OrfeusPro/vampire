# SDK Launcher composition и повторное использование входа

Текущий EXE 1.13.22:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинная квитанция](AUTO-ENTRY-PROOFS-CURRENT.json) закрепляет профили,
проверки, зависимые материалы и замеры повторов.

## SDK → Launcher

`build-sdk-launcher-profile.py` связывает готовые 3667 SDK native случаев,
девять component manifests и статическую проверку 14 Launcher roots.
Новые native / HTTP / browser действия сборщик не запускает.
Подготовленный immutable профиль содержит 98 входов с полными SHA.
Лёгкий `sdk-launcher-profile.py` принимает явные SHA профиля и клиента,
проверяет каждый вход, разрешённые пути, размеры, locale и launcher-only scope.
Указатель next и старый loader этим пакетом не переключаются.

Семь новых source-bound composition тестов используют текущий профиль:
два HTTP плана, раздельные credential / device keys / launcher token,
истечение контекста между запросами и отказ неподдерживаемых SDK операций.
Порча manifest, component, context, EXE, неполный комплект компонентов,
неподходящий путь и превышение размера отклоняются.
HTTP / browser и permission ровно одной SDK policy являются явными fixtures.
Настоящий source guard после выхода из fixture продолжает отклонять текущий
непривязанный runtime. Серверная авторизация не выполнялась.

Target variant существующего `sdk-runtime-launcher-11316` подключён к `on_update`.
`sdk-launcher-check-guard.py` сверяет все входы профиля до и после проверки,
включая попадание в кэш. Неизменный вызов штатного dispatcher занял 2,294 с;
запуск дочерних процессов был запрещён assertion-проверкой. JVM / native — ноль.

## Семь областей прежнего candidate

`candidate-proof-bridges.py` использует готовые текущие archive / Version /
Login input, prepare и state-flow proofs. Штатный publication v3 проверяет
их source, lineage, матрицы, runtime и tools; готовые native сценарии не повторяются.
Четыре Version/Login projections проходят provider / observe и итоговый
owner barrier. Их восемь tag и 160 writer случаев наследуются статически.

Итог содержит семь прежних evidence scopes и 371 вход. Старые check reports
под прежними ID не создаются; исходные ограничения и callback preconditions
сохранены. Проверка producer, source, набора providers, owner barrier и
целостности всех файлов подключена к отдельному `candidate-proof-bridges-current`.
Его guard работает при каждом cached вызове. Четыре source-bound теста прошли.
Неизменный dispatcher занял 2,261 с без нового native / JVM и дочерних процессов.

Эти scopes предназначены для последующей сборки ограниченного candidate.
Они не активируют профиль и не подтверждают создание, stats, целую world-session
или неограниченную работу онлайн. Сам bridge не выдаёт runtime admission.
Для следующего SHA нужны новые опубликованные proofs и собственная квитанция;
переключения по одному номеру версии или совпадению адресов нет.

## Следующие шаги

Общий VersionResult уже готов отдельным пакетом.
[CharacterList / clock / lobby exports](HEADLESS-ENTRY-COLLECT-CURRENT.md)
собраны. Остаются их текущие native сценарии, новый lobby decoder и сборка
ограниченного runtime candidate. Создание Carnage имеет отдельный source guard.
