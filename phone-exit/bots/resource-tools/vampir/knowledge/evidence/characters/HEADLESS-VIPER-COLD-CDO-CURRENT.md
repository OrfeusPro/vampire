# Холодное создание CDO пресета в Vampir 1.13.22

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Текущий owner `0x1416a4980` и initializer `0x1417ca930` собраны
одним ограниченным экспортом `run-ea90b06e1993`. Getter класса
`0x1454ceec0` и allocator / constructors / completion взяты из готовых
экспортов. Проверка сверяет полные ranges и исходное имя класса
`/Script/NnFramework.NnDataAssetForCustomizePreset`.

Три сценария используют начальную память 00, A5 и FF. Native owner создаёт
свежий объект, allocator обнуляет память через именованный memset,
конструкторы и completion исполняются до публикации CDO. До последующих
engine callbacks девять целых полей равны нулю, семь float равны 0.5,
VoiceType равен нулю. Повтор owner использует тот же CDO без выделения.
Границы объекта сохранены.

Регистрация класса, UClass metadata, superclass CDO, пустой список
property initializers, TLS/context и object bookkeeping заданы стендом.
Дополнительные engine helper, initializer cleanup, PostInitProperties
и callback UClass также являются fixtures. Эти границы требуют отдельной
проверки перед использованием полей как загруженного пресета.

Пакет уточняет холодную ветвь ранее проверенного
[CDO allocation и copying](HEADLESS-VIPER-CDO-CURRENT.md).
Загрузка cooked F/M assets и последующие overrides остаются открытыми.
`viper-cold-cdo-current` подключён к автообновлению с отдельной квитанцией
и полными SHA зависимостей.
[Общая квитанция](../updates/ENTRY-PACKAGE-CURRENT-VALIDATION.json).
