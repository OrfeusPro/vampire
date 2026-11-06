# Текущие ClassInfo lookup и потребители выбора класса

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Этот ограниченный пакет продолжает [defaults пресета](HEADLESS-PRESET-DEFAULTS-CURRENT.md).
Ранее готовые 25 constructor cases не повторялись. Новая матрица исполняет
ClassInfo lookup и потребителей выбора; allocation / completion / CDO copy
не включены и остаются отдельным этапом создания Viper.

## Точные функции и identity

| Роль | Текущий адрес | Инструкций | Проверка |
| --- | --- | --- | --- |
| ClassInfo lookup по type | `0x145895b40` | 149 | Whole native |
| Sparse iterator | `0x14142e750` | 42 | Whole native |
| Запись выбранных класса / пола | `0x14642cf80` | 159 | Whole native, engine gates fixtures |
| Получение type выбранного ID | `0x14644bfa0` | 36 | Whole native, row provider fixtures |
| ClassInfo singleton | `0x1458962b0` | 27 | Static whole source |
| ClassInfo name | `0x145896980` | 10 | Static whole source |
| ClassInfo column loader | `0x1458b6800` | 1465 | Static whole source |
| Preset class registration | `0x1454ceec0` | 31 | Static whole source |

Singleton `0x14b1bdfd0` содержит vptr `0x1499783f0` и interface
`0x149978428`. Interface slot `+0x48` указывает на name getter, который
использует ASCII `ClassInfo` по `0x1499783e0`; slot `+0x50` — на column loader.
Loader содержит точные `DefaultGender` / `Type` literals. Выбор класса вызывает
именно singleton `0x1458962b0` и lookup `0x145895b40`: неоднозначность среди
шестнадцати похожих singleton roots снята по source callsites и pointers.

Проверены также bytes текущего preset property array `0x1498b6b20`, 18 descriptors
(17 полей и внутренний UnderlyingType), ASCII names, gen flags и offsets. Эти
data anchors не доказывают активный engine cache или полный schema lifecycle.
Все заявленные whole bodies сверяются с целыми unwind ranges и точными байтами
EXE; отсутствующие / изменённые source anchors отклоняются.

## 49 native сценариев

27 случаев ClassInfo lookup проходят пустую таблицу, пять записей и sparse
таблицу из 35 слотов с внешним occupation bitvector. Проверены девять type
значений, дубликаты и первый занятый match; row storage не меняется. Для type 1
в sparse таблице выбирается слот 3, а не поздний дубликат в слоте 31.

Восемь успешных случаев выбора используют type 1 / 3 / 5 / 99 и оба допустимых
гендера. В PlayerState `+0x360` записывается uint32 ID найденной row `+8`,
а в `+0x364` — переданный byte пола. Для отсутствующего type записывается
подтверждённый source sentinel 0. ID намеренно отличаются от типов: например,
type 1 даёт fixture ID `0x80003000`, что обнаруживает ошибочную подмену ID типом.

Восемь ранних отказов — выключенный контроллер, busy, null actor, неверный режим,
не готовый контроллер, несовместимый actor type, type 100, gender 2 — не пишут
выбор и не обращаются к ClassInfo lookup. Ещё шесть случаев getter подтверждают
чтение row type `+0x28` после выбранного ID; отсутствие row возвращает 0.

Явные fixtures: строки / occupation bits ClassInfo, типы engine classes и
проверки совместимости, player / actor getters, получение type / пола из тегов,
singleton cache provider, сохранение выбранного actor и завершающий service.
Предыдущий actor и preview widget отсутствуют; их callbacks и deselection
ветви не заявляются проверенными. Getter поиска по ID использует fixture row
provider; это не исполнение всего lookup-by-ID / engine cache.

## Воспроизведение и следующий пакет

`verify-viper-class-current.py` и context `native-contexts/viper-class-11322.json`
используют общий `native-request-harness-11316.py` с явным текущим SHA, без
memcpy fixture. Два tests проверяют всю матрицу, ID / type и gate boundaries,
а также отказ при подмене identity bytes. Сеть и авторизация отсутствуют.

Exports переиспользованы: `run-ddd300a85f1d`, `run-49796294d192`,
`run-117e8a6a09e1`. Полные SHA закреплены в context. Новый immutable native
report хранится в `code-clues/viper-class-current-v1/` библиотеки ресурсов.

Для следующего отдельного CDO пакета найдено по одному bounded candidate:

| Роль | База 98802d55 | Кандидат 03edad26 |
| --- | --- | --- |
| Ordinary object construction | `0x1417e6cb0` | `0x1417e6e60` |
| Allocation | `0x1417e6110` | `0x1417e62c0` |
| Completion | `0x1417cbe90` | `0x1417cc040` |
| Postconstruct | `0x1417dd530` | `0x1417dd6e0` |
| InitProperties | `0x1417daa00` | `0x1417dabb0` |
| Default copy | `0x1417dda00` | `0x1417ddbb0` |

`knowledge/viper-cdo-current-navigation.json` фиксирует формы целых инструкций,
полные source SHA и ограниченное окно ±128 KiB. Это навигация, не semantic proof
и не разрешение применять старую allocation / default-copy модель к новому EXE.
Следующий collect должен брать только действительно отсутствующие whole bodies.

Текущая свежесть CSV Class / DefaultGender, преобразование пользовательского
тега Viper, загруженный preset с отсутствующими integer полями, Create 103 / 104
и приёмка сервера ещё не доказаны. Этот пакет не формирует Viper payload и не
ослабляет Carnage-only runtime guard.
