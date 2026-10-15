# Vampir: макет → поле кнопки → ветвь обработчика

15 октября 2026. Продолжение [NATIVE-ENTRY.md](NATIVE-ENTRY.md).
Источник: тот же Windows Shipping EXE с SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Макеты — WBP_TitlePanelUI patch entry2425 и base entry8447.
Данные Android этим анализом не проверяются.

## Где результаты и как повторить

После build-entry-reference.py и build-native-entry-code.py:

```powershell
python phone-exit/bots/resource-tools/vampir/build-entry-button-links.py
python -m unittest discover -s phone-exit/bots -p test_vampir_entry_buttons.py
```

Результат: `F:/PhoneExit Resources/Vampir/code-clues/entry-button-links.json`.
В нём хеши входных отчётов/EXE, полные фрагменты участка привязки и инициализации,
инструкции поиска/сохранения каждой кнопки, сравнения и условные ветви,
литералы имён со смещениями, экспорты контролов из двух вариантов макета с SHA
и родительскими цепочками. Ссылки на источники не заменены координатами кликов.

## Что доказано

Участок `0x146428b50` получает элемент TitlePanelUI и ищет в нём именованные
кнопки. Для каждой из 11 кнопок проверена ограниченная последовательность:
LEA имени → построение имени вызовом `0x1415a8e80` → получение элемента
`0x144a72480` с аргументом R8=R14 → сохранение RAX в поле объекта RDI.
Неизвестная последовательность или изменённое поле прекращает генерацию.

В `0x146428c8f` R14 получает RDI+0xa00. Обработчик `0x146417ad0`
переносит RCX в RBX, входной RDX в RSI и сравнивает RSI с полями `[RBX+offset]`.
Отдельная инструкция `0x146417f0e` получает основной объект как RBX−0xa00.
Поэтому поле +0xaa8 основного объекта и +0xa8 подобъекта обработчика совпадают.

Дополнительно участок инициализации `0x14640a6eb–0x14640a6f2` помещает
таблицу `0x149c4cd60` в `[RBP+0xa00]`. Указатель в слоте таблицы +8
равен `0x146417ad0` — адресу обработчика с диагностикой OnButtonClicked.
Весь путь эмиссии события и внутренности регистрации слушателя пока не разобраны:
`owner_vtable_handler_verified=true`, `callback_dispatch_target_verified=false`.

| Контрол WBP_TitlePanelUI | Поле основного объекта | Поле подобъекта | Сравнение VA |
|---|---|---|---|
| ButtonStart | +0xaa8 | +0xa8 | 0x146417db2 |
| ButtonServerSelect | +0xab0 | +0xb0 | 0x1464181c9 |
| ButtonOptionSetting | +0xab8 | +0xb8 | 0x1464182b5 |
| ButtonReset | +0xac0 | +0xc0 | 0x1464182da |
| ButtonLanguage | +0xac8 | +0xc8 | 0x1464184e2 |
| AccountManagement | +0xb10 | +0x110 | 0x146418494 |
| ButtonPreCharacterMake | +0xb20 | +0x120 | 0x146417d62 и 0x1464185dc |
| ButtonWebView | +0xb28 | +0x128 | 0x146418610 |
| ButtonCharacterGiftReceive | +0xb30 | +0x130 | 0x1464186ea |
| ButtonCharacterGiftSealing | +0xb38 | +0x138 | 0x146418768 |
| ButtonRegionSelect | +0xb48 | +0x148 | 0x1464187d7 |

У всех найденных сравнений следующая JNE пропускает обработку при несовпадении;
совпадение идёт по fallthrough. ButtonPreCharacterMake проверяется в двух местах.
Таблица не означает разрешение боту нажимать все эти кнопки.

## Как это уточняет вход

Теперь участок `0x146417db2–0x1464181c9` можно связать именно с ButtonStart,
а не со всей функцией OnButtonClicked. Подтверждённая ранее AL-ветвь SignIn
и прямой вызов BeginGameImpl находятся внутри этого участка; другие кнопки
пропускают его. Ветка ServerSelect начинается отдельно с `0x1464181c9`.

Остаются неизвестными условия до AL-проверки, тип Sequence, работа вызываемых
функций и конкретные окна, появляющиеся по результату. Геометрия/видимость
Android и идентичность сервера/персонажа также требуют проверки.
`vision.json.launch_buttons` остаётся пустым; отчёт не исполняется ботом.
