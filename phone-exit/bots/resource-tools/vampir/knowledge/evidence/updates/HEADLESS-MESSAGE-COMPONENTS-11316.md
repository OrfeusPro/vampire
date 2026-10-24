# Компоненты сообщений и расшифровка отказов 37 / 16

24 октября 2026. Продолжение [живого входа через HK](HEADLESS-LIVE-CANDIDATE-11316.md).
Источник EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Сначала проверены компоненты, затем таблицы и связь чисел с ключами.
Новых входов, создания или переключения ботов этот этап не выполняет.

## Компоненты текущего архива

Готовый каталог использован повторно. Его старые offsets не совпали с текущим
архивом. Существующий `recover-release-game-config.py --directory-only` сохранил
проверенный каталог pakchunk500 из release audit
`c44b60d512a5b6a07a3ca7f6242eb23a385d36c87c67a7490fb2bad3c150b4db`:
directory manifest `b8ee52f76aecb1ecb7544de13a59e2355b7a32b44d1da1fb6426e650f17f9a04`.
Это проверка SHA1 расшифрованного индекса с прежним key candidate, не перенос
key callback в текущий EXE. Ключи не сохранялись.

[Verifier компонентов](../../../verify-message-components.py) выбирает ровно
четыре именованных пакета и восемь payloads. Проверяет SHA manifest/каталога/
encoded entries, EXE/архива, decoder dependencies, header/prefix, размеры и
стабильность архива до/после. Никакого обхода всех окон нет.

| Patch-компонент | Точные прежние exports | Изменённые exports |
| --- | ---: | --- |
| WBP_MessageBoxConfirmPopup | 19 из 21 | TextMessage, TextOk |
| WBP_MessageBoxPopup | 22 из 25 | TextMessage, TextCloseButton, TextOk |
| WBP_SystemMessageBoxPopup | 20 из 23 | TextMessage, TextCloseButton, TextOk |
| WBP_SystemMessageUI | 16 из 17 | TextMessage |

Четыре `.uasset` совпали побайтно; четыре `.uexp` изменились. Проверены 86
корневых/контрольных exports: 77 совпали, девять текстовых отличаются.
ButtonOk/ButtonCancel и корневые WidgetBlueprintGeneratedClass совпадают.
Изменение текста само по себе не доказывает изменение перевода: properties этих
девяти блоков ещё не разобраны. Абсолютная геометрия, active mount, выбор base/patch
в реальном окне и наследуемые стили этим сравнением не установлены.

Report:
`F:/PhoneExit Resources/Vampir/knowledge/message-component-checks/82ee5c01ce06350ea1d3970b1d04900db8f125bba96c4663f63487f00da9b8f2/manifest.json`.

## От кода к таблице и popup

Готовый LoginResult handler в `14679b068` читает code из packet `+10` в EDX,
затем вызывает `14679ef30` в `14679b06e`. Dedicated helper сохраняет EDX до
`145bccec0` в `14679ef4c`; RCX задаёт выходной descriptor. Это связывает текущие
отказы 14/22/37 с lookup, а не с номером строки CSV.

`145bccec0` ищет raw uint32 в статической таблице и возвращает record `+8`.
`145bff0d0` читает текст record `+10`; при начальном UTF-16 `@` удаляет префикс,
преобразует ключ через `145806ed0`, ищет ссылку и рекурсивно разрешает её.
Это статический разбор: runtime lookup/recursion и защита от циклов не исполнялись.

Dedicated helper передаёт текст в `144a513a0`. Он получает окно через
`144a4dfa0`, которое запрашивает у `144a28140` selector byte 1. Селектор работает
с конфигурацией manager, а не содержит фиксированный путь WBP. Конкретный asset
selector 1 ещё не связан с одним из четырёх компонентов. Семантику 1 как «OK»
и конкретные callback-действия по кнопке пока не присваивать.

Явные экспорты: `run-cdd95da25609` — lookup/text/popup helpers;
`run-c7e91fc7815c` — getter и исследованный table slot;
`run-15172e0b063b` — selector и два CSV loaders. Все под каталогом
`ghidra/request-exports/<полный SHA>/`. Экспорт `145921090` сам по себе не дал
имя таблицы; его не считать getter имени по положению slot.

Точные ASCII literals ResultCodeString.csv и ResultCodeString_Name.csv дали
RIP-relative LEA в `145bde4c3` и `145be8dff`, roots `145bde430` и `145be8db0`.
Name loader вызывает преобразование symbolic key в numeric через `145806ed0`.
Это leaf из пяти байт: E9 в `1457d9210`, собственного unwind root нет.
`collect` для него не запускался. Большой целевой owner, 90 467 байт,
проверен статически; его Ghidra-декомпиляция не запрашивалась.

## Подтверждённые ключи и переводы

[Прежний verifier pointer pairs](../../../inspect-release-result-names.py)
получает явные SHA, owner и constructor. Для текущей сборки проверены полный
decode unwind ranges, native LEA literal, constructor `141426950`, local string,
integer и два соседних указателя одной пары. Проверка отклоняет подмену
`37 → BlockedIp`. Map insertion и lookup не исполняются.

| Code | Символический ключ | Текущий русский текст |
| --- | --- | --- |
| 37 | CreateRestrictedServer | Создание персонажа недоступно на этом сервере. |
| 16 | InvalidState | Недопустимое состояние |

Английский текст 16: `Processing. Please try again in a moment.`
Это не устанавливает конкретную причину недопустимого состояния и не разрешает
бесконечные повторные входы. Code 37 из попытки JP 251 теперь расшифрован как
ограничение создания на выбранном сервере; причина code 16 на JP 256 остаётся
неизвестной. Список персонажей не получен, создавать персонажа пока нельзя.

[Verifier переводов](../../../verify-login-error-texts.py) извлекает только
CSV/ResultCodeString.csv и EN/RU ResultCodeString_Name.csv по полному проверенному
каталогу текущего pakchunk1. Каталог:
`d2691f91f8d88d15329639bc8457bced595cef0d5ee6b4bfff3b17e98c97f523`.
Для multi-block CSV проверяются authenticated position prefix, размеры/method/
block count и фактический record header. Используется прежний decoder;
нового формата PAK инструмент не вводит. Все три payload SHA сохранены в report.
Число ищется в numeric Key, символическое имя — в уникальном Key перевода;
порядок строк не используется.

Reports:
`F:/PhoneExit Resources/Vampir/code-clues/release-result-names/a5866e314204d116c235f2c3ce23472e32b563e7707a3e361d889788a3318b18/manifest.json`,
`F:/PhoneExit Resources/Vampir/knowledge/login-error-text-checks/c378c20322cf9d97a23f784c85881e4d7494b1837523ac3394deb0a0b9459aaa/manifest.json`.

Runtime получил подпись 37; порядок запросов и retry policy сохранены. Synthetic
socket test проверяет, что после 37 не отправляются список/создание и сессия не
объявляется готовой. Исторические отчёты живых отказов не переписаны.

## Проверка и обновления

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-message-components.py
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-login-error-texts.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_message_components.py
```

Check `message-components-error-texts-current` связан с вопросом и update target.
На новом патче искать declared CSV literals/callees и вновь проверять dictionary
pairs, каталоги, выбранные payloads и переводы. Совпавшие exports использовать
повторно; изменённые тексты/схемы оставлять в ручной очереди. Автоматического
переноса адресов, runtime promotion, авторизации и кликов в checks нет.

Далее: связать selector 1 с конфигурационным WBP и текстовыми полями; проверить
девять изменённых text exports. Для живой проверки — выбрать сервер с разрешённым
созданием и проверить вход после паузы. Новый персонаж только после свежего
принятого пустого списка и переноса current creation checks.
