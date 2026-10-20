# Vampir: вход по ресурсам клиента

Обновлено 15 октября 2026. Начинать с [главного файла](../../../../../vampir/README.md).
Это cooked-макеты Windows, не исходники обработчиков и не доказательство
совпадения с Android. По выбору пользователя проверяем сохранённые кадры.

## Где искать и как повторить

`python phone-exit/bots/resource-tools/vampir/build-entry-reference.py`
создаёт `F:/PhoneExit Resources/Vampir/ui-geometry/entry-reference.json`.
Источник — только перечисленные в `ui-catalog/index.json` варианты ресурсов;
старые JSON вне индекса не используются. Отчёт содержит 10 окон / 20 вариантов,
SHA256 каталога и каждого JSON, путь/размер/sample SHA архива, номер entry,
SHA uasset/body, смещения и SHA экспортов контролов, цепи родителей и слоты.
Сохраняются все контролы окна, поскольку размеры соседей влияют на размещение.

| Макет | Patch entry / базовый entry | Подтверждённые элементы |
|---|---|---|
| WBP_TitleUI | 2427 / 8449 | TitlePanelUI типа NkDeferredPanel, SafeZone_0 |
| WBP_TitlePanelUI | 2425 / 8447 | ButtonStart, ButtonServerSelect, ButtonRegionSelect; SwitcherAccount, SwitcherSelectState, SwitcherRegionSelectState |
| WBP_CharacterSelectUI | 2371 / 8393 | ButtonStart, CharacterSlot1…4, TextName, TextLevel; отдельно ButtonDelete, SwitcherDelete |
| WBP_ServerSelectPopup | 2409 / 8431 | ButtonOk, ButtonRefresh, TableViewMyCharacter, TileViewServerList; ImageMaintenance, ImageFull, ImageBusy, ImageNormal |
| WBP_ServerSelectMyCharacterT | 2407 / 8429 | ButtonAccess, TextCharacterName, TextServerName, WidgetSwitcherState |
| WBP_PatchUI | 2389 / 8411 | ProgressBarPatch, TextDownloadValue, TextApplyingValue, SwitcherText |
| WBP_PatchPopup | 2387 / 8409 | ButtonDownload, ButtonWIFI, ButtonLTE, TextLowStorage |
| WBP_LoginPopup | 785 / 8093 | TextBoxLoginId, CheckBoxRememberId, ButtonOk |
| WBP_SecurityLoginPopup | 827 / 8135 | TextBoxLoginEmail, TextBoxLoginId, TextBoxLoginName, SwitcherMode |
| WBP_SecurityLoginCodePopup | 825 / 8133 | TextBoxNetmarbleCode, TextBoxNotmarbleCode, ButtonOk, ButtonCancel |

Patch — `Saved/PersistentDownloadDir/Patch/Install/pakchunk500-Windows.pak`;
базовый — `Content/Paks/ProjectRED-Windows.pak`. Полные пути и отпечатки в отчёте.
Отдельные варианты сохраняются даже при совпадении body SHA; их приоритет
монтирования на Android не установлен.

## Что уже следует из макетов

У TitleUI нет собственной ButtonStart: найден контейнер отложенной панели.
Связь с WBP_TitlePanelUI теперь подтверждена сериализованным свойством UserWidget
у TitlePanelUI в обоих вариантах. Это явная ссылка на ресурс, а не только совпадение
имени. Runtime-создание панели и динамическое назначение класса пока не проверены.

Источник схемы — массив указателей на дескрипторы в EXE по offset 157219216:
UserWidget, DeferredResourceObject, UnderlyingType, CachePolicy, AsyncLoad.
UnderlyingType — вложенный enum-дескриптор, не самостоятельное свойство.
Для TitleUI читается заголовок свойств [0,12, 29]; только значение поля 0
декодировано: два FName и строка subpath, диапазон байтов [6,26) экспорта
TitlePanelUI (offset 7568). Получен путь
`/Game/RED/UI/Lobby/WBP_TitlePanelUI.WBP_TitlePanelUI`. Хвост [26,35)
сохранён непрозрачным с SHA256, остальные свойства не объявлены разобранными.

Генератор `decode-deferred-panels.py` создаёт `ui-geometry/deferred-panels.json`
в библиотеке: 958 панелей, 957 явных путей, одна без явного свойства, 0 ошибок.
Поддержаны WBP/ZBP, номерные FName и суффикс generated class `_C`.
В entry-reference.json связь проверяется по entry, источнику, SHA asset/body,
экспорту контрола и набору целевых макетов. Перед обновлением справочника запускать
сначала decoder, затем build-entry-reference.py. При изменении источников связь
не должна молча сохраняться.

TitlePanelUI.ButtonStart (export 105, offset 39685 в patch) растянут на весь
CanvasPanelLobby: anchors 0,0→1,1, offsets 0. Это область запуска, не основание
нажимать центр любого неизвестного экрана.

CharacterSelectUI.ButtonStart — другая кнопка (export 124, offset 44196),
в HorizontalBox_0: контейнер имеет размер 400×80 в единицах макета, привязку
к низу CanvasPanelSlot и смещение X=20. Сам CanvasPanelSlot привязан справа,
имеет ширину 500 и верхний отступ 300; выше находятся SafeZone и другие родители.
400×80 — размер родителя, не доказанный прямоугольник кнопки на телефоне.
Необходимо учитывать соседей, Scale/DPI, SafeZone и runtime-видимость.

## Что осталось связать перед автоматическими нажатиями

Статические ссылки и первые ветви обработчиков восстановлены отдельно:
[NATIVE-ENTRY.md](NATIVE-ENTRY.md), `code-clues/entry-code.json` в библиотеке.
Внутренний Sequence титульного экрана не совпадает с ELobbyState — не подставлять
названия из одного enum в другой.

В справочник добавлены подтверждённые в EXE значения ELobbyState:
Splash=0, Title=1, TrasnsitionSelectWorld=2 (так написано в клиенте),
CharacterSelect=3, CharacterCreateIntro=4, CharacterClassSelect=5,
CharacterCustomize=6, TransitionInGameWorld=7, Max=8.
Значения взяты из native-enums.json с дескрипторами, а не из порядка строк.
Это перечень состояний, не доказанный порядок переходов.

Также сохранены девять точных UTF-16LE строк с байтовыми смещениями и SHA EXE:
`UTitleUI::_BeginGame()`, диагностика отказа SignIn, `_BeginGameImpl()`,
GetLastPlayedServerId/InvalidInfoId, `_BeginPatch()`, `_ChangeSequence()`,
OnSuccessNetmarbleSDKAuth и ProcessNetmarbleSDK. Например, ссылки на последний
сервер находятся в диагностике offset 163917376, а отказ SignIn — 163917200.
Это зацепки для поиска ветвей обработчика. Из диагностических строк пока нельзя
вывести точные условия кнопок или считать переходы восстановленными.

Сейчас `vision.json.launch_buttons=[]`: пакет умеет запустить Android-приложение,
ожидать загрузку и распознать HUD, но автоматический проход входных экранов
ещё не включён. Порядок title→server→character не считать доказанным графом:
нужны обработчики/состояния и кадры переходов. Сохранённых кадров входа в
`phone-tests`, названных login/title/launch/server/character/patch, не найдено.

Для каждого состояния требуется привязка видимого элемента к ресурсу, проверка
окружения/активной вкладки, безопасной зоны и результата нажатия. Для выбора
сервера/персонажа нужна сохранённая идентичность. Не подменять её первым слотом.
Авторизация и код безопасности требуют ручного ввода. Загрузку ожидать;
ButtonLTE, удаление персонажа и сброс аккаунта не входят в сценарий входа.
KICKOUT_FOR_INSPECT остаётся отдельной паузой без повторного входа:
см. [UI-CATALOG.md](UI-CATALOG.md) и `ui-window-reference.json`.
