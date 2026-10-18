# SDK settings: конструктор и переопределения игры

19 октября 2026. Продолжение [GMC2 config](HEADLESS-SDK-CONFIG.md).
H04b остаётся частичным: найдены источники значений, но текущий environment
и живой ответ конфигурации ещё не получены.

Источник — собранный Windows клиент, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Этот EXE не изменился при [обновлении ресурсов](CLIENT-RELEASE-INDEX.md).
VA ниже относятся к image base `0x140000000`; версия Android не проверена.

## Воспроизведение и доказательства

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-settings.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_settings.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-settings.json`,
SHA256 `dca370b3cb47525bc16879fad4a6e0e116ea70dbe9d7a7c27df9caaa26fce573`.
Сохранены исходные bytes/file offsets/SHA, 9 дескрипторов полей, массив указателей,
registration metadata, диагностические строки, 4 native constructor replays
и 13 native game-override replays. Capstone 5.0.6 / Unicorn 2.1.4 закреплены
существующими инструментами; игра, память процессов, аккаунты и сеть не использованы.

## Регистрация класса и начальные значения

Accessor `0x1444ab740` регистрирует `NMSDKSettings`, `/Script/NMService`,
config name `Game`, размер объекта `0x228`. Constructor thunk `0x1444ac680`
при ненулевом объекте переходит в `0x1444ac9f0`. Отдельная registration function
`0x1444ab7f0` ссылается на params `0x1494c5e60`, содержащие property pointer array
`0x1494c5cd0`. Для девяти выбранных полей проверены имена, bytes дескрипторов,
packed offset words и вхождение в этот массив. Флаги сохранены без интерпретации.
Offsets дополнительно согласуются с getter/logging code `0x144536220`.

| Поле | Offset | Значение prefix конструктора |
|---|---|---|
| Market | 0x28 | пустая строка |
| GameCode | 0x38 | thered |
| BuildCode | 0x48 | 0 |
| SDKZone | 0x49 | 1 |
| SDKType | 0x50 | Global |
| WindowsEmailClientId | 0x68 | пустая строка |
| AndroidEmailClientId | 0x78 | пустая строка |
| IosEmailClientId | 0x88 | пустая строка |
| NetmarbleClientId | 0x98 | пустая строка |

Native slice `0x1444ac9f0..0x1444aca99` выполняется на четырёх заполнениях
объекта: 00/55/AA/FF. Инструкция `0x1444aca3d` записывает word `0x100` в +0x48,
то есть build byte 0 и zone byte 1. Base UObject constructor и FString constructor
заменены ограниченными shims; исполнены реальные инструкции присваивания,
но не загрузка конфигурации, lifecycle CDO или оставшаяся UI-часть конструктора.
Нельзя выдавать эти значения за окончательные настройки игры.

Service Initialize `0x144529670` получает класс, затем CDO через class+0x110;
при отсутствии вызывает leaf `0x1416aaaf0` → virtual slot+0x410. Сохраняет
game-instance в settings+0x220, вызывает CheckSDKLog/OutputDebugLog.
Наличие строк NMSDKMarket-nmp/NMSDKZone-Dev в этой функции само по себе
не доказывало активные значения. Переопределение найдено отдельно ниже.

## Переопределение со стороны игры

Диагностика `FNnNetmarbleSDKService::_InitSetting()` связана с root
`0x14561a930`. Class accessor вызывается на `0x14561a9a4`, затем берётся тот же CDO.
В settings+0x28/+0x38/+0x98 копируются FString из globals:

| Поле | Global | Начальный источник |
|---|---|---|
| Market | 0x14b5740c0 | initializer 0x141258b10 → nmp |
| GameCode | 0x14b574080 | initializer 0x141258ae0 → thered |
| NetmarbleClientId | 0x14b574090 | initializer 0x141258ab0 → literal client ID, bytes в отчёте |

Client ID здесь — публичная константа кода клиента, не токен/пароль аккаунта.
Последующие изменения globals ещё не исключены. InitSetting не записывает
build byte +0x48 в исследованном root; это не доказывает отсутствие других writes.

Environment берётся через singleton getter `0x14563d960`, который читает global
`0x14b575630`. InitSetting передаёт singleton+0x48 в `0x141433970`, получает
временную строку и сравнивает с ASCII literal `real` через `0x141459730`.
Сравнение UTF-16/ASCII использует таблицу `0x14899d500` для ASCII case folding;
не-ASCII несовпадение не превращается в Unicode case-insensitive equality.

Ветвь `test ebp; sete al; inc al; mov [rdi+0x49],al` на
`0x14561ab1e..0x14561ab38` записывает 2 при равенстве и 1 в остальных случаях.
Предыдущий GMC2 Start selector связывает 2 с production и 1 с Dev.
Native slice `0x14561a9cd..0x14561ab3b` проверен на 13 environment fixtures:
real/REAL/Real/rEaL → 2; пустая строка/dev/alpha/dr/production/строки с пробелами,
reals и réal → 1. Это именно game override: слова alpha/dr здесь не выбирают
одноимённые поля общего SDK selector.

Выполняются реальные инструкции копирования полей, весь comparator и запись zone.
Singleton, получение environment string, growth, memcpy и free ограничены shims;
значение environment задаётся явно, активная конфигурация не прочитана.
Root `0x145631210` присваивает singleton pointer на `0x145631232` и обнуляет +0x48;
тип поля и последующая загрузка реального environment ещё требуют исследования.

## Общий код и продолжение

`vampir_core.sdk_config.select_game_sdk_zone(environment)` повторяет это правило
без чтения файлов/сети. Аргумент обязателен; NUL отклоняется, лимит 128 UTF-16 units
— локальная политика, не найденный лимит игры. Значение по умолчанию не подставляется.
Наличие helper не означает, что активный environment уже установлен.

Далее проследить заполнение singleton+0x48 до InitSetting, порядок его вызова
относительно GMC2 Start и другие изменения globals/BuildCode. Затем можно собрать
подтверждённый GMC2 request plan. Реальный DECKEY, SDK response→constants,
email/password→code→token→game session остаются незавершёнными. network_ready=false.
