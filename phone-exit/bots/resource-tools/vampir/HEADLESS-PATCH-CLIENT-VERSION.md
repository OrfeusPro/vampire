# ClientVersion из manifestlist до числа игрового Login

20 октября 2026. Продолжение [числового входа Login](HEADLESS-LOGIN-REVISION-INPUT.md).
Установленный `windows.manifestlist` содержит `ClientVersion = Revision258392`.
Связь ключа с descriptor `patch object+0x1b0` подтверждена кодом и native slice.
Одна реальная попытка с extra_number = 258392 снова получила InvalidState 16.

## Цепочка данных клиента

- `PatchContext_LoadCallback`, `0x144aa10c0`, получает путь через
  `PatchState_Path`, `0x144a96910`, с kind = 2 и вызывает загрузку
  `PatchState_Load`, `0x144a98c50`, для структуры `patch object+0x198`.
- Путь kind = 2 добавляет `.manifestlist` к строке настроек `+0x100`
  и соединяет её с базовым путём. Это не имя отдельного pakchunk manifest.
- Загрузчик проверяет доступность файла, читает текст через `0x141557840`
  и передаёт его в `PatchState_Parse`, `0x144a98d10`.
- Parser после успешного JSON parse готовит ключ `ClientVersion`
  из literal `0x14960aa78`. По `0x144a98edf` вызывает строковый accessor
  `0x1415e5ae0`; затем переносит возвращённый FString в `structure+0x18`.
  При structure = patch object+0x198 получается поле patch object+0x1b0.
- По соседнему ключу `BuildUrl`, literal `0x14960aa98`, заполняется
  другой descriptor `structure+0x28`; это не источник числа Login.
- BeginGame отбрасывает первые восемь символов из descriptor +0x1b0,
  вызывает настоящий `_wtoi` и записывает global для Login +0x50,
  как проверено [предыдущими сценариями](HEADLESS-LOGIN-REVISION-INPUT.md).

Пять новых native-сценариев исполнили участок `0x144a98eb1..0x144a98f24`:
подготовку точного ключа и перенос descriptor в поле. Проверены пустая строка,
две ревизии, числовой текст с хвостом и Unicode. JSON accessor, строковые
primitives и начальный объект — fixtures. Полный JSON parser, ветви отсутствующего
ключа и завершение установки патча в этом replay не исполняются.

Новый runtime parser применяет собственные строгие правила: UTF-8 JSON с
допустимым BOM, максимум 2 MiB, без дубликатов ключей; `ClientVersion` должен
быть каноническим `Revision` с положительным uint32 без пробелов и хвостов.
Это намеренно уже permissive-поведения CRT; число не выводится из `BuildUrl`
или имён pakchunk. Валидация всех файлов manifest и доказательство завершённой
установки не входят в этот parser.

## Установленный источник и новый ввод runner

Файл:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Saved/PersistentDownloadDir/Patch/windows.manifestlist`.
39 582 байта, SHA256
`4dff7291228f11bd330f80af5a2797a877396e41287fe46a0db8fa4e3e874ffd`.
ClientVersion: `Revision258392`, BuildUrl: `Revision258392/Windows`, 106 файлов.
Вложенные имена pakchunk с `Revision258269` относятся к отдельным пакетам;
они не опровергают ClientVersion этого списка.

`read-installed-patch-revision.py` сохраняет публичный snapshot вне Git:
`F:/PhoneExit Resources/Vampir/patch-state-snapshots/<SHA256>/windows.manifestlist`.
Отчёт `code-clues/installed-patch-revision.json`, SHA256
`1d4c631c2232b92d27fc7013a5ba1208b5240130b7b737a7b18f1095e3375c55`.
Он фиксирует SHA источника и parser, но не утверждает свежесть относительно CDN.

В `probe-selected-game-login.py` можно явно выбрать
`--patch-manifestlist <path>` вместо `--extra-number <uint32>`.
Оба аргумента взаимоисключающие, один обязателен. Файл читается с лимитом
до авторизации; числового default нет. Источник выбирает вызывающий код.
В реальной проверке ниже использован существующий аргумент `--extra-number 258392`,
после получения числа из проверенного установленного файла.

## Источники, SHA и проверки

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Экспорт `export-c7552efd2125/run-ab81849b3448`: 390 функций / 181 предупреждение.
Manifest SHA256: `205d289a19bc055943dda1e05302047ae6fb2327ffac097cd7ccd5e2d606753c`.

Native report: `F:/PhoneExit Resources/Vampir/code-clues/patch-client-version-replay.json`,
SHA256 `eaf53074e61f677ffcc6ff6e680f7d08ae8b231f03a43bfa3f501797ce8a9ad0`.
Сохраняет source/tool/dependency hashes, диапазоны инструкций и результаты пяти
scenarios. Полный загрузчик и parser рассмотрены в Ghidra; исполненный участок
ограничен переносом одного поля.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/read-installed-patch-revision.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-patch-client-version.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_patch_revision.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_selected_game_login.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Проверки покрывают воспроизводимость slice, сохранённый snapshot, канонические
значения и отказ на missing / duplicate / malformed / excessive JSON,
границы uint32, неверный префикс, Unicode-цифры, пробелы и числовые хвосты.

## Реальная попытка с ревизией 258392

JP-выход подтверждён. Прежний bot-hk-test@vampir.top, Windows device profile,
JP server ID 251; новая SDK-сессия, SDK-страна HK. Лобби приняло Version →
список → Login для выбранного ID, ответы `[2, 104, 4]`, все result codes = 0;
send 545 / recv 11 466, 55 групп / 98 серверов. Lobby socket оставался открытым
во время игрового обмена.

Игровой Version принят, Login с extra_number = 258392 снова вернул 16 /
InvalidState; body 131 байт, send 641 / recv 94, других packet ID нет,
подсчёт байтов полный. Значит, одна ревизия пока не устранила отказ.
Список / создание персонажа не запрашивались. Сокеты и JP-транспорт закрыты,
exit 0, stderr пуст. Игра не запускалась, установка и device keys не менялись.

Свежие public snapshots вне Git:

- CDN manifest SHA256 `25350ff2fcaa9f28a1a571f158868672d19aba239f7752f68f0f07cb7838a9bc`, body 6000 байт;
- GMC2 manifest SHA256 `f9a3a38e167c7716cf2eefe7e294e81c845f2e141843ac71c850ab3a7ba320bb`, HTTP 200, body 13 773 байта.

Пути: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/<SHA>/manifest.json`
и `public-gmc2-snapshots/<SHA>/manifest.json` соответственно.
Далее — фактический lobby kind, поля SDK / NID context и другие источники
Login до успешного входа и создания первого персонажа.
