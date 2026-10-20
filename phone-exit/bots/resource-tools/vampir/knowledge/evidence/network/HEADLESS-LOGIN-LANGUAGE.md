# Язык в Login и ветвь metadata с DeviceKey

21 октября 2026. Продолжение [сравнения официальной записи](HEADLESS-LIVE-TCP-CAPTURE.md).
Источник — код Windows-клиента с SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Назначение байта +0x124

Прежний reset-метод задаёт manager+0x18 = 7. Это начальное значение до применения
языка, а не доказанное состояние любого Login. В официальной записи байт равен 1.

Ghidra экспортировал три дополнительных участка:

- `0x1455709b0`: сравнивает подготовленную строку с manager+8, при непустом входе
  вызывает `0x145570240`, затем передаёт текущий manager+0x18 в событие.
- `0x145570240`: compiled diagnostic прямо называет метод
  `FNnLocalizationManager::UpdateLanguageCode()`. Метод получает строку,
  вызывает конвертер `0x1456aeba0` и сохраняет AL по manager+0x18.
  Инструкция по `0x145570338`: `88 46 18`, `mov byte ptr [rsi+0x18], al`.
  Обратный конвертер вызывается по `0x14557033f`.
- `0x14555cb50`: при допустимом непустом SDK config+0x240 подменяет входную
  строку этим значением; иначе сохраняет переданную строку. Полная семантика
  sentinel и приоритетов настройки пока не восстановлена.

В switch UpdateLanguageCode байт 1 выбирает compiled `en-US`, 7 — `ko-KR`,
6 — `ja-JP`. Это статическая связь, не предположение по языку видимого окна.
Непосредственные строковые конвертеры ещё не исполнены отдельно.
При включённом флаге записи метод вызывает helper ключа `0x145564cb0` и writer
`0x1445d0530`; diagnostic `_WriteLocalizeConfig()` / `Write Language Code`
подтверждает назначение ветви. Сам ключ и чтение текущего файла ещё не связаны.

Связь с тем же singleton проверена в существующем `ServerList_Update`:
в ветви выбора региона getter `0x145564550` передаёт объект в `0x1455709b0`
(callsite `0x145d4b1e9`). Этот getter используется и перед чтением байта в Login.
Таким образом byte Login+0x124 является текущим кодом языка manager.
Обязательность совпадения языка для сервера и связь с отказом 16 не доказаны.

## Код и проверки

`prepare_initial_windows_game_login(..., language_code=...)` принимает явный
uint8. Без аргумента сохраняется прежний reset 7. Runner
`probe-selected-game-login.py --language-code 1` передаёт английский язык;
значение проверяется до авторизации и включается в обезличенный summary.
Новый тест подтверждает изменение только этого байта, прежние поля сохраняются.

`encode_nid_metadata_with_device_key` воспроизводит существующий основной
collector и добавляет `,"I_DeviceKey":"..."` перед закрывающей скобкой.
Значение передаётся явно; функция не читает старые записи, не создаёт ключи и
не устанавливает свежесть данных. Ветка marketing не поддерживается.
Пустая базовая map отклоняется: буквальная запятая native suffix дала бы
некорректный JSON. Требования к строкам и общий лимит прежние.

На официальной записи новая ветвь собрала ровно те же 791 байт metadata.
Порядок и повтор I_World сохранены. Отчёт без значений:
`F:/PhoneExit Resources/Vampir/code-clues/official-login-shape-c027b2be-v3.json`,
SHA256 `5bd542f934c8a51b9b3a2cf061cdd503eb7d2bbc696fb42bad3b0c02f4baadab`.
Это проверка формата; свежая metadata ещё не подключена к сетевому runner.

Отчёт статических связей:
`F:/PhoneExit Resources/Vampir/code-clues/login-language-evidence.json`,
SHA256 `2401fcb1fe2f417965a2dbbc6c5f4f34d6457ff1d730462374dfc518a990baf2`.
Экспорт Ghidra: `export-c7552efd2125/run-157d58347cfd`, 422 функции,
191 предупреждение. Manifest SHA256:
`a503bc402b59578bca81c732354d3ce31778663b491d7cb8eefb48c52b1d4658`;
functions.json SHA256:
`78bd674dc4849d4746527678d6e2f96b17ab9889be5cc566d09ba187689ff8e8`.

Полный unwind range UpdateLanguageCode не проходит linear decode из-за switch
data. Инструмент сохраняет отдельно проверенный prefix до конца CALL обратного
конвертера; остальная семантика switch и config-ветви сверена с Ghidra. Это не
полное native-исполнение метода. Сырые данные игры и инструменты остаются вне Git.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-login-language-evidence.py
python -X utf8 phone-exit/bots/test_vampir_login_language_evidence.py
python -X utf8 phone-exit/bots/test_vampir_metadata_device_key.py
python -X utf8 phone-exit/bots/test_vampir_initial_game_login.py
python -X utf8 phone-exit/bots/test_vampir_selected_game_login.py
```

## Первая попытка с явным языком 1

Через JP samsung SM-A057F, SOCKS 17948, при закрытой игре получены свежие
конфигурации и SDK launcher auth. HTTPS показал JP. ServerList принят:
55 групп / 98 серверов. Но выбранное лобби server 256 вернуло код **10036**.
Игровое соединение и Game Login не открывались: влияние языка не проверено.
Транспорт завершён штатно. Причина отказа лобби не установлена.

Summary: `F:/PhoneExit Resources/Vampir/code-clues/live-language1-login-jp-20261020T221025804528Z-summary.json`,
SHA256 `b50e749d92904c3d0e63f79a0fc7ea6315797b87cb96f6b27567adbad568637b`.
Время UTC 20 октября 22:10:25 = 21 октября 01:10:25 Киев.
CDN manifest SHA256 `a41f593d6cca06ad045d4c3f568b419e5d49080578b822d427febb38c3ddecb0`;
GMC2 manifest SHA256 `1df9bb8666aa8ecc403a8d65277298686093c8c237aaad022b489adf52ae475e`.

Существующий mapper `0x1458091b0` исполнен с новым входом 10036, вернул пустой
ключ. Расшифровки это не даёт; одноимённую ошибку Winsock применять нельзя.
[replay-result-error-10036.py](../../../replay-result-error-10036.py) сохраняет
`code-clues/lobby-result-error-10036-replay.json` вне Git, SHA256
`75d1226f6319daf643fcbd94c3dba823c3124b141ba8f0f857e3dd3aa7a45e3a`.

По прямой просьбе пользователя повторена попытка: он сообщил, что официальный
клиент также подключался не сразу. Тот же samsung SM-A057F / JP, новый транспорт,
свежие CDN / GMC2 и SDK auth, процесс игры отсутствовал. Результат снова
LobbyLoginResult 10036, 545 отправленных / 11 506 полученных байт, 55 групп /
98 серверов. Game Login не отправлялся. Два полных ответа не доказывают причину
или постоянство отказа, но это не наблюдённые обрывы сокета.

Повторный summary:
`F:/PhoneExit Resources/Vampir/code-clues/live-language1-login-jp-20261020T221344157815Z-summary.json`,
SHA256 `138ad6bd59f7d00a6c1f75bd00e35b969a64cf74103db4ff32067c8cfb2fd457`.
Время 21 октября 01:13:44 Киев. CDN manifest SHA256
`b1f8c340116e0351c072ead759e6dfdfebcab7fa13c741a94a777f49787cbbc3`;
GMC2 manifest SHA256 `c647c37a918ebd143254c6cbe03e4236a7fdb672fb39cc52dc62c8200b008090`.
После проверки собственный транспорт остановлен.

## Дополнительное сравнение Lobby Login

Успешный официальный Lobby Login из flow 5 также прочитан по существующему
writer и собран обратно байт в байт. Тело 1 148 байт; integers 2 / 0 / 256 / 0,
raw +0x80 = 7. Они совпадают с выбранной ботом числовой ветвью. Длины шести
строк: 32 / 230 / 32 / 2 / 32 / 791. Четвёртая строка (country) и последняя
(metadata) у бота пустые по явно выбранному `sdk-without-nid-info`.
Совпадение всех остальных строк между разными попытками не заявлено.

Сценарий проверки вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/check-captured-lobby-login-20261021.py`.
SHA256 `22d0b10c3161f86feef89d386ea88c5ca875a1a45b53503a8196e7af97c2f6e9`.
Он проверяет CRC и обратное кодирование, выводит только числа и длины.
Следующая работа — соединить актуальные NID country / metadata с подготовкой
лобби, не перенося токены из записи и не считая отличие доказанной причиной.
