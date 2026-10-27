# Обнаружение клиента 1.13.18 и отдельный план обновления

27 октября 2026. Установленный EXE имеет FileVersion/ProductVersion 1.13.18,
SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`,
размер 198677504 байта. Проверка Authenticode: Signature verified.
Прежний снимок 1.13.16 имеет SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это разные версии; адреса и native результаты прежнего SHA не перенесены автоматически.

## Проверенный аудит

Выполнен штатный `knowledge-index.py update --baseline <manifest> --plan-only`.
Baseline: `release-snapshots/c44b60d512a5b6a07a3ca7f6242eb23a385d36c87c67a7490fb2bad3c150b4db/manifest.json`.
Новый неизменяемый аудит:
`knowledge/update-audits/42948f396d663fa062145c4443050024d88297a25aee723c2803c941fcfba4bd/manifest.json`.
Полный SHA совпадает с именем его каталога. Проверены inventory, размеры/mtime
до и после чтения и полные SHA 165 архивов в области baseline.

Из архивов изменился только `ProjectRED/Content/Paks/ProjectRED-Windows.pak`:
прежний SHA `9803fa475ae3cb501519b341a5fc49dafd8540c8351def2cf6cb97ff0cf1685d`,
новый SHA `5b26dff87905a87947c43f161bb252a15c761baccd0129d272368a68274b0366`.
Остальные 164 полных SHA совпали. Метка строк `sample_matches_unverified`
сохраняется от исходной классификации, но вывод о равенстве здесь основан на
полных SHA baseline/current, а не на head/tail samples.
Стабильность файлов не подтверждает окончание всей загрузки лаунчером.
Окно Netmarble показывало RF Online Next; готовность Vampir по нему не установлена.

## Сохранённый план и границы

Возобновляемый журнал:
`knowledge/update-runs/0e4e1d2aaa28535737a8648a5fdf28afc1e8fe0fa98e9d2bb009d9df214fb375/run.json`.
Состояние `planned`, этап audit completed; Ghidra, native replay и сборка нового
профиля в режиме plan-only не выполнялись. План отмечает game-ui, game-version,
map-data, quests, sdk-gmc2, launcher, game-login, character-list, heartbeat,
character-select, world-entry и position для перепроверки по графу зависимостей.
Это область влияния, не доказательство поломки каждого компонента.

Далее продолжить штатным `knowledge-index.py update --resume <run.json>`:
команда заново сверит установленные входы перед использованием плана.
Результат старого source-bound replay не считается проверкой 1.13.18.
[Порядок обновления](../../RESUMABLE-UPDATE.md).

Работающий hk-test не перезапускался: та же сессия
`59f92a3931a780f87a4ee83a9f4eb41b`, последний наблюдённый uptime 44755.8 секунды,
heartbeat 8887/8887. Эти показатели подтверждают продолжение прежней сессии,
а не новый вход или совместимость профиля с 1.13.18. Игровые команды не отправлялись,
baseline и профиль не активировались. Мультиаккаунтный live тест и выполнение
квестов остаются незавершёнными.
