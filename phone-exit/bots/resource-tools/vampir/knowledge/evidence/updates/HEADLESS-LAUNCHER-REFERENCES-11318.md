# Ключи и внешние ссылки launcher 1.13.18

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Request `1d7f7b13e0554a48dc52d82d5d3536d57be860840346fcbb34b8e06ecc9baf11`.
Продолжение [полного сравнения формы](HEADLESS-LAUNCHER-SHAPE-11318.md).
Новый export run-652644c53992 SHA256
`fd7a0e84eb9246d0eaa4b57e864eb1e4c99d41609e705a3f4c1e1dd61a9f22ad`.

## Source цепочка ключей

Проверены восемь целых инициализаторов. Каждая UTF-16 строка передаётся в RDX,
а адрес глобального строкового объекта в RCX перед вызовом141426B30.
После инициализации функция делает E9 в root1487E976C для регистрации очистки.
Первый export отказал из-за tail за unwind range; root добавлен явно, повтор
прошёл. Расширение или отключение проверки границ не использовалось.

| Ключ | Инициализатор | Literal | Global |
| --- | --- | --- | --- |
| buildCode | 1411B0170 | 14952CBE8 | 14B563CB0 |
| countryCode | 1411B0260 | 14952CD88 | 14B563D70 |
| credential | 1411B0290 | 14952CCB8 | 14B563D20 |
| deviceKey | 1411B02F0 | 14952CC88 | 14B563D00 |
| gameCode | 1411B03E0 | 14952CBD0 | 14B563CA0 |
| launcherToken | 1411B04A0 | 14952CC68 | 14B563CF0 |
| nmDeviceKey | 1411B04D0 | 14952CCA0 | 14B563D10 |
| os | 1411B0500 | 14952CDA0 | 14B563D80 |

Полные ranges/instruction bytes и conditional fallthrough проверены тем же
валидатором, что launcher shape. Exact literals и аргументы LEA проверяются
отдельно. Строковое присваивание native не исполнялось; runtime contents globals
не читались. Аналогичные literal owners других объектов не подставлялись.

Функция token ссылается на nmDeviceKey/deviceKey/countryCode/os/gameCode/buildCode/
credential; sign-in — на nmDeviceKey/deviceKey/countryCode/os/launcherToken.
Это проверка ссылок ключей, не фактических значений или сериализованного JSON.

## Callback и transport call sites

| Request | Callback E9 | Цель | Direct transport call |
| --- | --- | --- | --- |
| token1444EECD0 | 1444DF0B0, e9fbd3feff | 1444CC4B0 | 144522F90 |
| sign-in144503E10 | 1444DF1A0, e98b48ffff | 1444D3A30 | 144523110 |

Ссылки на callback и149530980 присутствуют в request code; значение последней
строки и использование её как header здесь не устанавливаются. Transport targets
взяты из настоящих direct calls. Цели callbacks/transport целиком ещё не проверены.
E9 bytes сверены с EXE; результат callback или принятие сервером не доказаны.

Tool `audit-launcher-references-11318.py`, контекст
`knowledge/native-contexts/launcher-references-11318.json`, тест
`test_vampir_launcher_references_11318.py`, check `launcher-references-11318`.
Артефакт:
`code-clues/launcher-references-11318/158bf00293992be3178aa416d65244311ea6e933f139840ad79b6ff6fdb407bd/manifest.json`.
Static checks прошли; network_used=false, profile_activation=false,
compatibility=not_established. Прежняя release-launcher-contract для нового SHA
не разрешена этим результатом. Credentials/profile/process memory не читались.

Далее проверить whole callback targets1444CC4B0/1444D3A30, JSON getters/dispatch,
transport и SDK/GMC2 context. Новая авторизация не выполнялась, действующая сессия
сохраняется. Это ещё не готовый профиль 1.13.18.
