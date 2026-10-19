# SDK sign-in response: структура player и SDK accessToken

19 октября 2026. Продолжение [request preparation](HEADLESS-SDK-SIGN-IN.md).
Источник — собранный Windows EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base 0x140000000; исходного C++ проекта нет.

## Evidence и native replay

Инструмент `replay-sdk-sign-in-response-fields.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-response-fields-replay.json`,
SHA256 `d75efa085213385aecdf7765cdb01f72d89dfcb00acdff00631fbd3beb309f95`.
Сохранены response/initializer/setter/load fragments с instruction bytes/file
offsets/SHA и tool SHA. Auth constructor leaf взят из прежнего body report,
его bytes сверены с EXE, source report SHA сохранён.

Ранее найденный callback `0x1444d85f0` — leaf JMP к root `0x1444cc1a0`.
Этот разбор не начинает ошибочно с leaf как с unwind root. Native replay
исполняет auth constructor `0x1444bc380`, затем response field slice
`0x1444cc725..0x1444ccb55`. Early branches остановлены на именованных адресах:
status-outside, no-resultData, no-playerInfo, no-player.
Остановка slice — исследовательская граница, не штатный результат callback.

Response body JSON и numeric status уже заданы fixtures на входе slice.
Предыдущие JSON/errorCode gates, network result lifetime и полный callback
не исполнялись. Helpers присутствия/получения объекта/строки, FString операции,
settings getters/setters, module writes и Save — явные fixtures/captures.
Wrong JSON types не моделируются: fixture getter требует ожидаемый тип.

## Подтверждённые ключи

Constructor записывает native literal pointers в auth object:

| Offset | Key |
| --- | --- |
| 0x20 | playerInfo |
| 0x28 | player |
| 0x30 | playerId |
| 0x38 | playerStatus |
| 0x40 | gameRegion |
| 0x48 | idpInfo |
| 0x50 | joinedCountryCode |

Global initializer sources также сохранены: `0x14b4f0b70` → resultData,
`0x14b4f09e0` → accessToken, `0x14b4f0b20` → errorCode.
Global FString значения в replay заданы согласованными fixtures; initializer
source проверяется статически. Native constructor pointers исполнены реально.

Проверенная часть структуры:

```text
response
└── resultData
    ├── accessToken
    └── playerInfo
        └── player
            ├── playerId
            ├── joinedCountryCode
            ├── gameRegion
            └── playerStatus (object)
```

idpInfo находится вне проверенного player slice: дальнейшие source instructions
проверяют его в playerInfo, получают array и обновляют module JSON. Эти операции
пока только статические; не переносить idpInfo внутрь player по сходству названий.

## Передача значений

- playerId → setter `0x14454bc50` с bool=false, затем Save и UNMPlayer::Load
  `0x14452bde0`. Diagnostic sources подтверждают назначения функций.
- resultData.accessToken → module+`0x78`, отдельный SDK access token context,
  ранее использованный при формировании accessToken/authToken headers.
- player.joinedCountryCode → UNMPlayer::SetJoinedCountryCode `0x14454b8c0`,
  bool=false. Caller передаёт строку, не перепроверяет её в данном slice.
- player.gameRegion → module+`0x68`.
- player.playerStatus object → calls `0x1445280c0` и `0x1444f0c20`.
  Их тела не исполнены; внутреннюю семантику status пока не объявлять.

Это отделяет provider NID accessToken от accessToken ответа SDK sign-in.
Ни один fixture token не является настоящим credential или доказанной session.

## Тринадцать fixtures

Numeric status199/200/201/206/207: native диапазонный gate допускает200..206
к дальнейшему field traversal; вне диапазона уходит в другой branch.
Status — явный fixture return-context: получение/привязка к HTTP response
helper до входа в slice не исполнялись. Сам диапазон не доказывает login success.

Отдельно исключены resultData/playerInfo/player и пять optional leaf fields.
Отсутствие resultData/playerInfo/player приводит к ранним границам slice.
Отсутствие playerId не мешает обработке accessToken в этом slice, но не вызывает
Save. Отсутствие accessToken сохраняет old module token fixture; отсутствие
gameRegion сохраняет прежнюю region fixture. Caller не очищает их здесь.
Результат Save=false тоже не останавливает дальнейшую обработку полей.

Не выводить из этого, что server разрешает такие ответы или что весь callback
примет неполный результат: следующие проверки/действия ещё не исследованы.

## Далее

Проверить начало callback: network errors, JSON parse/object gate и errorCode
presence/conversion. Затем idpInfo, callback result/IsSignIn, expiry/refresh,
SDK token →game Login. Лишь после полного контракта подключать response parser
к runtime; частичную схему не выдавать за завершённую авторизацию.
Ни auth POST, ни реальные аккаунты/tokens/storage/сеть не использованы.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_sign_in_response.py' -v`.
Три regression tests проверяют source report, constructor keys, 13 caller cases,
optional field preservation, captures аргументов и продолжение после Save=false.
