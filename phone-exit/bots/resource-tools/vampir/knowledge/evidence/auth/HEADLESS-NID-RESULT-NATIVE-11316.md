# Текущий OnResult: проверки полей и передача токенов

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [статической сверки handlers](HEADLESS-NID-RESULT-SOURCE-11316.md).
Сохранённый EXE / synthetic memory, без процесса игры, сети и реальных аккаунтов.

## Выполняемый код

`replay-nid-result-11316.py` исполняет OnResult slice
`0x1450f40da..0x1450f4bc4` и целый FString copy constructor `0x1414266a0`.
Entry service acquisition и query parsing обходятся явно. Stop находится перед
post-adoption вызовом `0x144543690`. Проверяются полные SHA EXE / двух exports,
байты выполняемых инструкций; используется Capstone 5.0.6 / Unicorn 2.1.4.
Instruction / heap / string budgets конечны, canaries вокруг synthetic stack.

Семь global key bindings повторно проверяются source audit. Globals содержат
synthetic FString descriptors с точными именами ключей, строки результата тоже
синтетические. Hash / map lookup — fixtures: по identity descriptor возвращают
index строки либо -1. Native caller затем сам читает row и копирует FString.
Copy constructor не подменён: это сохраняет отличие отсутствующего row от
пустой строки. Allocation / memcpy остаются ограниченными fixtures.

## Проверенные исходы

| Вход | Исход текущего caller в заданном fixture contract |
| --- | --- |
| resultCode отсутствует | Ветка missing resultCode до parser |
| resultCode пуст | Отдельная ветка empty resultCode |
| Integer fixture вернул false или ненулевое значение | Invalid result branch |
| Auth mode содержит bits вне маски 0x5 | Auth mode gate до чтения accessToken |
| accessToken пуст | Empty accessToken branch |
| refreshToken пуст, ключ присутствует | Adoption arguments достигаются |
| channelKey пуст | Empty channelKey branch |
| Channel mapper fixture вернул 0 | Unknown channel branch |
| netmarbleId пуст | Empty ID branch |
| joinedCountryCode пуст | Empty country branch |

Режимы 0 / 1 / 4 / 5 проходят mode gate. Остальные проверенные значения
останавливаются: все 256 вариантов младшего byte и отдельно 0x100 /
0x80000000 / 0xffffffff. Это не перебор всех uint32.

При map return -1 для accessToken / refreshToken / channelKey / netmarbleId /
joinedCountryCode выполняется реальное чтение unmapped low address. Replay
сохраняет точный instruction / address / size. Это наблюдение при synthetic
map contract, не доказанный crash живой игры: настоящий parser / map invariants
и верхние обработчики ещё не исполнены. Portable decoder должен по-прежнему
проверять обязательные поля и отклонять неполный результат до дальнейшей работы.

1100 случаев: четыре poison fills × 275 fixtures. На каждый fill — complete,
по missing / empty для шести полей, parser failure, nonzero result, unknown
channel и 259 auth modes. Проверены outcome, последовательность lookup,
отсутствие adoption captures при отказе и canaries.

## Раздельные adoption arguments

| Capture target | Передаваемое synthetic значение |
| --- | --- |
| 0x144550d80 | accessToken |
| 0x14142a250, receiver settings +0xb0 | joinedCountryCode, точная длина |
| 0x1445523c0 | netmarbleId, R8b = 1 |
| 0x144551210 | Channel mapper byte |
| 0x144552e10 | refreshToken, включая пустую строку |

Settings receiver проверяется во всех captures. Access / refresh не меняются
местами. Тела setters, изменение настроек, сохранение на диск и callbacks
не исполняются. Capture аргумента не означает сохранение токена настоящим клиентом.

## Fixtures, ограничения и следующий этап

Integer parser `0x1415e4460` и channel mapper `0x144531900` возвращают заданные
пары / byte. Это доказывает caller gates, но не допустимый numeric syntax,
строковый enum канала или mapping mailUserKey → 20 новой сборки. Class getter
возвращает synthetic initialized settings CDO. Hash/map, allocation/memcpy,
class getter, adoption settings calls и country assignment — fixtures/captures.
Доступ к сети, браузер, реальный NID результат и целая авторизация не проверены.
Runtime profile остаётся выключенным.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-result-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_result_11316.py
```

Два теста: 1100 сценариев / раздельные captures и отказ при повреждении copy
export. Check `nid-result-native-11316` связан с полным SHA / exports / tools.
Для следующего обновления в release-update-targets.json указаны root, copy
constructor, scope и required checks. Existing locator ищет handlers по точным
diagnostics; после нахождения нужно сверить parser / mapper / copy targets,
gates / row offsets / adoption calls и перенести replay. Совместимость runtime
не устанавливается автоматически.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- OnResult export: предыдущий evidence по ссылке выше.
- Copy export: `ghidra/request-exports/<SHA>/run-1740fcc91625/details.json`,
  SHA `f2cdd2d5e37669d223dbbf74217780bed1c64090827b75d3b62c78d99f7dce38`.
- Native report: `code-clues/nid-result-11316/b344472ef1e932110fb2513b3b956ecccb3f59aa9d16d92602809aadcf75895f/manifest.json`.

Далее проверить настоящие numeric / channel helpers по явным текущим адресам
`0x1415e4460` / `0x144531900`, затем auth source guards и подключение профиля
с отдельной живой проверкой после доступности серверов.
