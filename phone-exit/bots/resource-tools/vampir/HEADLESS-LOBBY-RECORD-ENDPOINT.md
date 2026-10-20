# Запись ID 104 → игровой endpoint

20 октября 2026. Продолжение [реального списка серверов](../../vampir-headless/LIVE-LOBBY-SERVER-LIST.md).
Источник — собранный Windows-клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Прочитаны текущий Ghidra export `ServerList_Update.c`, предыдущие BeginGame /
ConnectToServer результаты. Повторного экспорта не потребовалось.

## Источник полей

Участок master Update 0x145d4afe0 получает запись ID 104. На 0x145d4b585
инструкция `mov r8d, dword ptr [r15 + 0xc]` задаёт ключ поиска / вставки
в master map по +0x88. Значит сервер выбирается по **второму uint32** записи,
offset +0x0c. Первый uint32 +8 переносится как поле группы; это не ключ сервера.
Diagnostic Update выводит Group / Id из этих двух полей.

На 0x145d4b625 начинается копирование исходной записи в value subobject
найденного / вставленного map node. Node stride 0x80, value = node+8.
Копируются исходные +8/+0xc, строки +0x10/+0x20/+0x38, два words +0x30/+0x32,
enum / flags / nested array и остальные поля до +0x68. Поэтому ранее
проверенные [BeginGame getters](HEADLESS-BEGIN-GAME-SERVER-TARGET.md) и
[ConnectToServer](HEADLESS-GAME-CONNECT-TARGET.md) получают:

| ID 104 server record | Master value | Transport | Назначение consumer |
| --- | --- | --- | --- |
| +0x0c | map key | +0x270 | выбранный server ID |
| FString +0x20 | FString +0x20 | FString +0x278 | основной host |
| word +0x30 | word +0x30 | word +0x288 | игровой порт |
| word +0x32 | word +0x32 | word +0x28a | дополнительный word, роль не установлена |

## Связанное исполнение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-lobby-record-endpoint.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_server_target.py -v
```

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/lobby-record-endpoint-replay.json`.
SHA256: `c2be993da4d9c3383134520ec4cdaa4d98e636310a5826425fed4d596cfabbc3`.
Source/tool/upstream SHA, весь Update fragment и key-source instruction
сохранены. Capstone 5.0.6 / Unicorn 2.1.4 — только инструменты исследования.

Replay исполняет copy slice `0x145d4b625..0x145d4b6cf`, затем настоящий
BeginGame lookup/setters и ConnectToServer на тех же fixture objects.
16 сценариев: два server ID, короткий / длинный ASCII host и порты
12001 / 32767 / 32768 / 65535. Во всех случаях transport получает точные
host/words; signed native port guard пропускает к endpoint только первые
два порта. Формирование endpoint и нижний connect capture унаследованы
из проверенного harness. Старые target text / words заменяются copied record.

Границы: master map key / topology / last selection заданы fixtures, полный
Update с его guards и insertion не исполняется. String assignment и пустой
nested array copy — fixtures. Native ID 104 reader не сцеплен с copy slice;
он проверен отдельным whole-reader replay. Lower connect — capture, живого
игрового подключения здесь нет. Статическая связь ключа не выдана за
исполнение всех ветвей master model.

## Runtime

`select_game_server_target(server_list, server_id=...)` принимает отдельный
успешный LobbyServerListResult, отклоняет alternate handler branch +0x110,
ищет единственную запись по +0x0c и возвращает immutable GameServerTarget.
Обязателен явный ненулевой ID. Порядок массива и первый uint32 не выбирают
сервер. Никакой интерпретации availability flags, Login или socket IO здесь нет.

Локальная политика: порт 1..32767 (native caller дополнительно пропускал 0),
public literal IPv4 либо bounded ASCII DNS hostname. IPv6 / private literals /
локальные имена / malformed host отклоняются. DNS ещё должен проверяться
транспортом при разрешении; Phone Exit делает это на exit. Host скрыт из repr,
дополнительный word сохранён без объявления его UDP-портом. Неизвестный
override host не используется.

Три новых теста воспроизводят 16 native scenarios и проверяют выбор / bounds /
редакцию host; четыре ID 104 decoder и три прежних ConnectToServer tests
также прошли — всего десять целевых проверок. Внешней сети в этом этапе нет.
Далее — свежий список и явный выбор server ID, игровой Version на его endpoint,
затем игровой Login, список / выбор персонажа и позиция.
