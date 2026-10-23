# ID 104: чтение результата создания

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [запроса создания](HEADLESS-CREATE-REQUEST-WRITER.md).

Целый constructor `0x1456d8150` устанавливает table `0x14992a468` и создаёт
вложенную запись по packet `+0x18`. Reader `0x1456b8a30` читает uint32 code
в `+0x10`, затем ту же полную запись, что используется в ID 102. Reader не
пропускает запись при ненулевом code. Это структурное чтение, не применение
записи к состоянию аккаунта и не подтверждение успеха создания.

`replay-release-character-create-result.py` исполняет целые constructor /
reader и существующие native readers записи, строк, внешности и optional map.
16 тел: code 0 / 1 / 58 / 0xffffffff и четыре записи, включая пустые строки,
имя NightRaven, Unicode, непустой массив внешности и optional map с повторным
ключом. Все поля сравнены с переносимым decoder; cursor совпал с длиной тела.
729 коротких префиксов отклонены native и portable readers без выхода cursor
за доступный вход. Проверены canaries вокруг packet размером `0x188`.
Storage, input buffer, allocation / copy / cleanup остаются bounded fixtures.

Переносимый `vampir_core.character_create_result` требует полный SHA источника,
immutable bytes, явные byte / extension budgets и отсутствие хвостовых байтов.
Он повторно использует существующий parser записи через одноэлементный list
envelope; добавленные raw14 / tail нулевые поля отбрасываются и не имеют
семантики ответа ID 104. Формат вложенной записи сопоставлен с текущим native
reader целиком, но исходный модуль списка сохраняет свою историческую маркировку.
Возвращается code и raw record; автоматического сохранения ника или retry нет.

Три теста включают native сверку, отказ на одиночный code, неверный SHA,
лишний байт, превышение byte budget и недостаточный aggregate extension budget.

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_character_create_result
```

Report:
`F:/PhoneExit Resources/Vampir/code-clues/release-character-create-result/324910d77c77292089edf21e3ca594d424d1265cf5b5211e6cbf90381e74ee48/manifest.json`.
SHA256 совпадает с именем каталога. Новый constructor export — comparison
`c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-9027b69badae/details.json`,
SHA256 `0eb4225456e8b5627fc3174e0b05d3320fc00aed84f9f6bfd62e590ec8bb280b`.
Reader уже был в `details/run-dbbbcb857839/details.json` того же comparison.
Проверка зарегистрирована как `release-character-create-result`.

Ограничения: handler `0x146796690` здесь не исполняется; смысл отдельных
ненулевых кодов, включая name_taken, не установлен. Значение 58 в fixture не
заимствует семантику Login 58 другого пакета. Нет реального capture ID 104,
сети, создания персонажа или подтверждения серверного допуска. Следом —
appearance producer / JSON и обработка успеха / отказов ID 104, затем одна
явная отправка после принятого пустого списка нужного аккаунта и сервера.
