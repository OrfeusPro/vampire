# Create104 reader и handler в Vampir 1.13.22

Источник имеет SHA256
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Текущий handler `0x1467984c0` собран одним ограниченным запросом в
`run-5ece46e2b059`. Его 140 инструкций и полное PE unwind покрытие сверены
с EXE. Регистрация и таблица `0x149dc9588` переиспользованы из
[пакета Create](../updates/HEADLESS-GAME-CANDIDATE-CURRENT.md).

В одной памяти Unicorn исполняются 34 whole roots. Полный native INPUT,
Create104 constructor/reader и вложенная запись передают тот же packet
текущему handler. Предыдущая большая матрица чтения сохранена отдельно.
Добавлены шесть сценариев композиции.

- Три успеха проверяют совпадение имени, несовпадение и пустые имена.
  Вставка записи вызывается независимо от callback совпадения имени.
  В выбранное состояние записан ключ из `packet+0x20` в `selection+0x400`.
  Варианты покрывают UI refresh, отсутствующее/несовместимое окно,
  выключенный/отсутствующий SDK и callback активной SDK feature.
- Коды `1`, `58` и `0xffffffff` передаются error consumer. Смысл этих
  кодов для Create по этой проверке не установлен. Вставка записи и
  success finalizer в ошибочных сценариях отсутствуют.
- При существующем PlayerState и подходящем error UI сбрасывается
  `UI+0x378`. При явно выключенном error UI native handler достигает
  инструкции `0x146798527` с нулевым RDI и попыткой записи `null+0x378`.
  Это наблюдение стенда при заданных предпосылках. Поведение живого UI
  и факт реального сбоя не проверялись.

В каждом случае прочитан полный INPUT и сохранён packet. Для возвращающихся
ветвей проверен Win64 ABI. Временное имя освобождено, границы allocations
и пакета сохранены. Строковые memory helpers, сравнение, record insertion,
selection/UI/SDK services и их внешние эффекты ограничены fixtures.
Producer, сохранение default персонажа, серверное создание и runtime
admission остаются отдельными этапами.

`verify-create-handler-current.py` публикует content-addressed manifest
и повторно проверяет 93 хеша входов перед использованием кэша. Область
зарегистрирована как `create-handler-current` для вопроса
`create-packets-current` и частичного контракта `character-create`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-create-handler-current.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_create_handler_current.py
```
