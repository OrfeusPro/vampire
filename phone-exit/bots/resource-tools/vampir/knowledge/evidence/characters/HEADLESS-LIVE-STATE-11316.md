# Живое состояние: изоляция и границы декодирования 1.13.16

Источник клиента: `ProjectRED-Win64-Shipping.exe`, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это код собранного клиента, не исходный C++ проект.

Исследование `live-world-state-11316` подготовлено двумя явными заданиями:
`c496bf0f6ae2f36a0a49f4b9213be1e4278247ece71edecd8612fb89027ec520`
и `048c0584f014b3752a1e2f39687cde67ca41f150303bf34d54cde7c649944a51`.
Получены bounded Ghidra exports в библиотеке ресурсов:

- `ghidra/request-exports/<SHA>/run-f4d4115c1822/details.json`: восемь внешних функций.
- `ghidra/request-exports/<SHA>/run-fa0e43376ec9/details.json`: девять вложенных функций.

`inspect-release-ping-result.py --source-sha <SHA> --packet <имя>` расширен
явным текущим SHA и именами Sight / NPC / Stat пакетов. Getter / table / ctor
кандидаты не являются разрешением runtime или доказательством смысла полей.

Статически просмотрены readers `1456c5390` / `1456c5550` (Sight),
`1456c5180` / `1456c5230` (NPC), `1456c4740` / `1456c5630` (level / stats),
`1456c4890` (move notify) и writer `1456d38b0` (move).
Вложенные: `145788180`, `14579e350`, `14579e590`, `14579e690`, `14579e6f0`,
`1457a8030`, callback `1456c6690`, vectors `144aaced0` / `144aad280`.

Например, `1457a8030` последовательно вызывает archive slots `+58`, `+50`, `+50`
для полей объекта `+8`, `+10`, `+18`; внешний `1456c5630` читает ключ, массив,
bool и короткое поле. Это форма чтения. Единицы, signed interpretation,
значение пары stat values и связь с отображением HP/MP ещё не установлены.
В текущем runtime эти поля не называются HP/MP и не публикуются как таковые.
Нужны reader replay и handler → применение в модели / UI того же SHA.

Реализованы независимый snapshot каждого bot/session, общий registry / Stop API,
постоянный pump после world finish и отдельный UI адаптер. Контракт, команды,
лимиты и проверки: [LIVE-SESSIONS](../../../../../vampir-headless/LIVE-SESSIONS.md).
Старую карту не подключаем после изменения установленного PAK без новой проверки.
Отправка движения / квестов и отображение окружения остаются открытыми.

Живая проверка 25 октября: SDK / lobby приняты, Version 0, Game Login 58
`BlockedIp`, initial Ping получен. Персонаж не выбран, постоянная сессия не доказана.
Приватный итог без credentials:
`F:/PhoneExit Resources/Vampir/live-checks/hk-20261025/hk-persistent-result.json`.
Транспорт остановлен. Это отдельный отказ от исправленного ранее Login 16.
