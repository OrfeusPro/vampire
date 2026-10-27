# Локальная проекция серверной цели входа на атлас

Источник контекста сборки UI: EXE 1.13.18,
`d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Это не автоматически доказанная identity owner и не native математика виджета.

Фактический установленный PAK карты совпадает с прежним полным SHA:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Переиспользованы неизменённые данные immutable audit
`code-clues/map-projection-11316/0b26af0a29fcf9f968e9d6f01fd7b3bc198a2e15d944007d93915b34a662c677/manifest.json`
в `F:/PhoneExit Resources/Vampir/`. World SHA:
`c782ba8bd2c11a82382082da8a0e5487f4479d8605d795455cfc6e987f862c8c`,
Map SHA: `a17dcb5015fa7e1fca8b052bd59d6d65bd077fcf40901719c70bb06e0749b7b4`.
Старое native доказательство остаётся относящимся к 1.13.16.

Общий сборщик проверяет полные SHA installed PAK / EXE, immutable audit,
проекцию / изображение атласа и связи World → Map. Генерирует отдельный
local-map-projection.json для всех проверенных миров Map10/11.
Общий frontend компонент загружает metadata один раз, применяет локальную
линейную формулу к raw server XYZ только при connected и известном мире.
Сохраняет semantics server_target_before_engine_correction и явно помечает
origin=local_atlas / current_native_widget_math_verified=false.
Конфликтующие world/map, нечисловые / бесконечные координаты и неизвестные
источники данных отклоняются. Настоящая owner projection имеет приоритет;
невалидная ненулевая owner projection не скрывается локальным fallback.
API position, coverage и игровые действия не меняются.

Четыре Python теста, включая три Node набора, passed. Проверены источники,
отказ при смене PAK/audit, unknowns, приоритет projection и существующее
правило отсутствия центрирования при выборе объекта. Check
local-atlas-projection-11318 включён в on_update / общий кэш с release-bound
record index; перед reuse фактический PAK проверяется по полному SHA.

Сборка requested preview:
`db886ae57459177e0ee98e8253e1ad700168efe8e5419e1412077a047944372f`.
Generated metadata SHA:
`10fd688cc997f0559b23ca9556b51c8845c6a5153dffdc1f4d891fe37ab59b50`.
1970 resources / 1507 images; gate phase не изменена.
В браузере текущей сессии Okly мир10012 / XYZ90049,151840,-44 отобразились
на Map10: маркер виден в центре, подпись сообщает локальную проекцию серверной
цели входа. Кнопка «К персонажу» доступна. Соединение не перезапускалось.

Границы: это серверная цель входа, а не подтверждённое фактическое положение
после коррекции движком. Движение, навигация, текущие native widget bindings,
HP/MP, другие игроки и монстры этим пакетом не подтверждены. Квесты не переносились.
Новая строка native queue не закрывается локальным вычислением атласа.
