# Ограниченный профиль 1.13.16 и живые отказы входа

24 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
После [проверки handler списка](HEADLESS-CHARACTER-LIST-HANDLER-11316.md)
подготовлен отдельный `candidate-11316`. Обычный `recovered-release`, baseline
и назначения аккаунтов сохранены. Это профиль эксперимента, не готовая сессия.

## Источники и границы

[Определение](../../../../../vampir-headless/game-candidate-11316.json) закрепляет
девять неизменяемых offline reports: archive/writers, preparation Version/Login,
readers/handlers результатов, WaitingEnd и список. При загрузке проверяются SHA
отчётов и их источник. Storage/service fixtures сохраняют прежние ограничения.
Общая сеть этим не доказывается.

Config snapshot:
`12abc7a1cda6b050250662acab29155092484da595d50c0e93c2ffff42bfb145`.
Проверены полный SHA manifest, установленного EXE, архива и DefaultGame.ini,
строки NetworkSetting, AppVersion 1.13.16 и compiled tag
`32283C4C6485307BCF524765A84409C3`.
Pointer `14b1b9e98` имеет file offset 186353816 и bytes `2000964901000000`;
literal `149960020` расположен в file offset 160819744.

Профиль разрешает только Version/Login/список. Выбор, создание, world и heartbeat
не объявлены поддержанными. SDK использует существующий текущий `recovered-release`
с отдельным свежим GMC2; имя кандидата не подменяет его контекст.
CLI требует явного выбора кандидата. Автоматической активации нет.

## Реальное соединение

Использованы `bot-tw-test@vampir.top`, launcher auth и свежий свободный HK
Infinix X6525, SOCKS5 loopback 1087. HTTPS Cloudflare подтвердил loc HK.
Повторной регистрации не было. Перед входом создана проверенная копия баз:
`F:/PhoneExit Backups/Vampir/accounts/20261024T131931Z-d039750249ae`.

Свежий CDN 1.13.16 получен через этот же маршрут:
`90a79de66556d4afc9ddd4ca2274c0ebd47054b187086e2e68f61a04fb45138b`.
SDK сообщает joined country JP. Каталог: 55 групп / 98 серверов.
ClientVersion 262487 прочитан из текущего windows.manifestlist.

| Попытка | Lobby Version / Login | Game Version | Game Login | Список / создание |
| --- | --- | --- | --- | --- |
| JP 251, lowest-valid-id | 0 / 0 | 0 | 37 | Не отправлялись |
| JP 256, explicit ID | 0 / 0 | 0 | 16 | Не отправлялись |

Для каждой попытки lobby оставался открыт до Game Login, затем соединения
закрылись. Game LoginResult — полное тело 131 байт; при отказе публикации списка
нет. Смена сервера изменила код, но не установила причину. Значения 37 и 16
не объявлены BlockedIp. Подпись InvalidState для 16 в существующем runtime
происходит из прежней проверки; текущий mapper отдельно не перенесён.

[Квитанции без credentials](LIVE-CANDIDATE-11316.json) содержат SHA приватных
сводок. Пароли, токены и auth bodies не сохранены в этих сводках.
Тестовый дочерний transport остановлен по проверенному PID владельца; отсутствие
listener 1087 и принадлежащих ему процессов проверено. Рабочие боты не переключались.

## Сначала компоненты окон

По уточнению пользователя сначала просмотрен готовый каталог компонентов,
затем таблица переводов; новый полный разбор ресурсов не запускался.
[Квитанция вариантов и SHA](ERROR-COMPONENTS-INVENTORY.json).

| Компонент | Подтверждённые поля сохранённого каталога |
| --- | --- |
| WBP_MessageBoxConfirmPopup | TextMessage, ButtonOk, TextOk |
| WBP_MessageBoxPopup | TextMessage, ButtonOk, ButtonCancel, TextCloseButton |
| WBP_SystemMessageBoxPopup | TextMessage, ButtonOk, ButtonCancel, TextCloseButton |
| WBP_SystemMessageUI | TextMessage; кнопка OK не найдена |

Сохранены base/patch варианты. Это исторический каталог, не доказательство
активного окна 1.13.16 или его DPI. Таблица `table-study/ProjectRED-Windows-6106.csv`
содержит английские тексты ошибок с ключами, но порядок строк не задаёт числовой
result code. Перевод ошибки не позволяет назначить 37 по сходству текста.
Прежние [компоненты и native-связи](../interface/SYSTEM-MESSAGE-UI.md) использовать
как ориентиры, не переносить адреса на новую сборку автоматически.

Current LoginResult handler относит 14/22/37 к отдельному helper `14679ef30`.
Его полный экспорт получен в `run-48c7c4d6cbbb`: он получает текст через
`145bccec0` → `145bff0d0` и передаёт его popup helper `144a513a0`.
Сам export не устанавливает ресурс WBP, ключ перевода или семантику 37.
Эти зависимости не исполнялись и не расширялись автоматически.

Далее: проверить актуальность выбранных компонентов, затем связать dedicated
helper → источник текста / ключ → WBP → кнопки. Отдельно проверить текущий
numeric mapper. Не повторять вход до появления нового проверяемого различия.
После принятого Game Login получить свежий список; только принятый пустой ответ
разрешает следующий проверенный шаг создания Carnage. Creation/world source checks
пока открыты, персонаж не создан.

## Локальная проверка

`test_vampir_candidate_game_profile.py`: проверка реальных источников, повреждения
отчёта, запрета расширить scope и CDN без direct fallback. Проверки не авторизуются.
`test_vampir_selected_game_login.py` также проверяет запрет selection до auth.
Старый public-CDN тест, ожидающий исторический `recovered-release` на установленном
EXE, отклоняется source guard; guard сохранён, это не успешная проверка старого профиля.
