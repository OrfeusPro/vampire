# SDK sign-in: завершение ответа и общий парсер

19 октября 2026. Источник — код собранного клиента Windows, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Продолжение [response gates](HEADLESS-SDK-RESPONSE-GATES.md).

## Воспроизведение и происхождение

Инструмент [replay-sdk-sign-in-completion.py](replay-sdk-sign-in-completion.py)
создаёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-completion-replay.json`.
SHA256 отчёта: `a0d97c50a3dc99e2f484d8a98e981fc80c1483c666fca0cd1f2abf4dedf9f1d3`.
Отчёт сохраняет фрагменты инструкций, смещения, SHA и ссылки на исходные reports.
Запуск из корня проекта: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-sign-in-completion.py`.

16 сценариев исполняют native gates и обход полей от `0x1444cc2e9`
до `0x1444ccd56`, включая фактический SetSignIn `0x14454c3d0`.
JSON, выделение памяти, копирование FString и внешние действия остаются fixtures
или captures. Полное завершение функции, cleanup и жизненный цикл ссылок не исполнены.

## Подтверждённые связи

- `resultData.playerInfo.idpInfo` — массив; присваивание в module+0x90
  захватывается fixture, семантика элементов ещё не восстановлена.
- Байт module+0x88 получает 100 без credential или байт credential+0x50
  (33 в fixture), если достигнута ветвь playerInfo.
- SetSignIn действительно записывает байт service settings+0x400.
  Он может установить true даже при отсутствии resultData, playerInfo или token.
  Этот флаг не доказывает полноценную авторизацию.
- Сравнение прежнего и нового player ID исполняется как чувствительный к регистру
  цикл UTF-16. При изменении вызовы `0x1445250f0` и `0x14454bc40` с пустой строкой
  захватываются; последующее действие не исполняется.
- Вызов `0x1444ccd42` → `0x1444dff20` получает auth pointer и исходный response
  shared pointer. Сам dispatcher и делегаты не исполняются.

Статические фрагменты dispatcher, GetPush и OnPlayerUpdate сохранены отдельно.
Не проверены полный error dispatch, связь с игровым Login, срок действия и refresh.
Реальные ключи, профиль, storage и HTTP авторизации не использованы.

## Общий offline parser

[sdk_sign_in_response.py](../../vampir-shared/vampir_core/sdk_sign_in_response.py)
предоставляет `parse_sdk_sign_in_response(status=..., body=...)` и неизменяемый
`SdkSignInData`. Это явно более строгая локальная политика, чем native callback:

- HTTP status — целое 200–206; body — bytes размером 1–65536, строгий UTF-8/JSON.
- Дубли JSON-ключей, нечисловые константы NaN/Infinity и чрезмерная вложенность
  отклоняются; errorCode обязателен и равен ровно целому 0 или строке "0".
- Обязательны свежие непустые resultData.accessToken и playerInfo.player.playerId.
  Старое состояние и provider token не подставляются.
- Текстовые поля ограничены 8192 печатными ASCII-символами — ограничение
  локального подмножества, а не доказанный полный серверный контракт.
- gameRegion и joinedCountryCode необязательны; отсутствие возвращает None.
  Из idpInfo сохраняется только количество элементов, максимум 64.
- Token, player ID, region и country скрыты из repr. Возвращённые данные
  не подтверждают origin, подпись, срок действия или принятие игровой сессии.

Парсер не выполняет I/O и пока не подключён к живому login runner.
Проверки: [native replay](../../test_vampir_headless_sdk_sign_in_completion.py)
и [строгий parser](../../test_vampir_headless_sdk_response_parser.py).
