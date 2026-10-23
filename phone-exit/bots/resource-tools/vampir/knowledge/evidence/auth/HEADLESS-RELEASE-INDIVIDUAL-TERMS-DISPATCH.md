# Индивидуальные условия без player ID и передача результата

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [BasicTerms / NO DATA](HEADLESS-RELEASE-BASIC-TERMS-RESPONSE.md)
и [игрового callback условий](HEADLESS-RELEASE-TERMS-CONTINUATION.md).
Авторизация аккаунтов, принятие условий и SDK SignUp здесь не выполнялись.

## Запрос без SDK player ID

Полный готовый экспорт `1445a0100` использован повторно. Его вызывает
`1445a1100`, когда длина сохранённого player ID меньше двух символов.
В этой ветви используется **termsUrl**, а не agreementUrl ветви с player ID.
Предыдущее обобщение «все individual terms используют agreementUrl» неверно.

Шаблон UTF-16 по `14954a008`: `{0}/game/v2/{1}/terms/{2}?{3}`.
Входы: termsUrl, game code settings `+38`, имя content `+90 / count +98`.
Четыре query-параметра — country, locale, termsType, platform.
Country helper `144584210` и locale `143d1d470` описаны в предыдущем evidence;
актуальные значения из процесса игры не считывались.

Constructor `144561f60` устанавливает vtable `149549ba0`. Слот `+30`
указывает на `144586be0`: полный getter копирует UTF-16 literal `148a919b8`,
значение **I**. Это точный источник `termsType`, не подбор параметров.
Имя **terms_of_service_ko** ранее подтверждено initializer и игровым caller;
оно не означает принудительный корейский язык окна.
HTTP wrapper `144522040` ранее установлен как CreateGet.

Callback pointer `1445744c0` имеет байты `e94b70ffff` и ведёт к root
`14456b510`. Leaf без unwind сначала оставлен в очереди; затем явно выгружен
root. При `resultCode == -1` root создаёт error result
`144517fd0(..., 0x1c20, 0x1ca86d0, 9, ..., -1, ...)` и передаёт
`144580990(content, 2, result)`. Другой ненулевой resultCode даёт state 3.
Нулевой код читает **object** `resultData.terms`, заполняет content через
`1445a5f70`, затем вызывает `14457a520`. Эта успешная ветвь и HTTP parser
целиком native-сценарием пока не исполнялись.

## Dispatcher и отложенный вызов: 96 native случаев

[replay-release-terms-dispatch.py](../../../replay-release-terms-dispatch.py)
исполняет целые `144580990` и `1445742c0` из текущего EXE.
Сверяются полный SHA источника, SHA экспортов и все экспортированные байты.
Непредусмотренный native-вызов останавливает выполнение.

Dispatcher сохраняет content, byte state и исходную пару result / control block
в closure размером `0x28`, передаёт descriptor с thunk `1445742c0`
планировщику `141409e10` с selector 1. Consumer до вызова сохранённого thunk
не исполняется. Shared reference увеличивается на один на время очереди.

Thunk сбрасывает content `+60` для state 2 / 3. Если callback `+20` задан,
он выбирает heap storage `+30` либо inline storage `+40`, получает callable
context через virtual slot `+8` и передаёт прежние state / result pair.
Результат, его code и control block не заменяются на успешные.

Матрица: state 0 / 1 / 2 / 3 и границы 4 / 255, callback задан / отсутствует,
inline / heap storage, control block задан / отсутствует, result code 0 /
`0x1ca86d0`: **96 случаев**. Во всех проверяются исходные 64 байта result,
пара указателей, состояние показа, consumer и удержание queued reference.
State 2 с ненулевым result действительно доходит до consumer при binding.

Fixtures: успешная allocation, сохранение scheduler descriptor до явного thunk,
getter callable context и consumer capture; логирование выключено.
Деструктор очереди, освобождение retained reference, гонки времени жизни,
реальное окно и игровой consumer здесь не исполняются. Отдельный прежний
replay игрового consumer не превращает эти два теста в целую живую сессию.

Отчёт:
`F:/PhoneExit Resources/Vampir/code-clues/release-terms-dispatch/bd986a7d59008d3f6fd3118f000b803955cbb8f54d8cf73db3f83bad2a27f9da/manifest.json`.
SHA256 совпадает с именем каталога. Два offline-теста проверяют матрицу и
отказ при повреждении export. Check `release-terms-dispatch` включён в workflow.

## Публичный ответ и переносимый GET plan

Один анонимный GET, обычная проверка TLS, без proxy / redirect / credentials,
timeout 10 секунд, read budget 30 секунд, лимит тела 512 КиБ:

```text
https://terms-api.netmarble.com/game/v2/thered/terms/terms_of_service_ko?country=UA&locale=en-US&termsType=I&platform=PC
```

Country UA / locale en-US / PC — явные исследовательские входы, не наблюдение
текущего аккаунта. Ответ HTTP 200, 240 байт, resultCode -1 / NO DATA.
`resultData.terms` — объект с null в title, url, required, contentExists,
useAgree, useNotice, agreeNotice, disagreeNotice, termsCode, imageContent.
Это отличается от массива BasicTerms. Ответ не меняет аккаунт и не доказывает
отсутствие условий для любых других параметров.

Snapshot:
`F:/PhoneExit Resources/Vampir/public-terms-snapshots/546b805cb1df5271d414753df4abfb9f20f996541d1f63a8bb7b07964e192382/manifest.json`.
SHA256 manifest совпадает с именем каталога; SHA тела указан внутри.

[sdk_terms.py](../../../../../vampir-shared/vampir_core/sdk_terms.py) теперь
содержит отдельный offline `plan_individual_terms_read` для no-player-ID ветви,
точного имени и termsType I. Все остальные query-входы задаются явно и проходят
прежние строгие ограничения. Сетевого вызова и individual response parser в
runtime пока нет. BasicTerms parser отклоняет individual object, сохраняя
различие форматов. Пять тестов query / JSON / source provenance прошли.

## Материалы и следующий шаг

Пути относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Экспорт | SHA256 |
| --- | --- |
| `run-006adfae88f9/details.json`, готовый individual loader | `8a17f0d348ee3ceb45424666e5f43611d6d0ffb5887fabdd07ad48f01a72897a` |
| `run-18d567ce0cd6/details.json`, dispatcher | `9b91484b0423a1b99725da19226112bbd4e8987f1cc8c79a4645698fdec0c764` |
| `run-61bf93179385/details.json`, constructor / response / thunk | `21adce1460632974a791d1e957058596d17bcb6ec04e336e3488686be04bef4c` |
| `run-870ba3c30a43/details.json`, termsType getter | `6b08dda0178d473c5daa6d4a3ef497340ad10eb91f66342967ecfeef7d4a95f0` |

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_terms_dispatch.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_terms.py
```

Далее исполнить реальную no-data ветвь `14456b510` до dispatcher с явными
HTTP / JSON / allocation fixtures и проверить error layout / context.
Отдельно проверить `1445a5f70` / `14457a520` и сохранение принятия для ветви
с доступными условиями. Только затем связывать первый SDK вход с продолжением.
State 2 не переименовывать в согласие; NID-регистрацию не повторять.
