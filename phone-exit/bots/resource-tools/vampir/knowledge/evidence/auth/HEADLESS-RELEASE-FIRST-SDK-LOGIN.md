# Первый SDK-вход: Fetch, условия и отдельный профиль игры

23 октября 2026. Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [ответа индивидуальных условий](HEADLESS-RELEASE-INDIVIDUAL-TERMS-RESPONSE.md).
Новый режим не регистрирует Netmarble заново и не создаёт персонажа.

## Связь Fetch с challenge

Готовый полный `1444ca990` использован повторно. Он проверяет success getter
`144532750`, а при false — `141639d50`. Последний — целый leaf
`0fb64120c3`: чтение byte `+20` / ret. Это признак присутствия тела, поэтому
HTTP-ошибка с телом не обязательно заканчивает native-разбор до JSON.
Leaf проверен по текущим байтам без Ghidra и без предположения по имени.

В JSON-ветви Fetch читает errorCode через string / `_wtoi`. Ненулевой код
передаётся конструктору `144517fd0` как context с domain 0, base 30050000,
step 27. Итоговый code `+c` равен **30050027**; context сохраняет errorCode.
Ранее целый игровой Fetch callback проверил сочетание code 30050027 / context
1203 и переход к BasicTerms. Это связь конкретного Fetch-ответа, не любого
отказа launcher SignIn 1203. HTTP / JSON / CRT Fetch целиком новым native replay
здесь не исполнялись; новая проверка этой связи статическая.

Готовый текущий Auth SignUp `144506cf0` подтверждает четыре поля контекста
и credential, POST `v1/sign-up`. Готовый callback `145605440` для step 13
при успехе вызывает SignIn channel 33 / step 15. Это статическое основание
последовательности нового runtime, не доказательство успешного живого SignUp.

## Отдельный runtime

[sdk_first_login.py](../../../../../vampir-shared/vampir_core/sdk_first_login.py):

1. Один свежий Fetch. Успешный marker ведёт к SignIn без условий и создания.
2. Только Fetch HTTP 400 с canonical numeric errorCode 1203 допускает продолжение.
   Остальные ошибки заканчивают операцию. Этот поддерживаемый subset строже native.
3. Анонимный BasicTerms GET. Продолжение только для resultCode -1 / пустого массива.
4. Анонимный IndividualTerms GET для `terms_of_service_ko` / type I. Продолжение
   только для -1 и текущего объекта из десяти null-полей.
5. Один SDK SignUp, затем SignIn после подтверждённого player ID. Новый SignIn
   должен вернуть тот же player ID; несовпадение отклоняется.

Доступные условия, code 0 даже с пустым массивом, неизвестная схема, transport /
JSON failure и неоднозначный результат создания останавливают выполнение.
Автоматических повторов нет. Новый отдельный запуск начинает с Fetch, чтобы
заново проверить наличие профиля. Неизвестный исход SignUp не выдаётся за успех.

Страна, locale и ветвь BasicTerms задаются явно. Native culture / settings
автоматически не читаются и не угадываются. Прежний NID / launcher SignIn
не переключается в этот режим по ошибке. Панель аккаунтов пока его не запускает.
NID-регистрация, игровой Login и команды персонажу здесь отсутствуют.

[sdk_terms_http.py](../../../../../vampir-shared/vampir_core/sdk_terms_http.py)
выполняет один GET только на точный HTTPS terms origin и канонический URL плана.
В запросе нет credentials / cookies / SDK headers. Обычная проверка TLS,
нет proxy по умолчанию и redirects, сохраняется явно заданный SocksRoute.
Timeout 10 секунд, read budget 30 секунд, лимит 512 КиБ; encoding / declared
length / фактический размер проверяются. Ответы в runtime не сохраняются.

Individual summary требует текущие десять полей; no_data допускает только null
в каждом. Code 0 возвращает безопасный marker terms_available, на котором flow
останавливается. Тексты / ссылки / identity наружу не возвращаются. Consent
остаётся false. HTTP errorCode parser дополнительно отклоняет NaN / Infinity.

## Запуск и проверки

В [run-nid-sdk-sign-in.py](../../../../../vampir-headless/run-nid-sdk-sign-in.py)
добавлен явный режим с current source profile и свежим SdkInputs. Он несовместим
с отдельным Fetch, прямым SignUp и launcher flow. Входы проверяются до открытия
NID, свежесть контекста повторно проверяется перед каждым сетевым этапом.

```powershell
python -X utf8 phone-exit/bots/vampir-headless/run-nid-sdk-sign-in.py --email nightraven@vampir.top --profile recovered-release --first-sdk-login --terms-country UA --terms-locale en-US --basic-terms-mode all --password-stdin
```

UA / en-US / all — явные исследовательские параметры, не считанные настройки игры.
Пароль передаётся через stdin, не в аргументах процесса. Есть также
`--basic-terms-mode filtered-unique`; отсутствие любого выбора отклоняется.

12 новых offline-тестов покрывают очередность операций, точный challenge,
существующий профиль без SignUp, остановку на доступных условиях, один неизвестный
исход создания, несовпадение player ID, отсутствие query-входов, HTTP error JSON,
анонимные GET, лимиты и различие response shapes, а также current source provenance.
Дополнительно прошли 9 NID runner, 6 SDK HTTP, 7 launcher, 4 Fetch и 5 terms tests:
всего **43 теста**. Авторизаций и игровых действий в них нет.
Check `release-sdk-first-login` запускает 12 новых тестов; прочие наборы
проверены отдельно.

## Живая проверка и границы

Перед попыткой не было процессов игры или account worker. Для одного
подготовленного `nightraven@vampir.top` пароль прочитан через DPAPI из SQLite
в read-only режиме, без вывода. Прямой выход, current profile, указанные выше
явные query-параметры. Автозаполненный NID вход остановился до Fetch.
Одна отдельная повторная попытка после завершения первой также дала:
`login_failed`, шаг `submitted`, NID HTTP 400, numeric code отсутствует,
response observation `no_numeric_code`.

Ни одна попытка не вызвала Fetch, terms GET, SDK SignUp или создание персонажа.
Текст отказа, password, response body и tokens не сохранялись. Причина NID 400
не изолирована; успешный живой первый SDK-вход не заявляется.
Следующая живая проверка начинается с диагностики NID; при его успехе уже
подключена отдельная проверяемая цепочка первого SDK-входа.

## Источники

Полные exports относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Export | SHA256 |
| --- | --- |
| `run-3380a52fff6d/details.json`, Fetch response | `7b0307a30a6cc0b33c1149c956e12a0c822fa8f54a6b4299fbd07c429ad518aa` |
| `run-8c0479e8b8bd/details.json`, actual constructor | `c0e9b7937e1d716ecbf03759a5449a60a2f7e4e7fee46fda852643067b4d1cd5` |
| `run-313ff5f10ab1/details.json`, game Fetch / SignUp callbacks | `d376e82c676025619f3973f6ba86389e192bb85b48223a76d46529d9b914756e` |
| `run-429315d23bfb/details.json`, current Auth SignUp | `05607a1578f1907e7033e4a3708bee08ed0b64d9f3a13263dd6928f837e65522` |

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_first_login.py
```
