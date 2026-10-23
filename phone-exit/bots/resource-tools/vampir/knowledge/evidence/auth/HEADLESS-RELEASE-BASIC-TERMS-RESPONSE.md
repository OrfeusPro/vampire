# BasicTerms: GET, NO DATA и граница согласия

23 октября 2026. Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [перехода после условий](HEADLESS-RELEASE-TERMS-CONTINUATION.md).
Новые авторизации, принятие условий и SDK SignUp не выполнялись.

## Входы запроса

`144584210` начинает с country getter `144529870`. Если predicate
`1445326c0` даёт true, значение заменяется строкой из SDK getter `14452ba00`.
Иначе при наличии строки settings `+a0 / count +a8` используется запасная
строка `+b0 / count +b8`. Имена всех этих полей в рамках данного прохода
не доказаны; нельзя подставить joined country в каждую ветвь по одному имени.
Этот helper не исполнялся native-сценарием и в runtime не копируется целиком.

`143d1d470` уже имел полный экспорт: он получает culture object через
`1414833f0`, затем getter `1414886d0` и копирует результат. Это источник locale;
преобразование конкретной культуры и её актуальное значение не считаны из игры.
Существующий экспорт использован повторно без Ghidra.

`144522040` → `1445220d0`. Diagnostic последнего точно называет
`FNetworkManagerImpl::CreateGet`; query / headers и callback передаются через
эту обёртку. Следовательно, BasicTerms loader использует GET, а не SDK POST.
Это также уточняет ранее открытый метод wrapper launcher/fetch-player;
весь его контракт и ответ по одному совпадению wrapper не считаются готовыми.

BasicTerms callback pointer `1445744b0` — leaf `e9bb63ffff` в root `14456a870`.
Первый collect оставил leaf в очереди: нет однозначного unwind root. Следующий
явный request получил реальный root; полный экспорт сохранён.

## Ответ и особая ветка -1

Текущие initializers подтвердили имена глобальных ключей:

| Initializer | Global | Literal | Значение |
| --- | --- | --- | --- |
| `1411b74a0` | `14b566760` | `14952d348` | resultCode |
| `1411b74d0` | `14b5667a0` | `14952d3b0` | resultData |
| `141258fb0` | `14b5e84e8` | `14985b958` | terms_of_service_ko |

Последняя строка — явно передаваемое имя индивидуальных условий из игрового
callback. Это не язык окна и не общее обозначение всех условий.

В `14456a870` сначала проверяются ответ / JSON object и наличие resultCode /
resultData. Затем integer getter `14447d9a0`:

- `resultCode == -1`: создаётся error result с контекстом -1 и вызывается
  `144580990(content, 2, result)`. Это отдельная ветка raw UI state 2.
- `resultCode == 0`: читается `resultData.terms`, строятся записи условий,
  затем продолжается отдельная обработка контента.
- Другие коды / неправильный JSON имеют error path.

Тело parser и UI dispatcher статически разобраны, но целиком native replay
не исполнялись. В предыдущем replay raw state 2 задавался синтетически. Теперь
установлено хотя бы одно его происхождение из реального формата ответа: NO DATA,
при этом исходный result остаётся ошибкой. Поэтому state 2 сам по себе нельзя
переименовать в «пользователь согласился» или считать zero result.

## Публичное наблюдение

Свежая публичная GMC2-конфигурация, без учётных данных, вернула HTTP 200 и
`termsUrl=https://terms-api.netmarble.com`,
`agreementUrl=https://apis.netmarble.com/agreement-rest`.
Затем выполнен один анонимный GET по установленному URL-шаблону:

```text
https://terms-api.netmarble.com/game/v2/thered/terms?country=UA&locale=en-US&platform=PC
```

Country UA, locale en-US и PC здесь выбраны явно для исследования; равенство
реальному текущему native query не заявляется. Обычная проверка TLS, без redirect
и proxy, timeout 10 секунд / read budget 30 секунд / body limit 512 КиБ.
Ответ HTTP 200, 69 байт:

```json
{"resultData":{"terms":[]},"resultCode":-1,"resultMessage":"NO DATA"}
```

Публичный snapshot вне Git:
`F:/PhoneExit Resources/Vampir/public-terms-snapshots/e6d785c67906b5aa06b0f5ba0a85ec2f03c6fa3374cdc67a12ae7f72b0cfa712/manifest.json`.
SHA256 manifest совпадает с именем каталога; body SHA сохранён в нём.
Это результат только указанного query, не доказательство отсутствия условий
для любой страны / версии / аккаунта. Серверный ответ не изменил аккаунты.

## Подготовленный runtime subset

[sdk_terms.py](../../../../../vampir-shared/vampir_core/sdk_terms.py) добавляет только
offline GET plan и строгий parser безопасного summary. Нет сетевого вызова,
открытия окна, согласия или автоматического SDK SignUp.
Поддерживается точный публичный production termsUrl, явные game code / ISO country /
locale / PC / filtered branch. Query строится стандартным urlencode;
локальные ограничения строже native и не воспроизводят все его значения.

Parser требует integer resultCode, object resultData, terms array до 256 объектов,
строгий UTF-8 / JSON без дубликатов и NaN. Возвращает `no_data` для -1 с пустым
массивом, `empty` для 0 с пустым массивом, `terms_available` для 0 с записями.
Содержимое / URL / текст условий не возвращаются. Для всех summary
`consent_confirmed=False`, `sdk_creation_ready=False`.
Остальные / неоднозначные ответы останавливают обработку.

Четыре теста проверяют URL и ограничения query, разделение -1 / 0, отказ
повреждённого JSON, отсутствие identity в summary и текущий source provenance:
полный SHA EXE, SHA экспортов, байты инструкций, ключи и E9 callback.
Это **статическая проверка**, не новый native replay parser / UI.
Check `release-sdk-terms` подключён к общему workflow.

## Материалы и следующий шаг

Ghidra-пути относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-b3245757b183/details.json`, country / HTTP wrapper | `c3598cec6dd815f76ffa191424a096af5cedfe94f5d74ed7e5301c35e69a626c` |
| `details/run-4855ed8063c4/details.json`, GET impl / terms response | `363d3050bc6cf769014003e267ca2226e51caa4e9817f6e612c03db7633745aa` |
| `details/run-ac97599e2191/details.json`, три initializers | `81ff7f6647afcd199648e8951c39ca30fb4e13b30d70a2487d926af2d0a441bf` |
| `details/run-56052032a1e9/details.json`, ранее готовый locale helper | SHA указан в общем индексе; helper не включён в новый claim native execution |

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_terms.py
```

Далее `144580990` (передача UI state / результата), `1445a0100` (запрос
индивидуальных условий без player ID, полный экспорт уже есть) и его callback.
Нужно проверить, как отсутствие basic terms сочетается с обязательными
individual terms `terms_of_service_ko`, где сохраняется подтверждённый результат
и можно ли затем продолжить первый SDK SignUp. До этого summary не даёт
разрешения пропускать условия; NID-регистрация не повторяется.
