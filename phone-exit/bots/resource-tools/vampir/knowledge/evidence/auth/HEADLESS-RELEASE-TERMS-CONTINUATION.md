# Условия → выбор канала → первый SDK SignUp

23 октября 2026. SHA256 EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [Fetch-контракта](HEADLESS-RELEASE-FETCH-CONTRACT.md).
Реальные окна условий, HTTP и создание SDK-профиля не запускались.

## Связь с SignUp теперь замкнута

Individual-terms callback `145604f00` при raw state 2 вызывает сохранённый
delegate owner `+a8` через virtual slot `+60`. Native vtable `14990d430`
задаёт bridge `14560b130`, который передаёт storage `+18` в `145605cf0`.
Для raw state 3 используется owner delegate `+b8`, vtable `14990d498`,
bridge `14560aff0` → closure `145606690` с исходным результатом.

Success closure `145605cf0` получает service CDO и выбирает пару:

- CDO отсутствует либо predicate `144532190` возвращает AL=1:
  Guest channel 100 / SignUpForGuest step 12.
- Иначе: Netmarble channel 33 / SignUpForNetmarble step 13.

`144532190` исполняется реально: он проверяет прежний SDK channel byte `+88`.
Только channel 100 вместе с пустым idpInfo container `+90` даёт AL=1.
Количество idpInfo возвращает явный fixture `144479cb0`.
Нет CDO — отдельная native ветка, а не найденная идентичность аккаунта.
Боту не следует молча выбирать Guest при отсутствии данных реального аккаунта.

Далее вызывается `14561b940`, который создаёт callback descriptor с step и
передаёт channel в `1445077d0` → `144507850`.
В обычной ветке manager вызывает `144506c20`; этот wrapper непосредственно
передаёт credential shared pair в **`144506cf0` — текущий FAuthImpl::SignUp**.
Его body / keys уже сохранены в
[текущем SignUp](HEADLESS-RELEASE-SDK-SIGN-UP.md) и
[initializers](HEADLESS-RELEASE-SIGN-UP-KEYS.md).
Новый формат HTTP body здесь не придуман и не реконструируется заново.
Launcher channel 200 имеет отдельную ветку и другой backend; она не считается
эквивалентом NID channel 33.

Это создание игрового SDK-профиля после условий, а не повторная регистрация почты
Netmarble и не создание персонажа. Успешный SignUp callback шага 13 затем
продолжает SignIn channel 33 / step 15 по ранее сохранённому `145605440`.
Полный HTTP lifecycle и ответ настоящего сервера этой цепочкой не исполнены.

## Целая native цепочка: 99 сценариев

[replay-release-terms-continuation.py](../../../replay-release-terms-continuation.py)
использует прежний bounded harness и исполняет:

1. Целый `145604f00`, включая weak owner pin и проверку привязки delegate.
2. Реальные source-bound vtables и оба virtual bridge.
3. Целые success / error closures `145605cf0` / `145606690`.
4. Настоящий classifier `144532190` и result getter `141a2d1b0`.

96 комбинаций: шесть профилей SDK CDO / прежнего канала / idpInfo,
четыре raw UI state 0 / 1 / 2 / 3, bound / unbound и два result code.
Дополнительно три owner gate — null control, expired count, null owner.
Итого 99. При возврате strong count совпадает с исходным 4.

- Raw state 2 и непустая привязка дают 12 SignUp handoff captures:
  четыре Guest 100 / step 12 и восемь Netmarble 33 / step 13.
- Raw state 3 с кодом `0x1ca06be` вызывает повтор individual terms;
  другой код ведёт к error text / message selector 20.
- Иные состояния и отсутствие привязки не передают SignUp.
- Недоступный owner не производит внешних действий.

Service holder / CDO acquisition, idpInfo count, SDK handoff, UI / logging и
tracked lookup — fixtures / captures. Менеджер считает owner уже добавленным;
insertion / growth его массива не исполняются. Финальные destructors при count 1,
гонки и настоящий scheduler не покрыты. Неизвестный вызов останавливает replay.

`EUIViewState` не найден в текущих PE reflection descriptors. Поэтому raw state 2
не переименован в «пользователь принял условия». Его синтетическая установка
проверяет переход в коде, а не происхождение реального ответа окна.
Без проверки фактического завершения UI продолжать SDK SignUp автоматически нельзя.

Два теста проверили source-bound виртуальный путь, classifier / owner lifetime,
точные пары channel / step и отказ изменённого export.
Check `release-terms-continuation` подключён к общему workflow.

## Подготовка реального окна: что найдено и что остаётся

Individual Show `1445ac980` → `1445a8590` сохраняет callback, список и flags,
затем `1445a1100` начинает получение данных. При пустом сохранённом player ID
есть отдельный путь `1445a0100`; он не объявлен простой успешной заглушкой:
полный экспорт содержит собственные запросы / проверки.

Basic Terms loader `14459f770` получает `termsUrl` по ASCII literal `149548088`.
Статически найдены UTF-16 ключи query `country`, `locale`, `platform`.
Источник country — `144584210`, locale — `143d1d470`, platform — settings `+28`.
В зависимости от settings используются шаблоны:

```text
{0}/game/v2/{1}/terms?{2}
{0}/game/v2/{1}/terms/filtered/unique?{2}
```

Текущий callback pointer `1445744b0` и HTTP wrapper `144522040` передаются
после сборки URL. Метод wrapper, полная query encoding и parser ответа пока
не доказаны этим разбором. Имя метода HTTP не выбирается по предположению.
Individual loader использует отдельный ASCII ключ `agreementUrl` и собственный
callback. Отсутствие player ID не позволяет пропустить обе цепочки по названию.

Следом проверить только `144584210`, `143d1d470`, `144522040` и target
basic terms callback `1445744b0`: установить входы URL / HTTP / ответ и переход
к реальному состоянию завершения. Затем добавить явный первый игровой вход
с тем же свежим NID credential и результатом условий. Перерегистрацию NID и
fallback SDK SignUp после обычного launcher 1203 не добавлять.

## Материалы

Ghidra-пути относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-3a0991b1f1c8/details.json`, virtual bridges / terms impl | `20a5532389041914f37cfc5236a9c9a50facdc0697d2aca5888f03f97e85e8b4` |
| `details/run-c558937a4554/details.json`, closures / Individual Show | `b3c2261d213515546d75e43e53b4521a2130815a106a854c6a9b9efb7ea54750` |
| `details/run-57ea578ebe47/details.json`, classifier / SignUp caller / Individual loader | `c281575496f53eda31722eb828dfe6c8125bb600a4e268c92e44a5ae4b5537b3` |
| `details/run-f8758b34d5e4/details.json`, SignUp manager / wrapper | `963b92de3bc9c758911e6f797ade0668306998c1ea41a2a3aeac2446151cfdd1` |
| `details/run-006adfae88f9/details.json`, Auth SignUp wrapper / terms loaders | `8a17f0d348ee3ceb45424666e5f43611d6d0ffb5887fabdd07ad48f01a72897a` |

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-terms-continuation/595612a2a11e90619462a020c1aa148721b960f27fe453e52528ffac1c5ce98b/manifest.json`.
SHA256 совпадает с именем каталога. Отчёт сохраняет exports, инструкции,
tool / dependency SHA, fixtures, 99 случаев и ограничения.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-terms-continuation.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_terms_continuation.py
```
