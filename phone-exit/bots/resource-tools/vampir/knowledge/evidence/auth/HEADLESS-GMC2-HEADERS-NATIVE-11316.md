# Выполнение GMC2 headers в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки URL](HEADLESS-GMC2-URL-NATIVE-11316.md).
Capstone 5.0.6 / Unicorn 2.1.4; сохранённый EXE, синтетическая память.
HTTP-запросы, авторизация и процесс игры не используются.

## Исполнение

`replay-gmc2-headers-11316.py` повторно использует готовые source-bound exports.
Новый запуск Ghidra не понадобился. Исполняются whole GMC2 constructor
`0x1444c4210`, три build initializers, whole build getter `0x1445320c0`
и header slice RequestGMC2 `0x1444fbe00` → `0x1444fc051`.
Выбранные шесть функций проверяются по четырём полным SHA exports и EXE.
Непроверенный адрес исполнения отклоняется общим harness.

В синтетическую HTTP vtable установлены capture methods +0x68 (URL),
+0xb0 (header), +0x60 (method). Проверяются receiver, destinations,
единственность URL / method, границы FString и termination.
Настоящий constructor задаёт имена заголовков; capture не подставляет их.

У общего harness исправлен учёт уже выделенных scratch pages: установка
capture fixture внутри synthetic memory больше не пытается отобразить эту
страницу повторно. Четыре URL-теста после изменения прошли; актуальный replay
URL снова получил те же результаты в 27 случаях.

## 73 сценария

Матрица: четыре build codes 0 / 1 / 2 / 255 × три ETag (пустой, один символ,
несколько символов) × три access token (пустой, один символ, несколько символов)
× два player ID (пустой / synthetic). Дополнительно проверен public production
вариант с пустыми account / device данными. Все аргументы совпали с
`plan_gmc2_get_request`, включая порядок headers.

| Параметр | Результат |
| --- | --- |
| Method / URL | GET / переданная строка URL |
| Первые headers | Content-Type: application/json, Accept: application/json |
| Обязательные поля | serviceCode, gameCode, buildCode, nmDeviceKey |
| Build 0 / 1 / 2 / 255 | A / B / C / A |
| Непустой ETag, включая один символ | eTag добавлен |
| Пустой ETag | eTag отсутствует |
| Непустой access token, включая один символ | playerId и accessToken добавлены |
| Пустой access token | Оба account headers отсутствуют независимо от player ID |

Проверены canaries manager до / после constructor и число вызовов player getter
fixture: один при непустом token и ноль иначе. Пустой nmDeviceKey сохраняется
как пустой обязательный header. Ни device identity, ни player ID не генерируются.
Production capture содержит ровно шесть headers, без account credentials.

## Fixtures и границы

HTTP methods только записывают аргументы. Class/CDO, FString storage / allocation,
memcpy/free и регистрация завершения — ограниченные fixtures. Device getter
`0x1444ec890` и player getter `0x14452b620` возвращают только явно заданные
синтетические / пустые значения. Их собственные bodies не исполнены.
Account classes `0x1444b1430` / `0x1444b1550` также fixtures.

Не проверялись request creation, TLS / console gates до slice, сериализация /
transport HTTP, активный startup, серверная совместимость и авторизация.
Результат подтверждает аргументы текущего header slice для перечисленных
входов, а не реальную отправку запроса. Полный SDK profile ещё не сформирован.

## Материалы и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-gmc2-headers-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gmc2_headers_11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gmc2_url_11316.py
```

Три header-теста проверяют все 73 результата, порядок / gates / canaries,
а также отклонение изменённых EXE и export. Вместе с четырьмя URL-тестами
прошли семь тестов. Отдельный registered check — gmc2-headers-native-11316.
В release-update-targets.json RequestGMC2 помечен с точной границей slice,
новой проверкой и явными device/player/HTTP fixtures; whole Request не заявлен.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Headers replay: `code-clues/gmc2-headers-11316/c584aa6b57b1c6408d01b8d137fc86a1b448a19273ffba5a5600087ef6926007/manifest.json`.
- Повтор URL с текущим harness: `code-clues/gmc2-url-11316/265a47ec3dc9994169d3b1830a98bb422248d77e5fa27e103a4ea2cb07ab8129/manifest.json`.
- Четыре exports с SHA перечислены в [предыдущем доказательстве](HEADLESS-GMC2-URL-NATIVE-11316.md).

Далее найти и исполнить текущий platform initializer / getter. Затем собрать
новый source-bound SDK profile из актуальных native reports; живой вход и
совместимость auth parsers остаются отдельными проверками.
