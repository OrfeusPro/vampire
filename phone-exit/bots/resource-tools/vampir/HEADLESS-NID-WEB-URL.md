# NID: сборка URL штатного окна входа

20 октября 2026. Контекст из [предыдущего этапа](HEADLESS-NID-WEB-CONTEXT.md)
можно связать с явной SDK-константой authWebViewUrl. Добавлен полный URL
для первоначальной signin-ветви в поддержанном printable ASCII-профиле.
Это подготовка адреса, не выполнение браузера или авторизации аккаунта.

## Источники и native-проверка

Клиентский EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4: 277 функций, 111 сохранённых предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-6c90c326c6af`.
SHA256 манифеста:
`d95428150e79fb2de2f18f56c14b7a7bf0008f98ad88eda2d2377a21ba1fff13`.
SHA256 `functions.json`:
`c81c6c107ac675b5f3ad8d67c318075f1e288d44ef44998dfdfafee7c6340fc9`.

Вызов serializer `0x144586a30` использует encoder `0x141c13850` для значений,
формат `{0}={1}` и разделитель `&`. В caller после base authWebViewUrl
добавляется `?` и полученный query. Это статическая связь по Ghidra и
проверенным литералам. Базовые пары уже проверены исполнением отдельно.

Новый `replay-nid-query-encode.py` исполняет весь цикл encoder, а также
настоящие whitelist `0x141c06750` и uppercase hex `0x1415ad670` из
[прежнего исследования формы токена](HEADLESS-AUTH.md). Их код / таблицы
повторно проверяются по bytes и SHA. Whitelist инициализируется настоящим
кодом в явно обнулённом BSS fixture.

99 профилей: каждый printable ASCII-символ, пустая строка, все эти символы
вместе, строка с разделителями и hex-строка. Результаты совпали с уже
существующим `_escape_ascii`; новый runtime переиспользует его.
Пробел → `%20`, плюс → `%2B`, амперсанд → `%26`, процент → `%25`.
Неэкранированными остаются только `A–Z`, `a–z`, цифры и `-._~`.

Reserve / append FString и однобуквенная ASCII-конверсия `0x141440af0` —
ограниченные fixtures. Сам цикл и выбор escaping исполняются native.
Полное преобразование UTF-16 / UTF-8, supplementary characters и весь
map serializer здесь не исполнялись. Не объявляется побайтно проверенным
порядок обхода Unreal map; runtime сохраняет явный порядок пар контекста.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/nid-query-encode-replay.json`.
SHA256: `d41613d3037669fb0f39f2b7472f7fe2e9894895e9a8e858929689651bedb678`.
Сохранены native fragments, leaf / table proofs, исходные SHA и результаты.
В отчёте только искусственные данные; настоящие ключи не использовались.

## Runtime

`vampir_core.nid_web_url.bind_nid_web_url(context, constants=..., max_url_size=...)`
возвращает immutable `NidWebUrl`. Поле url скрыто в repr. Не выводить сам
адрес в журнал: query содержит идентификаторы устройства.

Требуются ровно 12 проверенных параметров исходного контекста, nidV=3,
authType=signin и поддержанный webViewType. Дубликаты / посторонние поля,
linking-режимы, пустые обязательные значения, controls и Unicode отвергаются.
Пустые допустимые поля остаются `key=`. Общий размер URL ограничен явным
byte budget. Граница ASCII — заявленный поддержанный профиль; никакого
молчаливого удаления или неправильного кодирования Unicode нет.

authWebViewUrl берётся существующим SDK lookup и должен совпасть с
`https://members.netmarble.com/auth`, найденным в
[публичном GMC2](HEADLESS-PUBLIC-GMC2.md). Тест повторно проверяет snapshot
SHA и декодирует старый SDK-ответ, без нового запроса. Изменение endpoint
требует сверки источника. Host / userinfo / query / fragment не подменяются
непроверенными значениями вместе с device context.

## Следующая граница реального входа

URL ещё не открывался. Нужно связать активные значения остальных настроек
и доставку результата штатного окна в бот. Для webViewType=sdk страница
может использовать custom scheme `nm{gameCode}://nmidprovider/result`;
его следует принять в окне бота без передачи обработчику установленной игры.
Регистрация / подмена системного protocol handler не выполнялась.

Нужны штатные reCAPTCHA / проверки профиля, распознавание device challenge
и последующий SDK sign-in. URL builder не обходит эти этапы и не выдаёт
provider token за SDK accessToken. Реальная сессия остаётся открытой задачей.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-query-encode.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_web_url.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_web_context.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_auth.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Все 16 выбранных тестов прошли: пять URL / encoder, три web context,
пять прежних auth и три provenance Ghidra. Новых сетевых запросов нет.
