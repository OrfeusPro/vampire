# Узкий текущий контракт SDK Fetch

Source SHA256:
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
База Fetch: `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Это статическая проверка запроса и более узкой локальной политики ответа.
Выполнения native Fetch, полного error dispatcher и допуска игрового входа нет.

Готовые whole exports `run-74606681db58` используются повторно:
request `0x1444e7b80`, 621 инструкция; response `0x1444c9c80`, 667 инструкций.
Инспектор сверяет полные unwind ranges и исходные bytes двух EXE, форму всех
инструкций / локальных ветвлений, CRT import `_wtoi`, адреса данных и вызовов.
Одного совпадения формы недостаточно: семь дополнительных окон инструкций
проверяют credential virtual `+8`, две пары JSON, authUrl lookup, endpoint,
callback и transport, errorCode, HTTP range и optional resultData.

## Подтверждённое представление запроса

`credential` берётся через virtual `+8`, его результат становится значением
первой пары. Global `0x14b564ba0` связан с ключом `credential` уже проверенным
current Launcher initializer. Вторая пара — global `0x14b564c10` и строка
`channel` по `0x1495320a0`. Object builder `0x1444c2530` получает ровно эти
две пары. Аппаратные поля в этот body не добавляются.

`scope` проверяется отдельным явным фрагментом initializer `0x1411b0620`:
39 байт, семь инструкций, RCX global `0x14b564c10`, RDX UTF-16 literal `scope`
по `0x14952e0d0`, constructor `0x141426b90`, E9 в `0x1487ec32c`.
Это **не** whole export initializer и не исполнение CRT cleanup. Прежний отказ
Ghidra на выходе из unwind ranges сохранён; проверка не отключалась.

Lookup `authUrl` использует строку `0x149531c80`. К полученной базе добавляется
UTF-16 `v1/fetch-player` по `0x1495320b0`. HTTP wrapper `0x144522df0` совпадает
с transport текущего Launcher token; object builder, serializer, config getter
также связаны точными адресами с существующим 14-root Launcher report.
Обычные SDK headers `gameCode` / `buildCode`, NID channel 33, конфигурация и
геоконтекст сохраняют отдельные доказательства SDK-пакета из 3667 случаев.
Этот пакет их заново не исполняет. Runtime по-прежнему обязан проверить весь
immutable SDK-профиль, а не только ссылки этого статического отчёта.

## Ответ и границы

Request callback `0x1444deed0` содержит точный E9 в выбранный response root
`0x1444c9c80`; другой похожий response не подставляется. Проверены ссылки на
`errorCode` / `resultData`, getter calls, `_wtoi`, ветвление HTTP 200–206 и
optional object resultData. Native nested identity, error object construction,
owner / callback lifetime и dispatcher здесь не воспроизводятся.

Локальный Fetch parser строже: принимает только явный нулевой errorCode и
объект resultData, отклоняет неоднозначный JSON и возвращает только безопасный
`SdkFetchSummary`. Ни access token, ни player ID, ни SDK-сессию он не возвращает.
Native JSON implementations и credential provider связаны с прежними областями
доказательства; этот отчёт не превращает их во вновь исполненный native Fetch.

`contract_subset_verified=true` относится только к этому read-only subset.
`native_execution=false`, `runtime_admitted=false`, `profile_activated=false`.
Создание SDK-профиля, Terms / SignUp, direct SignIn, launcher Fetch, lobby,
персонажи и мир этим контрактом не разрешаются. Ненулевой Fetch ответ не
разрешает автоматически менять аккаунт или принимать условия.

## Воспроизведение

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-sdk-fetch-current.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_fetch_current.py
```

[Контекст](../../native-contexts/sdk-fetch-current.json) закрепляет два EXE,
три готовых exports, все значения и окна инструкций, Launcher / SDK proofs.
Инспектор сохраняет неизменяемый report в
`F:/PhoneExit Resources/Vampir/code-clues/sdk-fetch-current-static-v1/`.
Четыре проверки: настоящий source contract, отказ изменённого source/evidence,
отказ повреждённого scope fragment и отказ неприкреплённого context до rebuild.
Реальной авторизации и HTTP в них нет.

API `verify_report(report_path, root=..., workspace=...)` перед публикацией
Fetch-only пакета проверяет content-addressed путь отчёта, точный путь и SHA
контекста в workspace, заново исполняет статический audit и требует полного
равенства результата. Runtime должен проверять прикреплённые inputs без импорта
анализатора. Теперь это выполняет отдельный
[Fetch-only loader](HEADLESS-SDK-FETCH-READ-ONLINE.md), с собственным профилем и
одной операцией; исходные Launcher guards сохранены.

Сбор готовых тел, исходный initializer blocker и старый bounded Fetch-контракт:
[материалы](HEADLESS-SDK-FETCH-CURRENT-COLLECT.md),
[прежний контракт](HEADLESS-RELEASE-FETCH-CONTRACT.md).
