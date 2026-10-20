# Windows: отдельное окно NID и приём callback

Обновление 20 октября: добавлен отдельный явный режим регистрации через SOCKS,
с получением кода по IMAP. Новый аккаунт вернул NID country HK и успешно прошёл
SDK SignUp / SignIn. [Запуск и ограничения](NID-REGISTRATION.md).

20 октября 2026. Добавлен WinForms / WebView2 host, который может открыть
подготовленный URL штатного входа и вернуть результат Python-клиенту.
Проверен синтетический сценарий в настоящем WebView2. Позднее запущено
настоящее окно входа. После добавления однократного заполнения формы получен
настоящий NID callback. Последующий SDK POST отклонён; подробности —
в [описании runner](NID-SDK-RUNNER.md).

## Вызов и границы

Адаптер: `nid-browser.py`, host: `windows/nid-browser.ps1` / `nid-browser.cs`.
`capture_nid_credential(plan, expected_game_code=..., data_directory=...,
timeout=300, expected_email='', sign_in_password='')` принимает `NidWebUrl` из
[проверенного builder](../resource-tools/vampir/knowledge/evidence/auth/HEADLESS-NID-WEB-URL.md).
Поддерживается первоначальный signin с webViewType=sdk и ожидаемым gameCode.
Подмена host, game scope и режима отклоняется до запуска окна.
Необязательный expected_email показывается как подсказка пользователю;
это не проверка принадлежности результата указанной почте.

При явно переданном sign_in_password helper заполняет штатную форму и один раз
нажимает Sign in with email. Без него пользователь вводит данные вручную.
Helper не получает reCAPTCHA обходным способом и не подменяет результат
серверных проверок. После callback общий parser проверяет точный
`nm{gameCode}://nmidprovider/result`, поля и channel mailUserKey. Возвращается
`NidEmailCredential`, в repr которого токены скрыты. Это provider credential,
не свежий SDK token и не готовая игровая сессия.

Результат окна имеет только локальную проверку маршрута / origin и формата.
Нет выдуманного nonce или подписи callback. Принадлежность аккаунту и принятие
credential сервером ещё должны проверяться последующим SDK sign-in.

## Как окно удерживает deeplink внутри бота

Заполнение реализовано в `windows/nid-sign-in.js`. Допуск проверяется host
и самим script: только members.netmarble.com по HTTPS с обычным портом,
`/auth/signin` и `/auth/signin/email`. Script ищет единственную кнопку
Sign in with email, поле с placeholder Email и единственное password-поле.
Иные страницы, регистрация и неоднозначные контролы не заполняются.
После input events следующая итерация проверяет значения, затем отправляет
форму. Повторной отправки после submit нет. Изменение заполненных значений
останавливает автоматизацию. Пароль не сохраняется в браузерном менеджере.

Связь со страницей опирается на наблюдённую английскую форму Netmarble и
сохранённый web contract в HEADLESS-NID-EMAIL.md: doSignInByEmail получает
email / password и штатный reCAPTCHA token. Script вызывает UI, не копирует
этот token и не исполняет внутренние helpers страницы. Это отдельный слой
собственного клиента, а не native parity или готовая регистрация аккаунтов.
DOM fixture проверяет заполнение / submit и запрет другого origin, signup
и неоднозначных кнопок. Реальные попытки подтверждают доставку NID callback.

Обработчики устанавливаются до первой навигации:

- NavigationStarting отменяет внешние схемы и передаёт подходящий callback
  внутреннему обработчику. Для настоящего режима проверяется, что текущая
  страница имеет HTTPS origin members.netmarble.com.
- LaunchingExternalUriScheme также всегда отменяется. Host не вызывает
  ShellExecute / Process.Start и не передаёт URI обработчику установленной игры.
- NewWindowRequested помечается обработанным; popups не открываются наружу.
  Downloads, запросы permissions и ошибки сертификата отклоняются.
- Навигации iframe с неподдержанной схемой отменяются. Основная web-страница
  может использовать обычный HTTPS, но callback с другого top-level origin
  не принимается.

Системные URI handlers не регистрируются и не изменяются. Реальная полнота
NID-сценария, которому могут понадобиться дополнительные окна, ещё не
проверена. Не объявлять поддержанными все внешние IDP / linking / terms flows.

Использован стандартный API отмены
[LaunchingExternalUriScheme](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2.launchingexternalurischeme?view=webview2-dotnet-1.0.3856.49).
Порядок проверяется поведением синтетического host, а не только документацией.

## Процессы и данные

Запрос с URL передаётся PowerShell через stdin, callback возвращается stdout
по анонимным pipes. URL / токены не включаются в аргументы процесса и не
пишутся в результат smoke. Stderr helper не выводится родительским адаптером.
Парсинг ошибочного результата выдаёт фиксированное сообщение без callback.

Используется отдельная явно переданная папка WebView2, InPrivate mode,
отключены password autosave, autofill, devtools и web messages. Существующий
профиль браузера не импортируется. Отдельная папка может содержать служебные
данные WebView2; это не обещание гарантированного стирания памяти или диска.
Папку runtime размещать внутри `.local/`, исключённой из Git.

Таймер окна ограничивает ожидание 1–900 секундами. Закрытие пользователем,
таймаут или ошибка процесса не считаются успешным входом. Dispose закрывает
WebView2; при зависании / прерывании Python завершает только созданное им
дерево PowerShell helper. Для следующей попытки создаётся новое окно.

## Закреплённые зависимости

На текущем ПК найдена WebView2 Runtime `155.0.4283.62`; системная установка
не менялась. SDK package `Microsoft.Web.WebView2 1.0.3856.49` получен по
официальному NuGet URL, SHA256 архива:
`bc0f76eb911b569838dc4aa8f8d325269b966bedb592863d26211aef3a099f1a`.
SHA отдельных Core / WinForms / x64 loader DLL — в
`resource-tools/vampir/webview2.lock.json`. Перед запуском адаптер их проверяет.
Архив / DLL находятся вне Git, в
`F:/PhoneExit Resources/Vampir/tools/webview2/1.0.3856.49/`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/install-webview2.py
python -X utf8 phone-exit/bots/vampir-headless/nid-browser.py --smoke
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_browser.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_web_url.py
```

Installer повторно использует DLL с совпадающим SHA и не меняет WebView2 Runtime.
Для браузерного окна нужны Windows PowerShell 5.1 x64 / STA, .NET Framework
и установленный WebView2 Runtime. Android adapter этим host не реализован.

## Фактическая проверка

Smoke создаёт невидимое окно с локальной синтетической HTML-страницей,
пытается открыть popup и внешнюю схему, затем отправляет synthetic callback.
В smoke явно разрешена локальная about/data-страница; production-путь этого
исключения не имеет. Реальные endpoints и ключи не используются.

Получены callback, две отменённые внешние навигации и один заблокированный
popup. Общий parser принял только синтетические token / ID. После завершения
не осталось WebView2-процессов с тестовой папкой профиля. Внешний игровой
URI не передавался системному handler. Отдельно прошли восемь unit-тестов:
три adapter и пять URL / native encoder. Внешний вид окна не проверялся.

Далее — согласованные реальные настройки NID и первый вход через это окно,
штатное подтверждение устройства, SDK request / response и передача свежих
данных в уже подготовленный LoginFlow. Успешный smoke не заменяет эти этапы.
