# Авторизация, устройство и metadata

## Установлено

Реальный тестовый аккаунт проходит NID / SDK sign-in; SDK сообщает joined country
HK. Для runtime хранятся отдельные NMDeviceKey / NIDDeviceKey / SDKDeviceKey.
Выход JP, страна аккаунта и выбранный регион — разные параметры.
[Реальная проверка](../evidence/network/HEADLESS-FRANZ2-LOGIN.md).

Metadata collector и writer разобраны в bounded сценариях: известны ключи,
порядок обращений и связь 33 полей с ключами. Factory / owner создают 37 пустых
строк. Save после player ID — сохранение settings; SendSignIn — событие журнала.
[Поля](../evidence/auth/HEADLESS-NID-USER-INFO-FIELDS.md),
[factory](../evidence/auth/HEADLESS-NID-OWNER-FACTORY.md),
[событие](../evidence/auth/HEADLESS-SDK-SIGN-IN-LOG-PRESENT.md).

## Открыто

У launcher credential подтверждён отдельный channelCode 200 и базовый GetObject;
найдены запросы launcher/token и launcher/sign-in. Ключ заголовка launcherToken
установлен; первый ответ имеет строковый resultData, второй — объект SDK sign-in.
Внутренний канал берётся отдельно из credential+0x68. Native-маршрутизация
подтвердила SignInByLauncher для канала 200 и отдельный GetLauncherToken
с существующим credential, включая NID 33. Реальный launcher-токен и последующий
SDK sign-in приняты через два JP-телефона и HK; Game Login получил 58 / BlockedIp.
После новой замены телефонов launcher flow принят SDK, но Game Login на новом JP
вернул 16 / InvalidState. Изменение auth flow не устранило этот отказ.
21 октября официальный клиент на том же выбранном JP вошёл в мир после создания
Okly; бот после закрытия игры снова получил 16. Три ключа устройства совпали
с текущим Windows-хранилищем. Остальной игровой контекст ещё не сопоставлен.
[Реальная проверка](../evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md).

Источник первоначального заполнения common data, их значения перед Login,
обязательность metadata на сервере и различие SDK-only / launcher context.
Реальный отказ Game Login 16 не доказывает причину. Не расширять replay журнала
без статической связи с записью данных или недостающим полем Login.
Текущие вопросы: login-invalid-state / common-data-population в
[questions.json](../questions.json).

Credentials и локальные профили не переносить в документацию; новый device key
не генерировать при обычном повторе входа. Установленные роли сначала искать
в [реестре](../../../../vampir/FUNCTION-INDEX.md).

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Vampir — начало восстановления SDK авторизации](../evidence/auth/HEADLESS-AUTH.md)
- [ChannelManager silent: переход к Auth и обязательный player ID](../evidence/auth/HEADLESS-CHANNEL-SILENT-HANDOFF.md)
- [Первый SDK-вход из панели аккаунтов](../evidence/auth/HEADLESS-CONSOLE-FIRST-SDK-LOGIN.md)
- [Windows SDK: постоянные device keys](../evidence/auth/HEADLESS-DEVICE-IDENTITY.md)
- [Device keys: native getter branches](../evidence/auth/HEADLESS-DEVICE-LIFECYCLE.md)
- [SetDeviceKey: сравнение, запись и изменение settings](../evidence/auth/HEADLESS-DEVICE-SETTER.md)
- [Первый SDK-вход подтверждён; безопасные подсказки NID](../evidence/auth/HEADLESS-FIRST-SDK-LIVE-AND-NID-HINTS.md)
- [Игровой AutoSignIn: привязка callback и ветви результата](../evidence/auth/HEADLESS-GAME-AUTO-SIGN-IN.md)
- [Game-instance ветвь success callback: Google PGS](../evidence/auth/HEADLESS-GAME-PGS-BRANCH.md)
- [Game success: рассылка подписчикам и title interface slot+0x30](../evidence/auth/HEADLESS-GAME-SUCCESS-BROADCAST.md)
- [GMC2 geo-контекст и проверка версии 1.13.16](../evidence/auth/HEADLESS-GMC2-GEO-11316.md)
- [Выполнение GMC2 headers в 1.13.16](../evidence/auth/HEADLESS-GMC2-HEADERS-NATIVE-11316.md)
- [Участки GMC2 URL и headers в 1.13.16](../evidence/auth/HEADLESS-GMC2-REQUEST-LAYOUT-11316.md)
- [Выбор базы GMC2 в 1.13.16](../evidence/auth/HEADLESS-GMC2-START-11316.md)
- [Выполнение GMC2 URL в 1.13.16](../evidence/auth/HEADLESS-GMC2-URL-NATIVE-11316.md)
- [JP: официальный вход до каталога и отказ после выбора сервера](../evidence/auth/HEADLESS-JP-LAUNCHER-CAPTURE-20261024.md)
- [JP: регистрация Netmarble 24 октября 2026](../evidence/auth/HEADLESS-JP-REGISTRATION-20261024.md)
- [Launcher-вход: отдельный credential и два HTTP-вызова](../evidence/auth/HEADLESS-LAUNCHER-AUTH-CONTEXT.md)
- [ChannelManager: выбор SignIn и отдельное получение launcher-токена](../evidence/auth/HEADLESS-LAUNCHER-CHANNEL-ROUTING.md)
- [Launcher request / response в 1.13.16](../evidence/auth/HEADLESS-LAUNCHER-CONTRACT-11316.md)
- [Реальный launcher-вход: SDK принят, Game Login отклонён](../evidence/auth/HEADLESS-LAUNCHER-LIVE-LOGIN.md)
- [Launcher-токен: заголовок, ответы и отдельный номер канала](../evidence/auth/HEADLESS-LAUNCHER-TOKEN-CONTEXT.md)
- [UserInfo оказался FCommonLogData: создание и потребители](../evidence/auth/HEADLESS-NID-COMMON-LOG-DATA.md)
- [Десять базовых NID pairs в 1.13.16](../evidence/auth/HEADLESS-NID-CONTEXT-11316.md)
- [Реальное преобразование webViewType в 1.13.16](../evidence/auth/HEADLESS-NID-CONVERTER-11316.md)
- [После OnResult: Save, channel manager и credential SDK](../evidence/auth/HEADLESS-NID-CREDENTIAL.md)
- [NID deviceKey отличается от SDK sign-in deviceKey](../evidence/auth/HEADLESS-NID-DEVICE-CONTEXT.md)
- [Почта/пароль: отдельные SDK-ветки и публичный NID web contract](../evidence/auth/HEADLESS-NID-EMAIL.md)
- [Дополнительные параметры NID в 1.13.16](../evidence/auth/HEADLESS-NID-EXTENSIONS-11316.md)
- [Ранние условия NID и дополнительные поля аккаунта в 1.13.16](../evidence/auth/HEADLESS-NID-GATES-11316.md)
- [Основная строка NID metadata для Login](../evidence/auth/HEADLESS-NID-METADATA.md)
- [Создание common data и привязка к SDK-сервису](../evidence/auth/HEADLESS-NID-OWNER-FACTORY.md)
- [Настоящие numeric / channel helpers и OnResult в 1.13.16](../evidence/auth/HEADLESS-NID-PRIMITIVES-11316.md)
- [NID integer/channel helpers и общий валидатор полей](../evidence/auth/HEADLESS-NID-PRIMITIVES.md)
- [Кодирование NID query и передача URL в состояние 1.13.16](../evidence/auth/HEADLESS-NID-QUERY-11316.md)
- [Текущий OnResult: проверки полей и передача токенов](../evidence/auth/HEADLESS-NID-RESULT-NATIVE-11316.md)
- [Текущие обработчики результата NID: статическая сверка 1.13.16](../evidence/auth/HEADLESS-NID-RESULT-SOURCE-11316.md)
- [NID email: ответ, проверка профиля и передача результата SDK](../evidence/auth/HEADLESS-NID-RESULT.md)
- [Поля UserInfo и запись NID map](../evidence/auth/HEADLESS-NID-USER-INFO-FIELDS.md)
- [NID OnResult: проверки и аргументы принятия токенов](../evidence/auth/HEADLESS-NID-VALIDATION.md)
- [NID: полный базовый набор параметров штатного окна входа](../evidence/auth/HEADLESS-NID-WEB-CONTEXT.md)
- [NID: сборка URL штатного окна входа](../evidence/auth/HEADLESS-NID-WEB-URL.md)
- [BasicTerms: GET, NO DATA и граница согласия](../evidence/auth/HEADLESS-RELEASE-BASIC-TERMS-RESPONSE.md)
- [Заполнение common data в новой сборке](../evidence/auth/HEADLESS-RELEASE-COMMON-DATA.md)
- [Контракт Fetch и отдельная операция чтения SDK-профиля](../evidence/auth/HEADLESS-RELEASE-FETCH-CONTRACT.md)
- [Первый игровой вход: Fetch и базовые условия](../evidence/auth/HEADLESS-RELEASE-FIRST-GAME-FETCH.md)
- [Первый SDK-вход: Fetch, условия и отдельный профиль игры](../evidence/auth/HEADLESS-RELEASE-FIRST-SDK-LOGIN.md)
- [Текущий игровой получатель результата SDK SignIn](../evidence/auth/HEADLESS-RELEASE-GAME-SIGN-IN-RESULT.md)
- [GMC2 response: путь clientIp к common data](../evidence/auth/HEADLESS-RELEASE-GMC2-GEO.md)
- [Индивидуальные условия без player ID и передача результата](../evidence/auth/HEADLESS-RELEASE-INDIVIDUAL-TERMS-DISPATCH.md)
- [Ответ индивидуальных условий: NO DATA до игрового перехода](../evidence/auth/HEADLESS-RELEASE-INDIVIDUAL-TERMS-RESPONSE.md)
- [Launcher-авторизация в текущем EXE](../evidence/auth/HEADLESS-RELEASE-LAUNCHER-CONTRACT.md)
- [SignUp SDK в текущей сборке](../evidence/auth/HEADLESS-RELEASE-SDK-SIGN-UP.md)
- [Ключи текущего SignUp: семь целых initializers](../evidence/auth/HEADLESS-RELEASE-SIGN-UP-KEYS.md)
- [Условия → выбор канала → первый SDK SignUp](../evidence/auth/HEADLESS-RELEASE-TERMS-CONTINUATION.md)
- [Auth-контекст и дополнительный каталог SDK](../evidence/auth/HEADLESS-SDK-AUTH-PATH.md)
- [SDK bootstrap: версия SDK и BuildCode](../evidence/auth/HEADLESS-SDK-BOOTSTRAP-VALUES.md)
- [Vampir — источник конфигурации SDK GMC2](../evidence/auth/HEADLESS-SDK-CONFIG.md)
- [Конструкторы и начальные значения SDK в 1.13.16](../evidence/auth/HEADLESS-SDK-DEFAULTS-11316.md)
- [Load: поля устройства и filename defaults](../evidence/auth/HEADLESS-SDK-LOAD-DEVICES.md)
- [Vampir — объединение строковых констант и чтение auth URL](../evidence/auth/HEADLESS-SDK-MAP.md)
- [Migration allocation: native обёртки не обнуляют tail](../evidence/auth/HEADLESS-SDK-MIGRATION-ALLOCATION.md)
- [NID storage suffix: sub → bytes → AES → HEX](../evidence/auth/HEADLESS-SDK-NID-SUFFIX.md)
- [Vampir — исполнение OAEP и декодирование одного secret chunk](../evidence/auth/HEADLESS-SDK-OAEP.md)
- [Связи игровых настроек SDK в 1.13.16](../evidence/auth/HEADLESS-SDK-OVERRIDE-LINKS-11316.md)
- [Выполнение игровых настроек SDK в 1.13.16](../evidence/auth/HEADLESS-SDK-OVERRIDE-NATIVE-11316.md)
- [Vampir — полный адрес offline token request](../evidence/auth/HEADLESS-SDK-PATH.md)
- [Callback query: native percent loop и строгая общая граница](../evidence/auth/HEADLESS-SDK-PERCENT.md)
- [PC platform getter и полнота switch в 1.13.16](../evidence/auth/HEADLESS-SDK-PLATFORM-11316.md)
- [SDK profile-кандидат 1.13.16](../evidence/auth/HEADLESS-SDK-PROFILE-11316.md)
- [SDK response: predicates, JSON и errorCode](../evidence/auth/HEADLESS-SDK-RESPONSE-GATES.md)
- [Response errorCode: native variant → string → _wtoi](../evidence/auth/HEADLESS-SDK-RESPONSE-VARIANT.md)
- [SDK result: делегат, очередь задачи и исходный ответ](../evidence/auth/HEADLESS-SDK-RESULT-DISPATCH.md)
- [SDK runtime profile для launcher 1.13.16](../evidence/auth/HEADLESS-SDK-RUNTIME-11316.md)
- [Vampir — сборка списка секретных констант](../evidence/auth/HEADLESS-SDK-SECRET-LIST.md)
- [Vampir — Base64 и параметры RSA секретных констант](../evidence/auth/HEADLESS-SDK-SECRET.md)
- [SDK settings: конструктор и переопределения игры](../evidence/auth/HEADLESS-SDK-SETTINGS.md)
- [SDK sign-in: завершение ответа и общий парсер](../evidence/auth/HEADLESS-SDK-SIGN-IN-COMPLETION.md)
- [SendSignIn с доступным SDK-сервисом](../evidence/auth/HEADLESS-SDK-SIGN-IN-LOG-PRESENT.md)
- [Вызовы после SignIn ведут к FPlatformLogImpl::SendSignIn](../evidence/auth/HEADLESS-SDK-SIGN-IN-LOG.md)
- [SDK sign-in response: структура player и SDK accessToken](../evidence/auth/HEADLESS-SDK-SIGN-IN-RESPONSE.md)
- [SDK sign-in: JSON, заголовки и локальный план запроса](../evidence/auth/HEADLESS-SDK-SIGN-IN.md)
- [Первый SDK-игрок: отдельный SignUp и фактический отказ по стране](../evidence/auth/HEADLESS-SDK-SIGN-UP.md)
- [SDK: каталог хранения, Save/Load и третий device key](../evidence/auth/HEADLESS-SDK-STORAGE.md)
- [Token payload и channelKey migration path](../evidence/auth/HEADLESS-SDK-TOKEN-PAYLOAD.md)
- [Vampir — строка ответа GMC2 перед XOR](../evidence/auth/HEADLESS-SDK-UNESCAPE.md)
- [Vampir — параметры SDK и XOR конфигурации GMC2](../evidence/auth/HEADLESS-SDK-VALUES.md)
- [Auth silent result → игровой AutoSignIn callback](../evidence/auth/HEADLESS-SILENT-GAME-DISPATCH.md)
- [Manager-child routing → OnSuccessNetmarbleSDKAuth](../evidence/auth/HEADLESS-TITLE-AUTH-NOTIFICATION.md)
- [Title auth-success: country/state slices и BeginGame gate](../evidence/auth/HEADLESS-TITLE-AUTH-STATE.md)
- [FDeviceInfo platform перед NID: 1.13.16](../evidence/auth/HEADLESS-WEB-PLATFORM-11316.md)
