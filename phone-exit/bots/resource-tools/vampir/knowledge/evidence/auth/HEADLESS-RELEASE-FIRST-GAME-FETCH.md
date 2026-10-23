# Первый игровой вход: Fetch и базовые условия

23 октября 2026. SHA256 текущего EXE:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [обычного игрового callback](HEADLESS-RELEASE-GAME-SIGN-IN-RESULT.md).
Исследование offline; реальные условия, аккаунты и персонажи не изменялись.

## Найдено конкретное отличие от цепочки бота

Игра имеет отдельный Fetch перед SignIn. Текущий runner бота
`run-nid-sdk-sign-in.py` выполняет либо обычный NID SignIn, либо
NID → launcher/token → launcher/sign-in. Отдельного Fetch / TermsOfService
в этом runner нет. Это установленное различие операций, но ещё не доказанная
причина отказа конкретного аккаунта: реальный официальный auth route не записан.

`0x14560b250` создаёт descriptor с leaf `0x145608110` → root `0x145603ab0`
и вызывает wrapper `0x1444e91f0` с channel 33. Wrapper вызывает
ChannelManager implementation `0x1444e9270`. В нём сохраняется callback,
ищется credential переданного channel, затем для обычного канала вызывается
`0x1444e8890`, а для launcher channel 200 — `0x1444e9b00`.
Контракт этих двух backend handoff ещё не разобран; endpoint не угадан по имени Fetch.

Названия шагов и каналов получены заново из contiguous PE descriptors текущего
EXE, с name pointer / int64, а не перенесены из старого native-enums.json:

| Enum | Значения |
| --- | --- |
| `ENetmarbleSDKStep` | Fetch 11; SignUpForGuest 12; SignUpForNetmarble 13; SignInForGuest 14; SignInForNetmarble 15 |
| `ENMChannelType` | Netmarble 33; Guest 100; Launcher 200 |
| `ENetmarbleSDKCode` | ShowBasicTerm 30050027 |

## Целый Fetch callback

[replay-release-fetch-result.py](../../../replay-release-fetch-result.py) исполняет
весь `0x145603ab0` и три getter leaves `144532750`, `141a2d1b0`, `14180e6e0`.
Их проверенные байты и поля сохранены в предыдущем evidence и новом отчёте.
Проверяются weak owner gates и сохранение исходного strong count 4.
При живом owner первым идёт capture журнала шага Fetch 11.

- Успех predicate `result +4 == 0`: вызов `14561b6a0` с channel 33 и step 15.
- Отказ, одновременно `dword +0xc == 30050027` и `qword +0x28 == 1203`:
  вызов `14561a200`.
- Остальные отказы: error text, затем message selector 6.
- Null / expired control block и null owner: без внешних действий.

24 комбинации success / error × четыре значения `+0xc` × контекст
1202 / 1203 / 1204, затем три owner gates: **27 native сценариев**.
К условиям переходит только одна комбинация ошибки. Это точный gate данного
Fetch callback, а не универсальное правило для любого SDK-кода 1203.
HTTP response → native error construction здесь не исполняется;
raw result задан fixtures. Живой отказ launcher/sign-in нельзя автоматически
подставить в этот callback и объявить Fetch-ответом.

Logger, SignIn, terms, error-text и UI — captures. Неизвестный вызов за границей
останавливает replay. Новая авторизация или создание SDK-профиля не запускаются.
Два теста проверяют обе части gate, handoff успешного Fetch, owner gates,
актуальные enum и отклонение изменённого export.

## Куда ведёт точный gate

`14561a200` получает service, затем getter `14452d7a0`. Его diagnostic:
`Netmarble::FServiceImpl::GetTermsOfService`; возвращается impl `+0x320`.
Далее `1445a8df0` → `1445a8e70`. Diagnostic в последнем подтверждает
`Netmarble::Service::FBasicTermsContent::Show` с callback
`EUIViewState, FResult`. Это показ базовых условий, не прямой SDK SignUp.

Для результата задаётся adapter `1456081d0`: `0fb612e938c7ffff`.
Он загружает byte состояния через RDX и переходит в `145604910`.
Этот обработчик статически журналирует step 5, при raw state 2 создаёт две
дальнейшие привязки и вызывает `14561ace0`. Значение 2 здесь не переименовано
в «согласие»: enum EUIViewState и продолжение этих привязок ещё не проверены.
При raw state 1 дополнительных действий нет; для state 3 есть отдельный retry
по внутреннему коду, остальные отказы передаются message helper.

Отдельный `145605440` обрабатывает шаги 12 / 13. Успех 12 вызывает SignIn
channel 100 / step 14; успех 13 — channel 33 / step 15. Ошибка с комбинацией
внутреннего `0x1ca86d6` и context 1602 имеет отдельную UI-ветвь.
Полный native replay этого обработчика и его фактическая связь с backend SignUp
пока отсутствуют. Из названия enum не выводится разрешение отправлять запрос.

## Материалы и границы

Ghidra-пути относительно
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-313ff5f10ab1/details.json`, Fetch / SignUp callbacks | `d376e82c676025619f3973f6ba86389e192bb85b48223a76d46529d9b914756e` |
| `details/run-77e3786da51e/details.json`, переход к terms | `016100a24be5999fcbd3c2a535d5745d2bcb13b65e72bf4cf4883e15b2351970` |
| `details/run-65955959b5db/details.json`, service / terms wrapper / caller / callback | `f8e3fbcab222925c62906f05740c11c832888b4595df3984529282cc7d38c17f` |
| `details/run-9a795062de1a/details.json`, Fetch wrapper / BasicTerms Show | `bf2105cdefac3d78cca7be0d286c2a9143509a8daac8bff428a6cd5a94db8741` |
| `details/run-88adae59bed9/details.json`, ChannelManager Fetch | `ad68dbf9e89f0a77232e4c6cad29f0e48f15042af35e5260ed470fb307e57a37` |

Последний экспорт завершён. Его первая индексация была отклонена из-за
изменения research-checks во время операции. После завершения процесса новый
prepare использовал все десять полных экспортов повторно, без новой Ghidra.

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-fetch-result/df2c8cfb1328cdb2f6de531fa5491ad1cfa9c2a223cb402b5cbba7a1c71cbf6c/manifest.json`.
SHA256 совпадает с именем каталога. Там сохранены инструкции callback,
getter bytes, descriptor offsets enum, fixtures, tool / dependency SHA и 27 случаев.
Check `release-fetch-result` подключён к общему workflow.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-fetch-result.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_fetch_result.py
```

Далее нужны только backend handoffs `1444e8890` / `1444e9b00` и продолжение
terms `14561ace0`: endpoint / payload / результат Fetch, состояние условий и
точное решение перед первым SDK SignUp. Затем можно добавить явный режим
первого игрового подключения, сохранив обычный вход существующих аккаунтов.
Автоматического fallback по отказу launcher/sign-in нет; массовый вход не запускать.
