# SDK response: predicates, JSON и errorCode

19 октября 2026. Продолжение [player fields](HEADLESS-SDK-SIGN-IN-RESPONSE.md).
Источник — Windows клиентский EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это код/данные клиента, не доступный C++ проект.

Инструмент `replay-sdk-sign-in-response-gates.py` →
`F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-response-gates-replay.json`,
SHA256 `0d5f378d45acd0c846a39f7f0c47c2b2ba2cadfbf6978903b77b5fb012b8edbf`.
Report ссылается SHA на прежние response fragments/constructor; сохраняет
leaf bytes/file offsets/SHA, import descriptors и статический variant converter.

Дополнение: [variant converter и actual virtual TryGetString](HEADLESS-SDK-RESPONSE-VARIANT.md)
проверены в отдельном replay для string/number-string representations;
полный parser selection и прочие value classes ещё открыты.

## Что исполнялось

Native цепочка `0x1444cc2e9` → response predicates → body/status getters →
JSON/object gate → errorCode gate → ранее проверенный player field slice.
Native code останавливается перед construction/dispatch ошибок и до полного
success callback. Auth constructor переиспользован и исполняется как ранее.
Owner/process-exit/lifetime gates перед началом этого участка не включены.

Четыре маленьких getters/predicates найдены как leaf functions без unwind:

| Адрес | Actual native operation |
| --- | --- |
| 0x14452b040 | AL = dword[RCX+4] == 0 |
| 0x1416340b0 | EAX = byte[RCX+0x20] |
| 0x1418089f0 | RAX = qword[RCX+0x28] |
| 0x140bd6440 | RAX = RCX+0x30 |

Getter +0x30 указывает на FString body, +0x28 задаёт status context дальше.
Leaf instructions реально исполнились на fixture response object. Полные
конструкторы/имена полей объекта не восстановлены; не переименовывать raw
field4/field20 в доказанные «network error»/«ignore» flags без дополнительных
источников. Подтверждена именно следующая таблица caller:

- field4=0 → parse независимо от field20.
- field4!=0 и field20!=0 → parse.
- field4!=0 и field20=0 → ранняя error branch.

JSON parsing/IsObject/variant conversion — явные Python fixtures. Native code
проверяет их результаты и связывает с дальнейшим traversal. Wrong JSON types
errorCode не покрыты: fixture принимает **строковые** errorCode значения.

## Numeric gate и настоящий Windows CRT

Presence errorCode проверяется по global `0x14b4f0b20` (initializer errorCode
уже сохранён). Если ключ отсутствует, caller сразу переходит к status gate.
Если присутствует, через variant-to-string helper `0x144476940` получает FString,
затем вызывает IAT `0x148945bb0` → **_wtoi**. Результат !=0 ведёт в error branch.

PE import DLL/name/descriptor/thunk bytes проверены. Числовое преобразование
в replay использует реальный `C:/WINDOWS/System32/ucrtbase.dll`, SHA256
`dedb7611e1abc1ff3852dcac3d4c93a048d729e25b061973b9969f22698f14ca`,
ctypes `_wtoi` с c_wchar_p → c_int. Это тот же CRT, ранее использованный в
[NID primitives](HEADLESS-NID-PRIMITIVES.md); locale не изменялась.
Его Android/прочие CRT semantics не заявляются.

При fixture string conversion `0`, `0abc`, пустая строка, `oops`, ` 0` дали 0;
`1`, `-1`, `200` дали ненулевое и остановились до token adoption.
Это native caller/Windows CRT compatibility evidence, не policy нового runtime.
Нельзя считать malformed value корректным успешным ответом или доверять ему.

`0x144476940` экспортирован статически: он содержит type-dependent ветви для
JSON string/number/bool/прочих типов. В этом replay helper заменён fixture,
поэтому **числовой JSON errorCode=0 не выдан за доказанный весь variant path**.
Его native conversion — следующая отдельная зависимость.

## 18 fixtures и связанный результат

4 raw-predicate combinations, 3 JSON non-objects, 8 строк errorCode и 3 status
boundaries199/206/207. Native status range 200..206 подтверждён как прежде,
но теперь status взят native leaf из fixture объекта, не просто начальный R12.
Body FString также взят actual native getter.

Reject branches оставляют old token fixture; при пройденных gates код достигает
player slice и записывает new SDK token fixture. Окончание slice всё ещё не
login success: idpInfo, final callback/IsSignIn/game session не исполнены.
Settings/module writes/Save сохраняют прежние captures, реальной записи нет.

## Далее

Native variant-to-string для JSON numeric errorCode и полная error dispatch
semantics; затем idpInfo и final success callback/IsSignIn, expiry/refresh,
SDK token →game Login. После определения всего boundary — runtime response parser.
Реальные HTTP/accounts/tokens/registry/Saved/память процессов не использованы.

Проверка:
`python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_response_gates.py' -v`.
Три regression tests воспроизводят report и проверяют все 18 native outcomes.
