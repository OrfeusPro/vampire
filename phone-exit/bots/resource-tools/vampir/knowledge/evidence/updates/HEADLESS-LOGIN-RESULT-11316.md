# Reader игрового LoginResult 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Проверен ответ игрового пакета ID 4. Это не SDK sign-in callback и не отдельный
ответ лобби с тем же номером. Исторический decoder использован для независимого
сравнения, его адреса не перенесены в текущий EXE.

## Привязка

Префиксы старых constructor/reader дали соответственно 428 / 177 unwind roots,
а префикс старого handler не дал кандидата. По этому совпадению роль не назначена.
Рядом с текущим ASCII literal PktLoginResult найдена таблица `149926590`:
slot `+28` ведёт в `141453c40`, actual leaf возвращает 4. Slot `+20` ведёт
в reader `1456dc140`. RIP reference в constructor `1456d7690` указывает на
ту же таблицу. Полные SHA таблиц, instructions и явные leaf bytes проверяются
по source. Совпадение старого префикса не используется как автоматический binding.

Два последовательных batch exports содержат только явные roots:
`run-3c0581002a58` (constructor/reader) и `run-cfe450e70430` (четыре nested roots).
Использован существующий Ghidra проект без общего autoanalysis. Ветки callees
автоматически не расширялись. Leaf base constructor и virtual reader thunk не
имеют unwind и не передавались в unwind-only collect.

| Объект | Constructor | Reader | Table |
| --- | --- | --- | --- |
| LoginResult | `1456d7690` | `1456dc140` | `149926590` |
| Вложенный TimeBase | `1457a3500` | `1457fdce0` | `14991f3b8` |
| Вложенный PeriodServerDate | `1457a23a0` | `1457a5820` | `149926548` |

Native base constructor `1457fdaf0` обнуляет raw64. Native thunk `144aad190`
меняет this/archive аргументы и передаёт управление virtual reader slot `+20`.
Поэтому nested tables реально участвуют в вызовах, их layout не нарисован fixture.
ID getter, base constructor и thunk закреплены явными source bytes.

## Поля и проверки

Native caller подтверждает прежний порядок 25 операций. Смещения — hex поля
объекта клиента, не переменные offsets wire body:

```text
u32 +10; strings +18/+28/+38; u16 +48; time raw64 +58;
u16 +60; raw64 +68; string +70; raw64 +80; bool +88;
string +90; bool +a0; time raw64 +b0; strings +b8/+c8;
period bool +e0; time raw64 +f0/+100/+110/+120; bool +128;
raw32 +130/+134; bool +138.
```

Каждый archive fixture сверяет фактические this, kind, адрес назначения и номер
операции. Виртуальные slots: `+28` time raw64, `+50` raw64, `+58` u32,
`+60` raw32, `+70` u16, `+88` bool. Строковый reader — `144aacfd0`.
Внутреннее преобразование bool и UTF-8 здесь fixture, не native archive evidence.

320 полных случаев: 4 набора строк (пусто, ASCII, 128 ASCII, Ж界🙂) × 5 raw codes
(0/1/16/58/ffffffff) × 4 raw bool inputs (0/1/2/255) × 2 poison pattern × 2
значения успешного возврата primitive (1/128). Native reader возвращает 1,
потребляет полное тело; поля совпадают с существующим Python decoder.
Семантика code, raw64 и прочих полей новым handler пока не подтверждена.

332 коротких префикса: 99 для пустых строк, 106 для `x`, 127 для emoji.
Для каждого actual caller возвращает 0, fixture не читает за доступный ввод.
Ещё 25 случаев принудительно отказывают на каждой операции при полном теле:
после отказа reader не вызывает последующие операции. Это доказательство
распространения отказа caller, а не внутреннего поведения настоящего archive.

Проверены constructor/nested vptrs, canaries объекта и строковых буферов,
неизменность archive descriptor, сохранение восьми nonvolatile регистров / RSP.
После чтения разрешены изменения только успешно декодированных полей;
остальные поля и padding сохраняют байты после constructor.

Native caller с fixtures принимает trailing `extra`, consumed остаётся 99.
Локальный Python decoder сознательно отвергает trailing bytes. Его строгие
UTF-8 / scalar / NUL ограничения не объявляются свойствами native archive.

## Границы и автоматизация

Исполнены шесть whole roots и три явных leaf bodies. Archive primitives,
UTF-8 conversion/FString allocation заменены ограниченными fixtures. Реальные
malformed UTF-8, allocator failure, endian/length внутри actual archive,
bool normalization и reader cleanup требуют отдельного native переноса.
Handler/dispatch/list request и серверное принятие не проверены. Нет авторизации,
сети, изменения runtime source guard / baseline / действующих аккаунтов.

[Контекст](../../native-contexts/login-result-11316.json),
[квитанция](LOGIN-RESULT-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_context.py
```

Три теста прошли за 11,361 секунды: reader/model/short/failure/trailing проверки
и отказы при подмене SHA, export, callee, reader table и ID binding.
Это время набора, не всего обновления.

`native-login-result-context` включён в game-login/update; добавлены отдельные
bindings result-constructor/result-reader и vtable recipe. Кэш учитывает полный
SHA, два exports, context/verifier/harness/runtime/тесты и Python decoder.
На новом SHA заново проверить constructor/table/ID, nested calls, thunk,
virtual slots/order и failure propagation. Префикс с несколькими совпадениями
оставлять неоднозначным. Готовность game-login остаётся partial.

Далее — actual archive input/string primitives и handler/dispatch с отдельными
проверками result gates и перехода к персонажам. Готовые шесть roots повторно
не выгружать; общая интеграция Login writer/archive остаётся отдельной задачей.
