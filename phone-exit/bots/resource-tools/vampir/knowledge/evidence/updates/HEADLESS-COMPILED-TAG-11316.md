# Строка версии пакетов 1.13.16

23 октября 2026. Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверок обновления](HEADLESS-UPDATE-CHECK-DISPATCH.md) и
[исторического tag](HEADLESS-RELEASE-WIRE-TAG.md).

## Поиск и явный экспорт

Общий индекс не содержал current compiled-tag evidence. Из прежнего Ghidra
экспорта Version preparation `0x1467cfd30` взяты первые девять инструкций:
39 байт без CALL / RIP-dependent данных. Точный поиск в текущем EXE нашёл
единственный совпавший unwind root `0x1467ce6a0`. Это candidate, не перенос роли.

`prepare` вопроса release-game-login-code-1 с этим адресом показал missing.
Явный collect использовал существующий noanalysis проект и сохранил полный
экспорт только этой функции, 960 байт:
`F:/PhoneExit Resources/Vampir/ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-571e3ba7330a/details.json`.
SHA export:
`4280b5fc70e7708ecf95248adba6aeedcb7cd0755ac2da034ce0fc162a1770a5`.
Collect / его дочерние процессы завершились; выгрузка принята importer.

## Текущая привязка

| Поле | Значение |
| --- | --- |
| Инструкция MOV RDX, [global] | `0x1467ce8da` |
| Pointer global | `0x14b1b9e98` |
| Pointer file offset | `186353816` |
| Pointer bytes | `2000964901000000` |
| ASCII literal | `0x149960020` |
| Literal file offset | `160819744` |
| Compiled tag | `32283C4C6485307BCF524765A84409C3` |

Значение совпадает с предыдущей сборкой 1.13.14; адреса отличаются.
Совпадение установлено чтением проверенного current EXE через указатель,
а не подстановкой старой строки или данных приватного capture.

`replay-compiled-tag-11316.py` исполняет slice `0x1467ce8da..0x1467ce931`
на четырёх заполнениях destination: 0, 0x55, 0xaa, 0xff. Actual MOV читает
новый pointer, native stores / branches формируют descriptor по RBP+0x50.
Проверены length/capacity 33 и 66 UTF-16 bytes, canaries до / после полей и data.

Fixtures: ASCII FString constructor `0x141426950`, allocator `0x141436ed0`
и проверенный memcpy import thunk `0x1487f5ab9`. Аргументы fixtures ограничены
точными source / destination / count. Это привязка копирования, не исполнение
конструктора строки, allocator или всей подготовки Version.

Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/compiled-tag-11316/2e0f101e7c704acb8c462d8cb367f1dddd4c45dbe607ae38651d57ab1f84b6f9/manifest.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-compiled-tag-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_compiled_tag_11316.py
```

Три теста прошли: actual slice / guards, повреждённый export и malformed literal.
Check `compiled-tag-native-11316` подключён к research и on_update; inputs содержат
полный SHA source, export, harness и зависимости. В ориентиры обновления добавлены
адрес, границы и next-release review. Изменившаяся строка не ищется по старому
значению как обязательному признаку; новый candidate нужно подтвердить по коду.

## Оставшаяся проверка

Caller / vtable роль candidate, полный Version preparation, Login consumer этой
строки и остальные поля текущего game profile ещё требуют сверки. Новый
DefaultGame.ini уже извлечён; его AppVersion 1.13.16 не заменяет проверку
compiled tag. Runtime game profile этим этапом не переключается, старый SHA guard
сохраняется. Серверное принятие, активный cache и живая сессия не проверены;
сеть, авторизация, игра и приватные captures не используются.
