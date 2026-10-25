# Native источник из кэша, нормализация и physical resolver

25 октября 2026. Продолжение [whole installed predicate](UI-CONFIG-INSTALLED-COLD-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline native replay; реальные каталоги, конфиги, профиль и ОС не изменялись.

## Источники

Explicit request 20836e9d86108d784ece9f89126bdc63fe10f8ca115d11aed8b4fe911f922f52
содержит source / normalization / manager / resolver. До collect проверены
unwind: 141584080 и 1414833a0 не имеют записей; пакет с ними не отправлялся
в collector. Для них отдельно сохранено доказательство bytes / padding ниже.
Новое explicit задание
`d7469a32cc8eb4e3b353d59fbc0d734cf3a70bd497165b867c76f28428be1ca5`
содержит только unwind roots 141459960 / 141435f10 / 1414891c0 / 1415ca400.
Collect завершён, очередь пуста. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-09bf4a9674b0/details.json`, SHA256
`ba550eb5b292ff1279a7f9f3f9f480e40243e10bdf422fa1ccca51f0e861aa45`.
Псевдокод сверен с инструкциями всех chained fragments.

Прежние explicit requests whole predicate / flag compare / join сохранены
как три отдельные зависимости предыдущего replay; новый режим требует ещё
--source-request и --leaf-request того же полного SHA.

## Leaf / tail без придуманного unwind

1414833a0: точные bytes `488d0509e0e309c3`, затем восемь int3. LEA возвращает
адрес 14b2c13b0, RET. Это целый 8-byte leaf, не функция с угаданным размером.
Caller 141465720 подтверждён прежним экспортом / native replay.

141584080: bytes `4533c94c8d0596d44607488d15e7034607e97a1eebff`, затем восемь int3.
22-byte tail устанавливает R9D=0, R8=slash 1489f1520, RDX=backslash 1489e4478,
сохраняет RCX object и JMP передаёт управление в explicit root 141435f10.
Caller 141533f40 подтверждён. Replay проверяет отсутствие unwind, exact bytes,
padding и границы исполнения; leaf / tail не добавляются в exception table.

## Нормализация

Целое native тело 141435f10 исполняется в режиме равной длины pattern / replacement,
R9D=0: заменяет backslash на slash в рабочей строке. Поиск substring 1487f5ad7 —
fixture; запись символов и повтор до конца выполняет native код. Указатели
fixture переводятся в offsets по UTF16 units, включая surrogate pair.
Ветка иной длины, ignore-case режим, aliasing и allocation failure не проверены.
Не распространяем этот результат на все варианты generic replace.

В whole predicate больше нет no-op normalization fixture. Итоговый path на
реальном native backend boundary сверяется с независимым ожидаемым путём.
Например, synthetic C:\Game\ превращается в C:/Game/Engine/Build/InstalledProjectBuild.txt.
Это fixture-пример; фактическое расположение игры не установлено.

## Source 141459960

В новом режиме исполняются все инструкции готовой ветви, когда count по +8
объекта от 14144b6b0 не равен 0 / 1. Возвращается его data pointer; source getter
больше не заменён готовым returning fixture. Сам 14144b6b0 и содержимое кэша
пока fixtures с валидным nonempty FString, а не настоящие runtime значения.
Начало cold construction 1414599a3 явно запрещено в этом режиме.

Cold тело сохранено / проверено статически, но не исполнено. Оно использует
141579320, поиски /Engine по 1489f3e90, /%s/Binaries по 1489f3ea0 с runtime
14b1d6e70, /../Binaries по 1489f3ec0; fallback идёт через 1415c2820 и строки /
удаление / перенос / cleanup. Источники и единицы этих операций ещё не доказаны.
Нельзя объявлять кэш абсолютным root установленной игры по одному имени literal.

## Resolver и следующая цель

Настоящий leaf 1414833a0 возвращает 14b2c13b0. Целое тело 1414891c0 читает
его qword. Если pointer уже есть — возвращает его; при нуле вызывает настоящий
1415ca400, сохраняет результат в qword и возвращает. Ghidra выводит void,
но инструкции и native replay подтверждают перенос pointer через RAX.

1415ca400 возвращает статический object 14b33e848. Guard 14b33e850 использует
TLS epoch. При первичной инициализации вызывает constructor 1414400f0 (fixture),
сам записывает vtable pointer 148a21698, регистрирует cleanup 148864f60 через
atexit и вызывает footer. Значение final vtable не подставляется constructor
fixture. Header/footer/TLS/constructor/atexit остаются явными fixtures.

File-backed slot+0x78 таблицы 148a21698 указывает на 1415c6140. Bytes таблицы
проверены до и после сценария. Этот точный адрес теперь backend fixture;
его тело не исполнялось. Не называем query проверкой существования файла.
Первая цепочка 14b0bf650 / vtable+0x48 / 141465720 также остаётся native.

## Общая проверка

Новый режим replay-ui-config-installed-cold.py: 384 полных сценария и 384 cache
повтора на одной памяти. Четыре nonempty prefix fixtures, два capacity, backend
AL 0 / 2, восемь command-line fixtures и три режима platform state:
resolver ready; resolver empty / physical ready; resolver empty / physical init.
Native выполняет cached source, copy wrapper, join, normalization tail / replace,
manager leaf, resolver, physical provider и первую forwarding цепочку.

Проверены нормализованный query path, pointers / final vtables / constructor gate,
один normalization / query / flag / free, moved source, cache repeat без новых
services, RIP / RSP и восемь nonvolatile GPR. В отчёте сохранены leaf bytes.
Ни base_directory, ни normalize_fixture, ни platform_manager / platform_resolver
готовых fixtures в новом режиме нет. Остаток — base-manager cache, substring,
FString copy/reserve/byte-copy, physical guard/constructor/atexit, backend/free /
ASCII iswspace. Первый file-backed manager guard остаётся в готовой ветви.

Отчёт `code-clues/ui-config-installed-native-chain-d00a-02.json`, SHA256
`76cb4678e2e19ab8e64052157438fe7736bf73545e6ed5c7d9bee7fe2e9b8c76`.
Unicorn 2.1.4 / Capstone 5.0.6 закреплены. Два теста installed-модуля прошли
за 5.008 с: старый 128-case режим и новый 384-case режим, оба с cache повторами.
Проверка имеет собственный dependency cache; неизменённый 26-test UI suite
переиспользуется только при прежних SHA зависимостей.

Следующий шаг — backend 1415c6140, constructor 1414400f0 и источник cache
14144b6b0 / cold source 141459960. Actual path, filesystem result, config
precedence, whole base-path / loader и UI применение остаются открытыми.
