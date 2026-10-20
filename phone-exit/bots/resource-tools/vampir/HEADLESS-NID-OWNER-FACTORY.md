# Создание common data и привязка к SDK-сервису

20 октября 2026. Продолжение [FCommonLogData и owner](HEADLESS-NID-COMMON-LOG-DATA.md).
Источник — собранный Windows-клиент, не исходный C++ проект.

## Проверенная цепочка

В Ghidra разобраны factory `0x14450f420` и её direct caller `0x144510fd0`.
Caller создаёт несколько компонентов SDK-сервиса. На `0x14451115b` настоящая
инструкция `lea rcx, [rdi + 0x310]` задаёт адрес пары owner / control block,
а следующий call `0x144511162` вызывает factory.

Factory выделяет owner размером 0xf0 и вызывает ранее проверенный конструктор
`0x14450f5d0`. Тот создаёт inner размером 0x278 с 37 строками по inner+0x28.
Factory также создаёт внешний control block 0x18, устанавливает shared-self
пару по owner+0x10 и возвращает пару по адресу SDK-сервис+0x310.
Vtable внешнего control block — `0x1489a4e48`; два DWORD counters после возврата
равны 1 и 2. Эти числа не используются как критерий готовности SDK.

Три native-сценария с исходным заполнением 0 / 0x55 / 0xff исполнили:

1. Настоящие две инструкции SDK caller, которые передают адрес +0x310 в factory.
2. Полную factory от входа до возврата, полный owner constructor и zeroing leaf.
3. Настоящие getters `0x144524800` и `0x144521e80` от входа до возврата.
4. Проверку конечного адреса структуры, всех 37 пустых descriptors, shared-self
   связи и contents внешнего control block.

Все сценарии подтвердили пустые common data на этапе создания. Теперь связь
factory с полем SDK-сервиса проверена настоящим callsite, а не ручной записью
этой пары в fixture. При этом сам SDK-сервис и RDI в точке callsite — fixtures:
весь большой caller и реальная инициализация host не исполнялись.

Allocation / memset, перенос shared-pointer, два соседних контейнера owner и
InitializeSRWLock остаются ограниченными fixtures. Проверены только успешные
выделения памяти. Размеры шести allocations: 0xf0 / 0x278 / 0x18 / 0x10 /
0x18 / 0x18. Это не проверка scheduler, thread safety или рабочего SDK lifecycle.

## Уточнение прежнего кандидата после SignIn

Функция `0x14453cdf0`, упомянутая ранее как кандидат обновления после player ID,
уже связана с `UNMServiceSettings::Save` в
[SDK storage](HEADLESS-SDK-STORAGE.md) и
[credential adoption](HEADLESS-NID-CREDENTIAL.md). Новый экспорт Ghidra
сохраняет её под аналитическим именем SDK_SettingsSave. Наличие этого вызова
после setter не доказывает заполнение common data.

В SDK_SignInResponse есть другая последовательность:
`0x144524800 → 0x144524d70 → 0x144548ca0`.
Первый getter уже проверен; два последующих вызова в прежнем replay completion
были только fixtures. Их семантика ещё не подтверждена. Это следующий участок
для проверки источников значений, а не готовое исправление Login metadata.

## Происхождение и воспроизведение

EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Путь: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
Ghidra 12.1.4: `F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`.
Новый экспорт: `export-c7552efd2125/run-d40608313905`, 404 функции,
183 предупреждения. Manifest SHA256:
`8f1ba2e35faf48505791b4ec7494abf8570ad45ae64381b3c07cedebfc48c202`.

Отчёты в `F:/PhoneExit Resources/Vampir/code-clues/`:

- `nid-user-info-factory-replay.json`, SHA256
  `0be34af00d5c20c24321a7d63d25d4ef22327466ce07c3a0643f356e3cb9ba33`;
- `nid-user-info-factory-callers.json`, SHA256
  `5831b66e1a0d426fc7d6778c80ad7205ab9f608ad0afddfa3be9bff9eec0f255`.

Caller index повторно использует действующий E8 indexer: найден один
проверенный call, decode failures отсутствуют. Indirect / tail callers
по-прежнему не покрыты. Отчёты содержат hashes источника / инструментов,
исходные диапазоны инструкций, fixtures и результаты.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-user-info-factory.py
python -X utf8 phone-exit/bots/resource-tools/vampir/build-nid-user-info-factory-callers.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_user_info_factory.py -v
```

Прошли 12 проверок: две factory, три owner, четыре writer / caller и три
проверки целостности Ghidra export. Воспроизведение отчётов и hashes прошло;
ошибки декомпилятора остаются предупреждениями с явными границами.

Runtime и поля реального аккаунта не менялись. Новых сетевых попыток, запуска
игры или загрузки DLL не было. Причина Login 16 остаётся открытой; цепочка
создания common data не доказывает обязательность metadata для сервера.
