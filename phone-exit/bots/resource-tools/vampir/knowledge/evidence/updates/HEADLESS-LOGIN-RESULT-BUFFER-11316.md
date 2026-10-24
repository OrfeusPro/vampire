# LoginResult 1.13.16: создание входного буфера

Источник: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`,
immutable snapshot EXE в библиотеке ресурсов. Контекст:
[login-result-buffer-11316.json](../../native-contexts/login-result-buffer-11316.json).
Предыдущая проверка строк и её ограничения:
[FString / UTF-8](HEADLESS-LOGIN-RESULT-STRING-11316.md).

## Связи и исполнение

Concrete constructor `144aacb40` вызывает buffer constructor `144aac130`,
устанавливает table `149670880` и mode в `+14`. Он передаёт endian из пятого
аргумента Windows x64 (stack `+28` на входе), а не из младшего байта mode.
Buffer constructor вызывает leaf `144aace10`, устанавливает base table
`1496706e8`, pointer `+20`, size `+28`, cursor `+30` и endian `+38`.
Оба возвращают receiver; padding не инициализируется.

В общей цепочке concrete constructor получает действительный synthetic buffer,
его размер, mode 1 и endian 0. Host больше не записывает pointer/size/cursor
после конструктора. Следом исполняются прежние packet/nested readers, числовые
archive методы и FString/std::string/UTF-8 helpers на общей памяти.

Повторно использованы шесть готовых exports. Единственная новая выгрузка:
`ghidra/request-exports/<SHA>/run-80386d1eb460/details.json`, один root
`144aac130`. Его SHA и все call sites закреплены в контексте. Ghidra project
использован повторно, обхода дерева вызовов нет.

Общая цепочка содержит 20 явных unwind roots: default constructor заменён
concrete/base парой. Harness допускает budget 20 только для scope
`login-result-buffer`, ровно 20 roots и проверяемых bindings reader/constructors.
Прежние лимиты 16/19 и максимум 8 exports сохранены; произвольные 20/21/32
и отсутствие scope отвергаются. Все инструкции сверяются с полным SHA EXE,
необъявленное исполнение по-прежнему запрещено.

## Проверки и обновления

72 вызова constructor: оба roots, размеры 0/1/4096, mode 0/1/FFFFFFFF,
endian 0/1, два poison patterns. У base constructor mode отсутствует в ABI;
повторы с разными mode проверяют ту же base ветвь. Проверены поля, возврат,
восемь nonvolatile registers, stack, padding и canaries.

Вся цепочка повторно прошла 160 корректных полных ответов, 332 коротких ввода,
25 отказов на полях, trailing bytes, 4 границы размера строки и 6 специальных
строк с прежними zero-stack ограничениями. Строгий Python decoder сохранён.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_buffer_context.py
```

Три теста прошли за 28,882 секунды. Новый check
`native-login-result-buffer-context` подключён к game-login и update; зависимости
включают context, tools, pinned runtime и семь exports. Новый SHA требует
переноса constructor call/table/ABI и повторного replay. Поиск кандидата сам
по себе не разрешает runtime promotion.

## Открытое

Проверка endian 1 касается только сохранения аргумента конструктором; чтение
big endian не проверено. Mode проверен как raw field, его смысл для сессии
не установлен. Буфер synthetic, максимум 4096 bytes; произвольные invalid
pointers, переполнения и повреждённое состояние archive не исследованы.
Memcpy, allocator/growth/assignment/free остаются fixtures.

Далее — current handler/dispatch/result gates. Чтение ID 4 не доказывает
успешный вход, выбор персонажа или сетевую сессию. Авторизация и игровые
действия не запускались; аккаунты, пресеты и runtime source guard не менялись.
