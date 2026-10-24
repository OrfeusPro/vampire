# Native строковое чтение LoginResult 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [числового input archive](HEADLESS-LOGIN-RESULT-INPUT-11316.md).
FString, std::string и UTF-8 input helpers теперь исполняются вместе с целым
LoginResult и nested readers на одном archive / cursor / allocator state.
Готовый текст в поле пакета не подставляется; fixture FString reader удалена.

## Явные привязки

| Роль | VA | Источник связи |
| --- | --- | --- |
| FString reader | `144aacfd0` | Direct calls LoginResult reader |
| std::string reader | `144aac390` | Input table slot `+30` |
| UTF-8 length | `14144c440` | Direct call FString reader |
| UTF-8 wrapper | `1414466a0` | Direct call FString reader |
| Decode core | `14143bd30` | Direct call wrapper |
| Scalar decode | `14143b9a0` | Direct calls length/core |
| Archive byte leaf | `144aac240` | Slots `+78` / `+80`, JMP raw reader `+90` |

Декодирование использует другие helpers, чем уже проверенная запись UTF-8.
Новые exports: `run-4ef2b735941d`, `run-81d1e191e8c5`, `run-2fe73e379c6f`.
Сохранены только шесть явных unwind roots; прежние packet/numeric exports
переиспользованы. Общего анализа EXE / обхода дерева вызовов не было.

В интеграции 19 roots и шесть явных leaf bodies. Новый context задаёт
`function_budget: 19`; без него harness отклоняет запуск. Максимальный лимит
не изменён, произвольные найденные функции не разрешены. Полные SHA exports,
instructions, table slots и call sites закреплены в
[контексте](../../native-contexts/login-result-string-11316.json).
[Квитанция](LOGIN-RESULT-STRING-11316.json).

## Исполненный путь

FString reader вызывает std::string через настоящий slot `+30`. Native uint16
читает длину UTF-8 в байтах, native byte method / raw IO читают каждый byte.
В std::string исполняются inline writes и переход к growth boundary при нехватке
capacity. Затем FString caller сканирует C-string до NUL, native length считает
UTF-16 units, а native wrapper/core/scalar выполняют преобразование.

До 128 wide units caller использует stack scratch; для 129 и выше вызывается
allocator boundary. Native cleanup освобождает wide scratch и heap std::string.
FString assignment и storage allocator/growth/free остаются ограниченными fixtures;
они копируют именно полученные native UTF-16 bytes, не декодируют UTF-8 в Python.
Итоговые FString buffers сохраняются в полях результата, временные — освобождены.
Проверяются владение, повторный free, размер cpp-free и canaries allocations.

Stack-cookie fixture сохраняет RAX: caller задаёт EAX из BL до проверки cookie.
Обнуление RAX в этой модели ложно превращало успешное чтение в отказ; это была
ошибка fixture, а не обнаруженный отказ клиента. Исправленное поведение проходит
полное чтение и короткие входы.

## Сценарии

160 различных полных случаев: 4 набора строк × 5 raw result codes × 4 raw bool
inputs × 2 packet poison pattern. Прежняя ось fixture return 1/128 удалена:
после переноса всех чтений в native она больше не влияет на исполнение.
Числовые и прежние fixture-reader проверки сохранены отдельно.

Дополнительно проверены 4 полных тела с 15/16 и 127/128 ASCII characters,
332 коротких префикса, 25 отказов на каждом поле и trailing bytes.
Все корректные полные тела совпали с Python decoder. Проверены 7 actual string
entries, порядок / поля / vptrs, общий cursor, сохранность input buffer,
temporary cleanup и ABI. Принудительный отказ моделируется на entry выбранного
field reader; остальные операции исполняются целиком.

## Повреждённые строки и локальная политика

Шесть отдельных тел содержат в первом поле FF, C0AF, EDA080, F4908080,
`a NUL b` и UTF-8 для U+FFFE. При **явно обнулённой начальной stack-памяти**
native path принимает тела: пять дают `?`, NUL-вариант — `a`.
Python decoder отвергает все шесть: его строгая UTF-8/scalar/NUL policy сохранена.

Это не полное описание malformed behavior реального клиента. Некорректный scalar
может потребить завершающий NUL; тогда наличие нулевого wide unit после записи
зависит от исходного scratch. Пилотный прогон со старым содержимым stack показал
посторонний synthetic suffix, поэтому финальная матрица фиксирует zero stack,
а не выдаёт этот suffix за устойчивый decoded value. Наличие native записи
terminator во всех malformed ветках этим не доказано.

## Автоматизация и ограничения

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_string_context.py
```

Три теста прошли за 21,255 секунды, включая весь replay и отказ при отсутствии
explicit budget / подмене UTF-8 callee / export. Прежние числовые и caller тесты
также прошли. Это время набора, не обновления целиком.

`native-login-result-string-context` включён в game-login/update. Кэш зависит от
context/verifier, двух storage/input fixture modules, Python decoder,
harness/runtime/тестов и шести exports. Новый SHA требует переноса direct/virtual
links, byte leaf, UTF-8 call closure, storage ABI и проверок границ. Результат не
разрешает автоматическое продвижение runtime или ослабление строгого decoder.

Little endian only; source buffer/cursor заданы явно. Реальные allocator/growth/
FString assignment/free, concrete input buffer constructor, dispatch и handler
остаются открытыми. Allocation failure, very large/aligned std::string free,
произвольный испорченный archive state и общее malformed UTF-8 поведение не доказаны.
Нет сети, авторизации, изменения аккаунтов / ключей / default preset / baseline.
Далее — concrete input construction и current handler/result gates/dispatch;
подготовка Login writer и реальные SDK/UserInfo boundaries остаются отдельными задачами.
