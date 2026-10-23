# Version: Windows и CPU helpers 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Повторно использован `run-09b30ec921d8`; два дополнительных последовательных
экспорта содержат только пять явных roots. Полный EXE не анализировался заново.

| Материал | SHA256 |
| --- | --- |
| `run-09b30ec921d8/details.json` | `05567661bee229c7038ea1e621e08dd3a1c4c3d7685e9551554c222dab33c4da` |
| `run-3f96bbd3d272/details.json` | `9db07fe46882c292a83dc7b8e3a2f4351f4952add1767a55dc4eb26fecbf3a61` |
| `run-222e27fb93bc/details.json` | `42530f3b8c561ca7e295da4d7dcb673c21d17a196d2bf6d8644ef2492fd6cb4b` |

## Windows: 48 сценариев

Целиком исполнен `1415c9380`: signed TLS comparison, cached path, acquire,
инициализация структуры, ветка ошибки GetVersionExW, форматирование, release,
проекция в FString и cookie call. Проверены все nonvolatile registers, RSP
и canaries результата. GetNativeSystemInfo вызывается, но полученные им поля
в этом helper не выбирают суффикс: literal — `64bit`.

Проверена передача в `%d.%d.%d.%d.%d.%s`: major, minor, build, byte по `+11a`,
word по `+118`, `64bit`. В fixture OSVERSIONINFOEXW последние два поля соответствуют
product type и suite mask. Это не service-pack номера. Ошибка API обнуляет
первый wide char cache. При acquire, не установившем guard в -1, API не вызывается.

TLS/guard, WinAPI, memset, printf, cookie и FString — явные fixtures. Cookie fixture
проверяет аргумент и сохраняет RAX; реальный CRT cookie checker не исполняется.
GetVersionExW / GetNativeSystemInfo проверены по import names / DLL, memset —
по import thunk / имени. Реальная версия Windows и general printf не проверены.

## CPU: 72 сценария

Исполнены `14144d1a0`, getters `1415c6e80` / `1415c6e60`, move-trim wrapper
`141439fc0`, trim-end `141439db0` и trim-start `14143a030`.
Getters читают начальные ASCII buffers `14b0c7cb2` / `14b0c7cbf`.
CPU initializer / CPUID не исполнены: buffers заполнены synthetic fixtures.

Настоящие trim-инструкции изменяют count, перемещают NUL и передают владение
буфером. Проверены пустой FString с / без allocation, ASCII whitespace,
полностью пустой результат, `Unknown`, `|` внутри brand, embedded NUL и brand
длиной 63 символа. Входной CPU cache не изменён, временные allocations очищены,
canaries и ABI сохранены.

Третий compiled input — `Unknown`; поэтому фактически исполнена ветка `%s|%s`.
Разделители внутри brand остаются как есть: ветки замены `|` для другого третьего
input не заявлены проверенными. Actual constructors / alloc/free, memmove,
shrink, printf и ASCII iswspace classification остаются bounded fixtures.
Имена memmove / iswspace imports проверены; Unicode / locale поведение CRT не доказано.

## Повторение и автоматизация

[Контекст Windows](../../native-contexts/version-windows-11316.json),
[контекст CPU](../../native-contexts/version-cpu-11316.json),
[квитанция машинных результатов](VERSION-SYSTEM-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_system_context.py
```

`native-version-system-context` включён в game-version / update. Кэш зависит
от полного SHA, исходников, контекстов, exports и runtime. Новый SHA требует
переноса явных call sites, literals, globals, imports и fixtures, затем проверок.
Неоднозначный адрес или изменённый callee не подтверждаются автоматически.

Следующий шаг — включить helpers в whole Version prepare с явными оставшимися
границами context / combiners, затем Login prepare и result readers. Текущие
результаты не подтверждают полную подготовку, CPU initializer или игровую сессию.
Сеть, авторизация, runtime promotion и смена baseline не выполнялись.
