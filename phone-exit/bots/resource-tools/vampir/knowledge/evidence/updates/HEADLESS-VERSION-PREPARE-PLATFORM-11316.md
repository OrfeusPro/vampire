# Platform/context внутри Version prepare 1.13.16

Полный SHA: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Использованы восемь готовых exports из предыдущих проверок. Ghidra не запускалась.

В 288 whole prepare сценариях исполняются 19 явных функций: prepare/constructor,
NM wrapper/getter, Windows suffix, CPU formatter/getters/trim, combiners/copy/
append/grow и теперь selector `1445ce2e0`, store `1445c4b90`, lookup `1416dd660`.
Выход selector передаётся в настоящий lookup; lookup передаёт полученный индекс
в value-at fixture, результат которого используется реальными combiners.
Итоговое поле `+28` и cleanup проверены на общей памяти.

Матрица включает четыре poison pattern, пустые / непустые system inputs,
enum 0 / ffffffff, send 0 / 1 и девять platform/context сценариев:

- Windows cached и cold: context cache возвращает указатель; cold resolver
  вызывается с объявленными factory / type / descriptor и результат кэшируется;
- Windows absent: resolver возвращает 0, lookup не вызывается;
- Windows missing: 3 не найдено в таблице 1/2, value-at получает ffffffff;
- Windows duplicate: в таблице 3/3 выбран первый индекс 0;
- Windows negative count: lookup пропускает массив и передаёт ffffffff;
- Android и IOS cold: selector возвращает 1 / 2, lookup выбирает их индекс;
- unknown cold: Linux не совпадает с тремя literals, selector 0 не найден.

Проверены порядок сравнений и вызовов, количество входов в actual functions,
неизменность store/array, конечный cache, поля пакета, allocations/cleanup, owner
guards, входные FString и ABI. При missing/negative/unknown value-at fixture
выдаёт пустой текст; реальный combiner сохраняет `_` перед Windows suffix.

## Ограничения

FName constructor / equality, platform text getter, store type / resolver и
value-at остаются fixtures. FName equality fixture сравнивает текст точно и
возвращает raw byte 128; реальная нормализация имён не установлена.
Тексты Windows/Android/IOS в value-at заданы синтетически, реальные enum strings
не декодированы. Инициализированная таблица не доказывает устройство реального UObject.

Android / IOS сценарии проверяют ветвления selector/lookup при искусственных inputs:
Windows helper всё ещё исполняется. Они не доказывают совместимость Android runtime.
OS/CPU/NM state, allocator / internal copy / CRT, constructors/destructor/log/send
сохраняют границы предыдущих fixtures. Login prepare/results, сеть, авторизация,
runtime promotion и изменение baseline не выполнялись.

## Ограничение исполнения и обновления

По умолчанию harness сохраняет лимит 16 функций. Только явный `function_budget: 19`
в новом проверенном контексте допускает эту интеграцию; другие бюджеты, включая
20 и 32, отклоняются. Лимит exports остаётся 8. Исполняются только инструкции
явных функций и fixtures; автоматического обхода callees нет. Без явного budget
этот context также отклоняется. Предел не увеличивается в runtime бота.

[Контекст](../../native-contexts/version-prepare-platform-11316.json),
[машинная квитанция](VERSION-PREPARE-PLATFORM-11316.json).

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_prepare_platform_context.py
```

Проверка `native-version-prepare-platform-context` включена в game-version/update.
Кэш зависит от context, verifier, трёх fixture-модулей, harness/runtime, тестов
и восьми exports. Подмена helper/call site, неподтверждённое расширение budget
или изменение входов требуют проверки. Новый SHA не считается поддержанным
без явного переноса. Готовность game-version остаётся partial.

Следующий этап — реальные platform text / FName / context type/resolver/value
зависимости и whole Login prepare/result readers. Текущие exports не повторять.
