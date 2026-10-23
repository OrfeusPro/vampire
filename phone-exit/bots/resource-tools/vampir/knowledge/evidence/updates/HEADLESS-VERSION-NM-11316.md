# Version 1.13.16: настоящий NM provider и getter

Источник — EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [whole Version prepare projection](HEADLESS-VERSION-PREPARE-11316.md).
Реальные device keys не читались и не менялись, авторизация не запускалась.

## Источник поля и материалы

Wrapper `0x1445ccee0` вызывает только `0x1444ec890`, затем возвращает исходный
выходной descriptor. Этот getter уже связан с nmDeviceKey в
[текущем NID context](../auth/HEADLESS-NID-CONTEXT-11316.md), но там его тело
было fixture. Теперь оба тела исполнены целиком.

Cache FString находится по `0x14b562620`. Getter использует его, когда count
не меньше 2; иначе вызывает storage read `0x1415cb3e0`, GUID parser
`0x141560610` и при необходимости generator / formatter
`0x14155ff70` / `0x14154ea40`. Запись — `0x1415d73b0`.
Все call sites закреплены в [NM context](../../native-contexts/version-nm-device-11316.json).
Storage arguments `0x14b5622b0/0x14b5622c0/0x14b5622f0` — адреса descriptors;
их реальные значения / registry paths этим экспериментом не доказываются.

Семь явно выбранных Version callees получены одним collect, без рекурсивного
обхода. Export `run-09b30ec921d8/details.json`, SHA256
`05567661bee229c7038ea1e621e08dd3a1c4c3d7685e9551554c222dab33c4da`.
В том же export уже есть selector `0x1445ce2e0`, context getter `0x1445c4b90`,
lookup `0x1416dd660`, Windows helper `0x1415c9380` и CPU text helper
`0x14144d1a0`. Их тела ещё не исполнены этой проверкой; повторно выгружать их
не нужно.

## Проверенное поведение

[NM verifier](../../../verify-version-nm-device-context.py) выполнил 36 случаев:
четыре poison fills × девять профилей cache / storage / parser / write result.
Во всех случаях wrapper и getter — настоящие инструкции EXE.

- Cache содержит готовую строку: ни storage, ни parser не вызываются.
  Native count gate принимает также один символ или пробел без GUID validation.
- Ненулевой parsed GUID сохраняет исходный stored text, без нормализации.
- Parser failure или четыре нулевых GUID words ведут к generator, formatter и
  попытке записи. Generator / formatter здесь отдельные явные fixtures.
- False от storage read не мешает использовать непустое возвращённое значение,
  если parser fixture его принимает. False от write не отменяет заполнение cache.
- Повторный вызов выдаёт тот же текст и не добавляет ни одного storage / GUID
  события. Проверены output descriptor, canaries, временные allocations и ABI.

[Интеграционный контекст](../../native-contexts/version-prepare-nm-11316.json)
включает настоящие wrapper / getter непосредственно в whole Version prepare.
Ещё 64 случая проверяют проекцию и cleanup с populated synthetic cache.
Исполнение обоих входных адресов считается hook, ожидается ровно два входа
на один prepare. Provider fixture в этой ветви не устанавливается.
Поле Version `+0x48` содержит результат native NM getter даже при пустых
остальных строках. Это проверка реального источника одного поля, а не повтор
проекции с прежним provider stub.

## Ограничения

Storage / parser / GUID generator / formatter, FString operations и memory
allocation остаются bounded fixtures. Нельзя выдавать произвольный format
fixture text за доказанный реальный GUID encoding. Logging ветвь getter
отключена только в synthetic memory.

Интеграция с prepare проверяет initialized cache. Cold branches исполнены
отдельно; единая cold startup → registry → prepare цепочка не заявляется.
OS / platform / context / CPU getters, combiners, send и прочие границы
предыдущего prepare experiment остаются fixtures. Login prepare и result
readers не перенесены. Реальные registry paths, storage values и account /
device confirmation этой проверкой не устанавливаются.
Нет сети, игровых действий, смены runtime profile или baseline.

[Machine receipts](VERSION-NM-11316.json). Отдельные native прогоны заняли около
3 секунд каждый; три новых теста — 8,029 секунды. Три прежних prepare tests
после расширения harness прошли за 7,737 секунды. Это время этих участков.

## Повтор и обновления

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-nm-device-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-nm-device-11316.json
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-prepare-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-prepare-nm-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_nm_device_context.py
```

Check `native-version-nm-context` включён в on_update game-version.
Контексты, инструменты, exports и runtime distributions входят в ключ кэша;
изменение provider link, source SHA или export отклоняется тестами.
Ориентир `native-version-nm-current` фиксирует обязательную проверку wrapper /
getter / storage dependencies для следующего SHA. Runtime автоматически не
продвигается. Существующий prepare check с provider fixture тоже сохраняется
как отдельная проверка проекции, с прежними границами.

Следующий шаг — текущие platform/context и Windows / CPU helpers из готового
export, затем Login prepare и result readers. Живой тест разрешён только до
каталога серверов; это разрешение не отменяет оставшиеся проверки профиля.
