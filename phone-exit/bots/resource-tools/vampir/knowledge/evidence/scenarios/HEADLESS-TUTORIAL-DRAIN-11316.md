# Consumer очереди ID 9905 в 1.13.16

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [defer / deep copy](HEADLESS-TUTORIAL-DISPATCH-11316.md)
и [application](HEADLESS-TUTORIAL-STARTUP-11316.md).

Проверенный CALL `1464cc090` ведёт в application `1464c35d0` из consumer
`1464cbf80`. Последний имеет шесть связанных unwind ranges. Экспорт целого root
`run-647bb938de11/details.json` находится под текущим SHA в библиотеке Ghidra.
Context `knowledge/native-contexts/tutorial-drain-11316.json` закрепляет полный
SHA экспорта, constructor / getter и destructor vtable binding.

`replay-tutorial-drain-11316.py` исполняет consumer со всеми ranges, настоящий
constructor и ID getter. Для ветви ID 9905 application получает context и
packet+0x10. До byte состояния 6 consumer сохраняет очередь; при готовности
обходит элементы по порядку, пропускает null и вызывает virtual destructor
с флагом 1 после application. Затем native count становится 0 до shrink.

160 native комбинаций: states 0 / 5 / 6 / 7, пустая очередь / только null /
один packet / два с null между ними / три в обратном порядке, count records
0 / 1 / 8 / 64 и оба data flag. В 80 случаях после раннего возврата state
меняется на 6 и вызывается тот же consumer. Проверены:

- отсутствие изменений queue / packet до готовности;
- порядок передачи application и release каждого отдельного packet;
- сохранность records / flag при передаче, включая одинаковые keys в разных packets;
- ровно один release на packet, native count reset до shrink;
- отсутствие новой обработки / release после повторного вызова пустой очереди;
- guards context, state, queue, packets и record buffers.

Отчёт вне Git:
`code-clues/tutorial-drain-11316/e336b534d3d570ab75f932900957643a70117a1b46f0246b8ed3265fe8a5847e/manifest.json`.

State provider, application, deleting destructor и shrink/free — fixtures.
Release fixture обнуляет packet, поэтому повторный dispatch уже освобождённого
объекта не может незаметно пройти. Это не исполнение настоящего heap destructor.
Нет доказательства server/local map application в составе consumer, других ID,
caller lifecycle и соответствия native state 6 headless world finish.
Отдельные application / defer проверки не объединяются автоматически в live
готовность или разрешение исходящей команды. Runtime остаётся observational.

Это offline сценарии; никаких игровых запросов, входов или памяти работающего
клиента они не используют. Следом — lifecycle / replacement / pruning и реальные
loader / callback условия текущего tutorial шага.
