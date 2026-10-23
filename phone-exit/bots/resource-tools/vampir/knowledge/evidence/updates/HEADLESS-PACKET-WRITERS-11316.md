# Version / Login 1.13.16: порядок полей и отказы writers

Источник — собранный Windows клиент 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Это продолжение [проверки constructors / tag](HEADLESS-RESUMABLE-UPDATE-11316.md).
Рабочий игровой профиль не переключён.

## Источники и результат

| Пакет | Constructor | Packet table | Writer, slot `+0x10` | Полей | Native случаев |
| --- | --- | --- | --- | ---: | ---: |
| PktVersion | `0x1456d7be0` | `0x149926d08` | `0x1456e8830` | 13 | 56 |
| PktLogin | `0x1456d7570` | `0x1499263d0` | `0x1456e8370` | 25 | 104 |

[Квитанция с полными SHA exports и native reports](PACKET-WRITERS-11316.json).
Два writers получены одним явным batch через `prepare` / `collect`; общий
помощник `0x144aad310` — следующим явным заданием контроллера по объявленной
связи первого прямого вызова. Полные exports сохранены в библиотеке по SHA.
Повторный экспорт этих трёх функций не нужен.

[Проверка](../../../verify-packet-writer-context.py) исполняет целый writer
через закреплённые Capstone / Unicorn и source-context harness. Проверяет
связь constructor → packet table → slot `+0x10` → writer и прямой string helper.
Инструкции и exports сверяются с исходным EXE. Неизвестный вызов отклоняется.

Для каждого writer исполнены четыре варианта заполнения памяти: 0, `0x55`,
`0xaa`, `0xff`. В каждом проверены успех всех операций и отдельный отказ каждой
операции записи: следующие поля после отказа не передаются, writer возвращает
false. Проверены порядок, адреса строковых дескрипторов, числовые аргументы с
установленными старшими битами, неизменность пакета / archive, canaries, RBX,
RDI и восстановление стека. Итого 160 сценариев.

## Проверенные поля объекта

Это смещения в объекте клиента, не в переменном сетевом теле.

- Version: строки `0x10`, `0x28`, `0x38`, `0x48`, `0x58`, `0x68`, `0x78`,
  `0x88`, `0xa0`, `0xb0`; uint32 `0x20`, `0x98`, `0xc0`.
- Login: строки `0x10`, `0x20`, `0x30`, `0x40`, `0x58`, `0x68`, `0x78`,
  `0x88`, `0xa0`, `0xb8`, `0xc8`, `0xd8`, `0xe8`, `0x100`, `0x110`;
  uint32 `0x50`, `0xb0`, `0xf8`, `0x120`; bytes `0x98`, `0x99`, `0x124`;
  uint64 `0x128`; raw inputs bool helper `0x130`, `0x131`.

Полный чередующийся порядок задан в `writer_check.fields` соответствующего
[контракта](../../update-contracts.json), проверяется actual writer и защищён
тестами перестановки полей / подмены archive метода.

## Автоматизация и границы

В update добавлен source-context adapter `packet-writer-projection` для обоих
контрактов. Его журнал и кэш отделены от `version-login-tag`; тест проверяет
исполнение и повторное использование обеих проверок одного контракта.
Связи поиска writer и string helper объявлены как table slot и direct call.
[Ориентир](../../release-update-targets.json) `packet-writers-current` фиксирует
SHA, границы и обязательный `packet-writer-context` check. Следующая сборка
требует подтверждения constructor / table / helper; адреса не переносятся сами.

String helper и scalar archive methods в этом replay — fixtures: они проверяют
аргументы и заданный отказ. Native UTF-8 conversion, формат archive, нормализация
bool, сборка / отправка сетевого кадра и ответы сервера здесь не исполнены.
Полные preparation Version / Login тоже остаются непроверенными. Поэтому
`coverage` обоих контрактов остаётся `partial`; успех этой проверки не готовит
возможность `world-session`.

Команда локальной проверки:
`python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_packet_writer_context.py`.
Четыре теста покрывают реальные writers и отказы при изменении порядка, типа
операции, table slot / helper, SHA export и пересечении полей.

Следующая проверка — исполнить сохранённый `0x144aad310` вместе с текущими
UTF-8 length / conversion helpers и archive primitives. В его полном export
найдены вызовы `0x14144c550` и `0x1414465f0`; это ориентиры для явного `prepare`,
их семантика на новом SHA ещё не подтверждена. Исторические
[Version](../network/HEADLESS-VERSION-PACKET-WRITER.md) и
[Login](../network/HEADLESS-LOGIN-PACKET-WRITER.md) сохраняются как контекст
предыдущей сборки, не как доказательство нового wire encoding.
