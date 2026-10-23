# Целый producer создания: класс, ник, внешность и ID 104

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [модельного кандидата пресета](HEADLESS-CREATE-PRESET-OBJECT.md).

## Границы producer и фактический порядок полей

Исполнена целая `0x146449dc0`, привязанная к owner vtable `0x149ca7190`, slot
`+0x48`. Class getter в slot `+0x90` — `0x14644a0c0`; в этой проверке он fixture.
Его отдельная native проверка описана в
[источнике класса](HEADLESS-CREATE-CLASS-SOURCE.md).

Producer сравнивает raw class с текущим sentinel по `0x1496726a0`. При равенстве
он не читает PlayerState. Если class не sentinel, но lookup `0x14641af30`
возвращает null, не вызываются JSON helper и dispatch.
Пустой ник producer **не отклоняет**: проверка игрового ника относится к пути
до producer / runtime policy и серверу. Нельзя выводить допуск пустого ника
сервером из успешной сериализации.

Имя копируется из PlayerState `+0x368` / `+0x370` как FString. Native producer,
constructor ID 103, writer и UTF-16 → UTF-8 conversion исполняются целиком.
Дополнительные два raw bytes остаются `(0, 0)`, массив items пустой.
JSON helper вызывается с `owner+8`; возвращённый FString копируется в пакет.
Сам JSON helper здесь fixture, а не исполненный serializer.

Scalar mapping установлен статически по helper-вызовам consumer пресета и
прямым записям в owner. Сам порядок чтения owner в producer проверен native
с различными байтами, включая отдельный marker по `owner+8`, не попадающий в массив:

| Индекс wire array | Поле | Owner offset | Helper применения пресета |
| --- | --- | --- | --- |
| 0 | Gender | +0x30 | Начальный источник пола проверен отдельно |
| 1 | HairIndex | +0xb | 0x14642da10 |
| 2 | HairColorIndex | +0xc | 0x14642dbd0 |
| 3 | HeadIndex | +9 | 0x14642dc20 |
| 4 | SkinColorIndex | +0xa | 0x14642e0e0 |
| 5 | EyeColorLeftIndex | +0xd | 0x14642d940 |
| 6 | EyeColorRightIndex | +0xe | 0x14642d940 |
| 7 | EyeTexIndex | +0xf | 0x14642d9c0 |
| 8 | DecalIndex | +0x10 | 0x14642d880 |
| 9 | DecalColorIndex | +0x11 | 0x14642d8f0 |

VoiceType helper `0x146425770` пишет owner `+0x28`; voice передаётся через JSON,
а не добавляется одиннадцатым байтом массива. UI helpers / renderer здесь
не исполняются целиком; их mapping — статическое доказательство.

## 37 сценариев и сверка тела

Проверены 36 комбинаций sentinel / class 3 / raw `0xffffffff`, PlayerState
present / absent, трёх ников (включая пустой и `Ж界🙂`) и двух JSON fixtures.
Дополнительный сценарий использует текущий модельный Carnage/F preset.
Итого **24 остановки и 13 dispatch captures**. Владелец, PlayerState и guards
не изменяются. Во всех 13 captures native writer совпал побайтно с переносимым
`encode_character_create`.

Модельный кандидат заново извлечён с проверкой текущего PAK и template references:
class 3, gender 1, `DA_PresetDarkMage3_F`, wire bytes
`[1, 8, 16, 9, 2, 2, 2, 9, 0, 0]`. Исходные serialized values и inferred defaults
сохраняют прежние origins; кандидат остаётся `model_only=true` /
`verified_loaded_asset=false`. Имя `CandidateCarnage` и JSON — входы offline
эксперимента, не созданный персонаж или доказательство политики имени.

Dispatch `0x144aafc50` получает service fixture, packet, ожидаемый result ID 104,
четвёртый аргумент из source global `0x149672698` и пятый float 0. Назначение
четвёртого аргумента здесь не переименовывается по догадке.
Dispatch заменён capture: сетевой запрос не отправляется.

## Ограничения и следующий шаг

Class getter, PlayerState lookup, JSON helper, service lookup и dispatch —
fixtures / captures. FString allocation, bounded memcpy / raw output,
packet destructor / free и security check — fixtures. Нативная очистка памяти
не проверена. Byte-for-byte сравнение подтверждает тело в выбранных сценариях,
а не допуск класса, имени, JSON или внешности сервером.

JSON кандидата сформирован как явная строка fixture. В частности, текущая
проверка **не подтверждает** native key conversion, формат чисел или сериализацию
JSON библиотекой клиента. Следом — эти ключи / значения и whole handler ID 104.
После их проверки можно подключать уже разрешённую пользователем живую попытку
создания при принятом пустом списке; если персонаж существует, новый не создаётся.
Не возвращаться к constructors движка ради повторной проверки producer.

## Воспроизведение и источники

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-character-create-producer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_create_producer.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_create_writer.py
```

[Producer tool](../../../replay-release-character-create-producer.py) использует
[общий writer harness](../../../replay-release-character-create-writer.py).
Offline check `release-character-create-producer`; авторизация, игра и сеть
не запускаются. Проверка writer по прежнему пути также проходит.

Отчёт в библиотеке ресурсов:
`code-clues/release-character-create-producer/4c5dcc7aaee263b39aa5db69cd07516a33df556b2adbc852c78bb9e1386ff60a/manifest.json`.
В нём сохранены synthetic bodies, calls, модельный источник и SHA encoder.

Экспорты в общем comparison project
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/`:

| Каталог | SHA256 details.json | Данные |
| --- | --- | --- |
| run-33b73b3d42b9 | 977ff56c28a82d5ee388b4e464802f2675d0fbe7c2374fe99d16ccddb1e2f460 | Whole producer |
| run-8d15dc4015fc | 1e1a52528141a45e58a3d698ea9329d13ab90f8a314531f329e7e2ecd75c9b00 | Девять UI helpers scalar / voice |
