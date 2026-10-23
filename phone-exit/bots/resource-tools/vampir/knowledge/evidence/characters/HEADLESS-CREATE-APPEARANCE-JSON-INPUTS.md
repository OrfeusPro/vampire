# Внешность: входы генератора JSON и VoiceType

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [запроса создания](HEADLESS-CREATE-REQUEST-WRITER.md).

## Что выполняется

Целый helper `0x146447e50` принимает указатель на owner `+8` и результат
FString. Он обходит занятые строки sparse container: key string из entry
`+0x10`, float из `+0x20` и общий byte режима из input `+0x28` передаются
helper `0x1456746c0`. После обхода всегда добавляется отдельное числовое поле
`VoiceType`; его значение — byte input `+0x20`, то есть owner `+0x28`.
Ключ получен из текущего UTF-16 literal `0x149a3f328`.

Затем выполняются настройка writer с флагом 0 и вызов сериализации с флагом 1.
В этой проверке обе операции являются captures; смысл флагов за пределами
наблюдённого контракта не устанавливается. Полученный реальный JSON-текст и
его форматирование здесь не воспроизводятся.

Constructor owner `0x146442670` инициализирует byte `+0x28` нулём. Это отдельно
проверено во всех 144 прежних сценариях constructor / getter, включая canary
в начальной памяти. Пол owner `+0x30` берётся из PlayerState `+0x364` и при
его отсутствии остаётся прежним; его нельзя заменять нулём по аналогии.

## Проверка и границы

`replay-release-appearance-json-inputs.py` исполняет весь внешний helper и
native sparse iterator. 12 сценариев: пустой набор, одна запись, пропуски,
35 слотов через границу bitvector 31 / 32; VoiceType 0 / 1 / 255.
Проверены порядок занятых entries, их float-значения, byte режима, отдельный
VoiceType и достижение конца helper. Наличие 255 в fixture не означает,
что такой голос допустим в игре.

JSON objects / setters / writer / serialize, entry helper, FString assignment,
allocation / free / refcounts — явные bounded fixtures и captures. Деструкторы
JSON engine не проверяются. Ключи `fixture_N` и их значения синтетические;
допустимые реальные параметры внешности и конвертация их ключей не установлены.

Статический разбор `0x1456746c0` показал, что функция не просто копирует key:
она использует helper `0x14566c5e0`, lookup `0x145466740`, получает строковый
ключ и передаёт float как double в числовой JSON setter `0x1415f2740`.
Полное исполнение этого внутреннего пути остаётся следующим этапом.
Поэтому JSON только с VoiceType пока нельзя выдавать за достаточную внешность.

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_appearance_json_inputs test_vampir_create_class_source
```

Report:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-json-inputs/6997b343c4f76edb7caba37d43a583977228ec8c0678366163efc4e385aa3302/manifest.json`.
SHA256 совпадает с именем каталога. В текущем comparison
`c7552efd2125-98802d550890/run-fd4956a37b3c` используются details
`run-1dd894856f56` (внешний helper), `run-1dc059f7b039` (constructor),
`run-770966be34b2` (entry helper, SHA256
`53bad7b4e0591b8eeddd94a4d02a564b1cdea3202b28581a519a7d353c0bcf91`).
Проверка `release-appearance-json-inputs` зарегистрирована с зависимостями.

Сеть, JSON engine output, whole producer запроса и фактическое создание
персонажа не выполнялись. Следом нужны реальный источник параметров и
конвертация ключей, затем whole producer и обработчик ID 104.
