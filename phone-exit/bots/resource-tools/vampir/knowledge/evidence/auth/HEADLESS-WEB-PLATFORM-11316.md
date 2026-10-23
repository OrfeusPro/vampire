# FDeviceInfo platform перед NID: 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [профиля-кандидата](HEADLESS-SDK-PROFILE-11316.md).
Исследование offline, без процесса игры, сети и авторизации.

## Происхождение

По готовому export platform getter `0x144532410` выполнен поиск direct E8
callers. Два source-checked вызова: caller `0x1444ecf50`, callsite
`0x1444ed01b`; caller `0x144555fb0`, callsite `0x14455646f`.
Второму caller роль NID не присваивалась. Первый получен через prepare / collect;
сохранённый export включает diagnostic ASCII по адресу `0x149535650`:
`class FString __cdecl Netmarble::Service::FDeviceInfo::GetPlatform(void)`.

Это подтверждает caller platform getter, а не всю связь с NID parent.
Прежнее исследовательское имя NID_WebOS не используется как доказательство
новой роли. Другие NID inputs и родители ещё требуют сверки.

## Native execution

`replay-web-platform-11316.py` использует source-bound harness и исполняет
настоящие PC initializer, switch getter и FDeviceInfo::GetPlatform.
Полные SHA EXE / трёх exports и байты инструкций проверены. Capstone 5.0.6,
Unicorn 2.1.4. Неизвестный target останавливает replay.

Синтетические GS base / TLS array / thread epoch задают уже инициализированную
ветку guard: TLS index 0, epoch 0, global guard -1. Lazy lookup console variable
не исполняется. Global console pointer задаётся null либо объектом с двумя
явными значениями по offsets 0 и 4. Logging отключён.

52 случая: четыре poison fills × (один случай отсутствия console pointer
и 12 вариантов slots / двух bool predicates). Slots: (3,2), (2,3), (255,3);
оба результата каждого predicate перебраны.

| Условие | Выбор кода платформы |
| --- | --- |
| Console pointer null | 3 |
| Первый predicate true | Slot +0, второй не вызывается |
| Первый false, второй true | Slot +0 |
| Оба false | Slot +4 |

Для выбранного byte 3 actual getter возвращает PC; для проверенных 2 / 255 —
пустую строку. Во всех случаях проверены return receiver, FString counts,
storage pointer, canaries и точный порядок вызовов predicates.

Два predicates `0x14148ee80` / `0x14148ee40` — fixtures, их настоящая семантика
потока не проверялась. Также fixtures: TLS / console state, FString allocation /
storage, memcpy и exit registration. Результаты не доказывают фактический
console state игры, lazy registration, другие platform labels или auth lifecycle.

## Проверки и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-web-platform-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_web_platform_11316.py
```

Три теста подтверждают 52 результата / gates / canaries и отказ при изменённых
source / export. В release-update-targets.json добавлен current caller с точной
границей initialized TLS / console fixtures и обязательным
web-platform-native-11316. Поиск нового SHA остаётся assisted по проверенным
direct callers, без автоматического переноса роли или runtime promotion.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Callers: `ghidra/request-exports/sdk-reference-candidates/53857c5cbc88aeddd0a21bdfa8cd013e377949ce50ca919d24b3ac290b924825/manifest.json`.
- Export: `ghidra/request-exports/<SHA>/run-47e33521ffcf/details.json`,
  SHA `99158407757acb6b2b2d245e406b0b3e1c8e834048c00f442af56a5348a58cd9`.
- Replay: `code-clues/web-platform-11316/66a85ae9f63204d2ed19e67577ea63b25f802ce8d2403d6689e8a34be77b5a73/manifest.json`.
- Initializer / getter exports перечислены в [проверке платформы](HEADLESS-SDK-PLATFORM-11316.md).

Профиль-кандидат не изменён и не включён в runtime. Далее найти проверенные
callers FDeviceInfo::GetPlatform и текущий NID context builder, сверить остальные
входные поля и auth source guards перед отдельной живой проверкой.
