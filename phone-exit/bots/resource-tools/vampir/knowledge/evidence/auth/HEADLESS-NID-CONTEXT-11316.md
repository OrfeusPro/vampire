# Десять базовых NID pairs в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [FDeviceInfo platform](HEADLESS-WEB-PLATFORM-11316.md).
Сохранённый EXE и synthetic memory; без процесса игры, сети и авторизации.

## Поиск без потери неизвестного

Поиск direct E8 callers текущего FDeviceInfo::GetPlatform `0x1444ecf50`
нашёл 11 verified callers и root `0x1450e3c80`, который whole-unwind decoder
не смог полностью разобрать. Ранее один такой root прерывал весь поиск.
Теперь scanner декодирует roots отдельно, сохраняет успешные результаты,
unresolved_roots с причиной и unresolved_callers с raw callsite / target.
Raw candidate не попадает в verified references. Лимиты roots не увеличены.

Explicit prepare / collect для `0x1450e3c80` завершён. Ghidra export содержит
961 инструкцию и 191 decompiler block. Проверены реальный CALL к GetPlatform
и diagnostic ASCII `0x149738f10` с именем
FNetmarbleIDContent::CheckPossibleToOpen. Ключ GMC2 `authWebViewUrl`
находится по `0x149739048`. Это подтверждает роль и связь текущего NID parent,
а не вывод по старому имени или смещению адреса.

## Исполненный участок

`replay-nid-context-11316.py` исполняет инструкции от `0x1450e4058`
до `0x1450e42a8`, перед вызовом map constructor `0x143bfd2f0`.
Проверяются полные SHA EXE / пяти exports и байты выбранных инструкций.
Настоящие build getter и три initializers исполняются вместе с этим slice.
Capstone 5.0.6 / Unicorn 2.1.4, конечный instruction / heap / string budget.

| Порядок | Ключ | Источник в текущем slice |
| --- | --- | --- |
| 1 | gameCode | settings +0x38 |
| 2 | buildCode | `0x1445320c0`, settings byte +0x48 |
| 3 | countryCode | getter `0x144528a00`, context receiver |
| 4 | language | getter `0x143d1c730` |
| 5 | os | FDeviceInfo::GetPlatform `0x1444ecf50` |
| 6 | nmDeviceKey | getter `0x1444ec890` |
| 7 | deviceKey | getter `0x1445293f0`, context receiver / mode 1 |
| 8 | osVersion | getter `0x1444ecd90` |
| 9 | clientId | settings +0x98 |
| 10 | nidV | точный UTF-16 literal 3 по `0x1489e4a1c` |

32 сценария: четыре poison fills × build codes 0 / 1 / 2 / 255 × полный /
пустой synthetic context. Во всех случаях проверены точный порядок десяти
pairs, значения, последовательность getter calls, receiver / destinations /
device mode и canaries. Build getter даёт A / B / C / A; nidV всегда 3.
Пустые context values остаются пустыми, без автоматической подстановки.

Fixtures: шесть context getters, settings/context objects, FString literal
storage / allocation, memcpy и exit registration. Реальные device keys не
читаются и не генерируются. Отдельный предыдущий replay доказывает поведение
GetPlatform в заданном initialized TLS state; здесь он capture fixture,
поэтому единое выполнение обеих цепочек не заявляется.

Более ранние URL / availability gates, реализация country / language / device /
version getters, map construction, query encoding, webV / authType extensions,
browser callbacks и весь auth lifecycle не исполнены. Полный SDK-профиль
остаётся кандидатом; runtime не включён.

## Проверки и автоматизация

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-context-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_context_11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_references_11316.py
```

Три context-теста: 32 случая и отказ при повреждённых EXE / export.
Шесть reference-тестов включают сохранение 11 verified callers и одного
unresolved root; последующий explicit Ghidra export подтверждает именно его
callsite. Это разрешение отдельного unknown, не автоматическое присвоение
роли scanner. Source-bound check и scope сохранены в release-update-targets.json.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Callers с unknown: `ghidra/request-exports/sdk-reference-candidates/031efec9e8750fb3fe846ef0d8ef153f3f51a903a6922faf9ed6faf2a159ec65/manifest.json`.
- NID export: `ghidra/request-exports/<SHA>/run-988ec3bf8f0a/details.json`,
  SHA `ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd`.
- Replay: `code-clues/nid-context-11316/ba7dcda923ed58e82967bfdf38444e9f1499afea95c18ddf2436837ff4f84204/manifest.json`.
- Build getter / initializers exports — в [проверке URL](HEADLESS-GMC2-URL-NATIVE-11316.md).

Далее сверить webV / authType extensions и gates по готовому текущему export,
затем auth source guards и явное подключение профиля с отдельной живой проверкой.
