# Полная форма launcher token/sign-in в 1.13.18

Новый EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Baseline EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request `2694b619ef512867e971b239d682b91d0ae271bc5925409553884d531128f969`.
Полные SHA двух exports закреплены в `audit-launcher-shape-11318.py`:
run-e6508b986175 (baseline) и run-5e88e50e265d (новый клиент).

## Что проверено

| Функция | 1.13.16 | 1.13.18 | Инструкций |
| --- | --- | --- | --- |
| launcher/token | 1444EE9D0 | 1444EECD0 | 652 |
| launcher/sign-in | 144503B10 | 144503E10 | 679 |

Каждая инструкция export сверена с байтами EXE, начало с unwind root,
а полный набор адресов/байтов — с декодированием всех принадлежащих root ranges.
Отсутствующие инструкции/условные fallthrough или несовпадение bytes отклоняются.
Legacy export 1.13.16 не содержит block/direct-flow flags: отсутствие разрешено
только для явно закреплённого baseline; полнота проверяется диапазонами и Jcc.
False metadata не принимается. Новый export имеет полное coverage.

Для сравнения маскируются только relative call/branch targets и RIP displacement.
Локальные branch targets сохраняются как offset от entry и сравниваются отдельно.
Внешние вызовы сохраняются по порядку с source offsets и адресами для обеих версий.
Все остальные байты, смещения полей, immediate values, instruction positions и
косвенные вызовы должны совпасть. Обе полные формы совпали.

В каждой функции есть ровно одна ссылка на соответствующий UTF-16 route:
`launcher/token` (149531050 → 149532850) и
`launcher/sign-in` (149531260 → 149532A60). Ссылка из инструкции располагается
по тому же смещению функции: 1867 и 1739 байт соответственно.
Каждая пара содержит 70 внешних direct calls; RIP references — 22 и 20.
В артефакте сохранены все пары, включая повторные ссылки, без предположения
об общей разнице адресов между версиями.

Артефакт вне Git:
`code-clues/launcher-shape-11318/d367f9754bc36b5e44813d1b8ad28c00a42cda4ff77df0e2fa9c047082681d43/manifest.json`.
Tool `audit-launcher-shape-11318.py`; тест `test_vampir_launcher_shape_11318.py`;
исследовательский check `launcher-shape-11318`.

## Граница вывода

Это static comparison, без native execution. Пары внешних вызовов и RIP data
сохранены как unresolved; их совпадение по месту вызова не устанавливает
эквивалентность реализации/данных. Не проверены request serialization/headers,
response callbacks, актуальный SDK/GMC2 context или живой вход.
`compatibility=not_established`, `network_used=false`, `profile_activation=false`.
Прежняя `release-launcher-contract` не разрешена для нового SHA этим этапом.

Следом проверить source references ключей, callbacks и transport targets из
новых функций; затем перенести полный статический launcher contract и SDK
проверки. [Общий аудит 1.13.18](HEADLESS-RELEASE-AUDIT-11318.md).
Работающий профиль/онлайн-сессия не переключались, новая авторизация не выполнялась.
