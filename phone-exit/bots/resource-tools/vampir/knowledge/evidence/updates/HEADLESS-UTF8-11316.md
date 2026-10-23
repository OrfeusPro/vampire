# UTF-8 helpers 1.13.16: нативное преобразование и границы буфера

Источник — Windows EXE 1.13.16, полный SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки writers](HEADLESS-PACKET-WRITERS-11316.md).

## Подтверждённый участок

| Роль | Адрес | Проверка |
| --- | --- | --- |
| Общий string writer | `0x144aad310` | По одному прямому вызову length / conversion; целиком здесь не исполнялся |
| Длина UTF-8 по UTF-16 units | `0x14144c550` | Целая функция, без внешних вызовов |
| Преобразователь UTF-16 → UTF-8 | `0x1414465f0` | Целая функция, два вызова одного scalar encoder |
| Scalar encoder | `0x14143f320..0x14143f45c` | Bounded leaf, 317 байт, без unwind root; только внутренние прямые переходы, без вызовов |

[Контекст с bindings, export SHA и leaf bytes](../../native-contexts/utf8-11316.json).
[Квитанция отчёта](UTF8-11316.json). Полный machine report находится вне Git.
Готовый export string writer использован повторно; недостающие length / converter
получены одним явным `collect`, без обхода дерева вызовов. Leaf проверен отдельно
по реальным байтам EXE, его отсутствие в unwind не скрыто фиктивным root.

[Проверка](../../../verify-utf8-context.py) исполняет реальные инструкции length,
converter и encoder через закреплённые Capstone / Unicorn. Python формирует только
входы и независимое ожидание; UTF-8 bytes возвращает нативный код. Не исполняются
OS API, allocator, сеть или игровой клиент. String writer не входит в разрешённый
набор исполняемых функций этого replay.

142 сценария строк проверяют длину, указатель результата, недостаточную ёмкость,
целый записанный префикс и отсутствие записи за границей. Входы: пустая строка,
ASCII, границы 1 / 2 / 3 / 4 байт UTF-8, кириллица / CJK / emoji, длины 15 / 16 /
127 / 128, непарные суррогаты, повреждённые пары, U+FFFE / U+FFFF и встроенный NUL.
Ещё 80 случаев проверяют scalar encoder для 16 значений при capacity 0..4,
включая значение вне Unicode. Итого 222 сценария; canaries и входная память
сохранены, RBX / RSP восстановлены.

## Наблюдаемое поведение

- Непарный суррогат, U+FFFE, U+FFFF и scalar вне Unicode заменяются на ASCII `?`.
- Правильная surrogate pair образует один четырёхбайтовый UTF-8 scalar.
- При нехватке места scalar не записывается частично. Уже записанный префикс
  предыдущих scalars сохраняется; converter возвращает нулевой указатель.
- При успехе converter возвращает указатель после записанных байтов. Scalar
  encoder отдельно меняет указатель и оставшуюся ёмкость только при успехе.
- Встроенный NUL обрабатывается при явном count. Это не подтверждает его
  допустимость в FString / игровом пакете: string writer имеет свои правила длины.

Проверены конечные bounded vectors и неотрицательные ёмкости, а не произвольные
указатели / размеры. Нативный string writer, archive primitives, длина строки в
сетевом теле, bool normalization, preparation / result и сервер здесь не проверены.
Оба игровых контракта сохраняют `partial` coverage.

## Повтор и следующее обновление

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-utf8-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/utf8-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_utf8_context.py
```

Три теста проверяют реальные результаты и отклонение неверного source SHA,
повреждённых exports / leaf и подмены encoder. Проверка `native-utf8-context`
зарегистрирована для update и обоих игровых контрактов. Для нового SHA она
требует переноса; запись нового SHA без review не добавляется.
Ориентир `native-utf8-current` в [реестре обновлений](../../release-update-targets.json)
фиксирует адреса, scope и required check. Runtime и baseline не переключаются.

Следующий шаг — исполнить сохранённый string writer вместе с подтверждёнными
UTF-8 helpers и текущими archive string / uint16 / raw IO methods. До этого
успех UTF-8 helpers не означает доказанный формат всего Version / Login body.
